"""The WSGI serving stack behind ``recoverage serve``.

Bottle hands back a WSGI app; something still has to bind a socket, accept
connections, and speak HTTP on them.  That is a transport concern with its own
rules (one thread per connection, a deadline on every socket operation,
HTTP/1.1 framing), none of which belong to a command-line interface, so they
live here and ``cli.serve`` wires them up.

A leaf: stdlib only, imported by ``cli`` and by nothing else.  ``wsgiref`` is
the reference implementation and ``bottle.ServerAdapter`` is not used, because
the overrides below are on the server and handler classes themselves rather
than on the adapter around them.
"""

from __future__ import annotations

from http.client import HTTPMessage
from socketserver import ThreadingMixIn
from typing import IO, TYPE_CHECKING, Any, cast
from wsgiref.simple_server import ServerHandler, WSGIRequestHandler, WSGIServer
from wsgiref.types import InputStream

if TYPE_CHECKING:
    # _typeshed ships with mypy, not with CPython: the annotations below are
    # strings (from __future__ import annotations) and the casts are string
    # literals, so nothing here is evaluated at runtime.
    from _typeshed.wsgi import InputStream, WSGIApplication


class _ThreadingWSGIServer(ThreadingMixIn, WSGIServer):
    """Threaded WSGI server for the dashboard.

    wsgiref's stock WSGIServer handles one connection at a time; the SSE
    /api/events stream stays open indefinitely, which would stall every other
    request.  ThreadingMixIn gives each connection its own daemon thread.
    """

    daemon_threads = True

    def app(self) -> WSGIApplication:
        """The WSGI app, or a loud failure if none was installed.

        ``wsgiref.simple_server.make_server`` calls ``set_app`` before the
        listener binds, so a request cannot arrive without one; the typeshed
        stub types ``get_app`` as possibly-None, and every request path here
        needs the application rather than a check.  Naming the failure beats
        passing ``None`` into ``BaseHandler.run``, which would raise from
        inside wsgiref with no reference to this server.
        """
        application = self.get_app()
        if application is None:
            raise RuntimeError("no WSGI application installed on the server")
        return application


# Hard deadline for every socket operation on a client connection (the request
# read and each response write).  Without it a half-open TCP peer (crashed
# laptop, dropped NAT mapping) or an SSE client that stops reading pins its
# handler thread forever: ThreadingMixIn caps neither threads nor connections,
# so wedged peers silently accumulate until process exit.  With the deadline,
# socket.timeout unwinds the stalled op and the thread exits, releasing the
# connection and (for /api/events) its bounded SSE slot.  Generous multiples
# of the 15s SSE heartbeat (_SSE_HEARTBEAT_SECONDS) so only a genuinely
# stalled peer can trip it — healthy streams write far more often.
_CLIENT_SOCKET_TIMEOUT_SECONDS = 120

#: How long an idle keep-alive connection waits for its next request before the
#: handler thread gives up and the socket closes.  The per-connection deadline
#: above covers a request in flight; a browser holding a connection open
#: between loads must not pin a thread for that whole deadline, and
#: ThreadingMixIn starts a thread per connection.  15 s is longer than any
#: real page load's asset burst, so a connection survives a slow load and dies
#: soon after the tab goes quiet.
_KEEPALIVE_IDLE_SECONDS = 15

#: Status codes whose response carries no body by definition (RFC 9110 15), so a
#: missing Content-Length on one is correct and the connection stays usable.
#: Strings, because the wire status line is the only place they are read.
_BODYLESS_STATUS_CODES = frozenset(("204", "304"))

#: Headers that frame a body without ending the connection (RFC 9112 6).
_SELF_DELIMITING_HEADERS = frozenset(("content-length", "transfer-encoding"))


class _QuietTimeoutRequestHandler(WSGIRequestHandler):
    """wsgiref request handler with the per-connection deadline above.

    Also carries bottle's FixedHandler behavior (peer address without reverse
    DNS; no per-request logging): passing ``handler_class`` to Bottle replaces
    FixedHandler wholesale, so both overrides must be reproduced here.
    ``serve`` always runs with quiet=True.
    """

    timeout = _CLIENT_SOCKET_TIMEOUT_SECONDS

    def address_string(self) -> str:
        return self.client_address[0]

    def log_request(self, code: int | str = "-", size: int | str = "-") -> None:
        pass


class _KeepAliveRequestHandler(_QuietTimeoutRequestHandler):
    """Handler that serves every request on a connection, not just the first.

    wsgiref's stock handler is HTTP/1.0 and its ``handle`` reads one request
    line and returns, so the connection closed after every response: loading
    the dashboard opened a fresh TCP connection for the shell, ``detail.js``,
    ``/api/targets`` and the data payload, and paid a handshake for each.  The
    loop below is stock ``BaseHTTPRequestHandler.handle`` behaviour that
    wsgiref narrowed to a single request; restoring it is what makes
    ``protocol_version = "HTTP/1.1"`` mean anything.

    Two framing rules keep HTTP/1.1 honest:

    * A response that names no length and no transfer encoding (the streamed
      ``/api/events``, whose body ends when the stream does) is sent with
      ``Connection: close``.  Under HTTP/1.1 a client would otherwise read
      until the connection dropped, and every response after it on that
      socket would be misframed.
    * A connection left idle between requests falls back to the short idle
      deadline rather than the full per-request one, so an open browser tab
      does not hold a handler thread for two minutes.
    """

    protocol_version = "HTTP/1.1"

    #: ``cli.serve`` always builds the listener through
    #: ``server_class=_server_class_for(bind)``, which returns a subclass of
    #: this one, so the WSGI app is reachable without narrowing.
    server: _ThreadingWSGIServer

    def handle(self) -> None:
        self.raw_requestline = self.rfile.readline(65537)
        while self.raw_requestline:
            if len(self.raw_requestline) > 65536:
                self.requestline = ""
                self.request_version = ""
                self.command = ""
                self.send_error(414)
                return
            if not self.parse_request():
                return
            # The request is in flight now, so the full per-connection
            # deadline applies to its reads and writes again.
            self.connection.settimeout(_CLIENT_SOCKET_TIMEOUT_SECONDS)
            self._run_wsgi()
            if self.close_connection:
                return
            self.connection.settimeout(_KEEPALIVE_IDLE_SECONDS)
            self.raw_requestline = self.rfile.readline(65537)

    def _run_wsgi(self) -> None:
        # The two casts are typeshed gaps, not laundered evidence:
        # http.server types ``rfile``/``wfile`` as the raw buffered socket
        # objects, while wsgiref's constructor takes the PEP 3333 InputStream
        # and IO[bytes] protocols.  Both objects satisfy them at runtime
        # (wsgiref's own WSGIRequestHandler.handle passes the same two).
        handler = _KeepAliveServerHandler(
            cast(InputStream, self.rfile),
            cast(IO[bytes], self.wfile),
            self.get_stderr(),
            self.get_environ(),
            multithread=True,
        )
        handler.request_handler = self  # backpointer for logging
        app = cast(WSGIServer, self.server).get_app()
        assert app is not None, "cli.serve builds the server with the bottle app"
        handler.run(app)


class _KeepAliveServerHandler(ServerHandler):
    """The HTTP/1.1 half of keep-alive: the status line and the framing rule.

    wsgiref writes the preamble itself (``HTTP/`` + :attr:`http_version`), not
    through the request handler, so announcing 1.1 belongs here.

    A response that carries neither Content-Length nor Transfer-Encoding ends
    only when the connection does (RFC 9112 6.3), which under HTTP/1.1 would
    leave the client reading into whatever the next response put on the
    socket.  The streamed ``/api/events`` is exactly that response, and
    nothing else here is: bottle sets Content-Length for every body it
    returns.  So an unframed response gets ``Connection: close``, which is
    what a client has to do with it either way.
    """

    http_version = "1.1"

    # wsgiref assigns the first three in BaseHandler.__init__/start_response
    # and the last one is the backpointer _run_wsgi sets before run(); the
    # stubs describe none of them, so they are declared here.  By send_headers
    # the first three are all set, which is the only point this class reads
    # them at.
    environ: dict[str, Any]
    headers: HTTPMessage
    status: str
    request_handler: WSGIRequestHandler

    def send_headers(self) -> None:
        if not self._response_is_framed():
            self.request_handler.close_connection = True
            self.headers["Connection"] = "close"
        super().send_headers()

    def _response_is_framed(self) -> bool:
        # wsgiref's Headers.__contains__ is case-insensitive; iterating it is not.
        if any(name in self.headers for name in _SELF_DELIMITING_HEADERS):
            return True
        if self.environ.get("REQUEST_METHOD") == "HEAD":
            return True
        return self.status[:3] in _BODYLESS_STATUS_CODES
