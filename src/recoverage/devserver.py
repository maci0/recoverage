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

import contextlib
import logging
import os
import socket
from http.client import HTTPMessage
from socketserver import ThreadingMixIn
from typing import IO, TYPE_CHECKING, Any, cast
from wsgiref.simple_server import ServerHandler, WSGIRequestHandler, WSGIServer
from wsgiref.types import InputStream

from recoverage import config, metrics

if TYPE_CHECKING:
    # _typeshed ships with mypy, not with CPython: the annotations below are
    # strings (from __future__ import annotations) and the casts are string
    # literals, so nothing here is evaluated at runtime.
    from _typeshed.wsgi import InputStream


_log = logging.getLogger("recoverage")

#: Concurrent connections the dashboard admits.  Generous next to what a real
#: client needs — a browser tab holds one, a page loading assets and polling
#: holds a handful, and ``api._SSE_MAX_CLIENTS`` streams can be open on top —
#: and low enough that a flood of stalled peers is refused rather than spawning
#: a thread per accept until the process cannot make one.  Refusing is loud (the
#: client gets a 503, the operator gets a log line), which is the point: a
#: server that has stopped accepting should say so rather than look slow.
#:
#: A DEFAULT, not a constant: the admitted count is a thread and a descriptor
#: each, so it is sized by the deployment's memory and traffic rather than by
#: the protocol.  :func:`configure_transport` replaces both of these from
#: ``RECOVERAGE_MAX_CONNECTIONS`` / ``RECOVERAGE_CLIENT_TIMEOUT`` before the
#: listener binds, and :func:`recoverage.config.active_config` reports the
#: values the process runs with.
_MAX_CONNECTIONS = config.DEFAULT_MAX_CONNECTIONS


def configure_transport(*, max_connections: int, client_timeout_seconds: int) -> None:
    """Install the admission cap and the per-connection deadline.

    Called once by ``serve``, with the values it resolved from the
    environment, before the listener binds: the cap is read on every accept and
    the deadline is read on every request, so neither can be a value that was
    validated and then not installed.  The deadline is also pushed onto the
    handler class, because ``http.server`` reads ``timeout`` at instance
    construction and the per-request reset in
    :meth:`_KeepAliveRequestHandler._serve_requests` reads the module global.
    """
    global _MAX_CONNECTIONS, _CLIENT_SOCKET_TIMEOUT_SECONDS
    _MAX_CONNECTIONS = max_connections
    _CLIENT_SOCKET_TIMEOUT_SECONDS = client_timeout_seconds
    _QuietTimeoutRequestHandler.timeout = client_timeout_seconds
    # So /api/health's `connections.max` names the enforced cap before the
    # first accept rather than reading 0 until one lands.
    metrics.CONNECTIONS.set_limit(max_connections)


def listen_family(host: str) -> socket.AddressFamily:
    """The address family the listener for *host* binds.

    Probed through ``getaddrinfo`` rather than sniffed off the spelling, so a
    hostname that resolves to IPv6 only is covered as well as a literal, and a
    name that offers both keeps ``AF_INET`` (the historical default, and the
    one a dual-stack host's own loopback answer points at).  A name that
    resolves to neither keeps ``AF_INET`` and fails in ``bind()`` with the
    resolver's own error, as it always has.

    ONE definition for the family, because two readers need it and the port
    the banner prints has to come off the socket the listener will hold:
    :func:`resolve_listen_port` below and ``cli._server_class_for``, which
    picks the class carrying it.  A probe that bound AF_INET6 where the
    listener binds AF_INET reserved the port on the wrong interface, so
    ``--port 0`` published a number the server then failed to bind.
    """
    try:
        infos = socket.getaddrinfo(host, None, type=socket.SOCK_STREAM)
    except socket.gaierror:
        return socket.AF_INET
    families = {info[0] for info in infos}
    if families == {socket.AF_INET6}:
        return socket.AF_INET6
    return socket.AF_INET


def resolve_listen_port(port: int, host: str) -> int:
    """The port to actually bind: *port*, or one the OS picks when it is 0.

    ``--port 0`` is the documented way to say "any free port" (port 0 is the
    floor ``config.MIN_PORT`` sets), but the number the caller asked for is not
    the number that gets bound, and every consumer of the value is printed
    rather than read: the banner, ``/api/health`` and the URL the browser is
    handed.  Resolving it here, once, before the listener binds, is what keeps
    those three from naming port 0, which is not an address anything can
    connect to.  ``recoverage config`` deliberately does not call this: it
    reports the configured value, and the free port ``serve`` binds in its
    place is a different one on every run.

    The socket is bound to *host* on the family :func:`listen_family` names,
    which is the family the listener itself will hold, and closed again, so the
    port comes from the interface the server will use rather than from a second
    guess at it; a host that does not resolve keeps the 0 the OS would have
    given the listener itself, and ``bind()`` fails there with the resolver's
    own error, as it always has.
    """
    if port != config.MIN_PORT:
        return port
    with socket.socket(listen_family(host)) as probe:
        try:
            probe.bind((host, config.MIN_PORT))
        except OSError:
            # An address the probe cannot bind (a host that resolves but is not
            # a local interface, a family the OS refuses). The listener will
            # fail on the same address with the same error and a better
            # message; keep the 0 rather than reporting a port from a socket
            # this process could not actually open.
            return port
        return int(probe.getsockname()[1])


class _ThreadingWSGIServer(ThreadingMixIn, WSGIServer):
    """Threaded WSGI server for the dashboard.

    wsgiref's stock WSGIServer handles one connection at a time; the SSE
    /api/events stream stays open indefinitely, which would stall every other
    request.  ThreadingMixIn gives each connection its own daemon thread.

    Threads are capped at :data:`_MAX_CONNECTIONS`.  The per-connection
    deadlines below bound how LONG one thread lives, never how MANY there are:
    ThreadingMixIn starts a thread for every accepted connection, and the
    accept loop starts the next one without asking.  So a client that opens
    connections and sends nothing on them pins one thread, one stack and one
    descriptor each for the full :data:`_CLIENT_SOCKET_TIMEOUT_SECONDS`, and can
    do that as many times as it likes.  ``/api/events`` has its own cap
    (``api._SSE_MAX_CLIENTS``) because a stream is the expensive case; this one
    covers every other route the same way, and refusing costs one accept.
    """

    daemon_threads = True

    # wsgiref sets allow_reuse_address = 1, which is SO_REUSEADDR, and that
    # option means opposite things on the two families this dashboard runs on.
    # On POSIX (and BSD) it waives a lingering TIME_WAIT from a previous run, so
    # a restart right after a stop binds immediately.  On Windows SO_REUSEADDR
    # lets a second socket bind an address another socket is already bound to,
    # and traffic is then split between the two by whoever bound last: a second
    # `recoverage serve` on a busy port would come up as if it owned it, and
    # serve's OSError handler ("is another instance already running?") could
    # never fire, because bind() did not fail.  Windows expresses the
    # do-not-hijack rule as SO_EXCLUSIVEADDRUSE, which socketserver does not
    # expose, so the portable spelling of it is to leave the option off there.
    # The cost is one failed bind after a crash in the kernel's hands, which
    # serve already reports with the address in the message.
    allow_reuse_address = os.name != "nt"

    @property
    def _connections_open(self) -> int:
        """Live connections, read from the gauge ``/api/health`` publishes.

        The counter itself is :data:`recoverage.metrics.CONNECTIONS`, shared
        with the health endpoint, so the admission decision and the saturation
        gauge cannot be two numbers that disagree.
        """
        return metrics.CONNECTIONS.open

    def process_request(self, request: Any, client_address: Any) -> None:
        """Admit the connection, or answer 503 and close it at the cap.

        Refusing HERE rather than in the handler keeps the bound on the
        resource (the thread and its descriptor) instead of on the request:
        a connection that never gets a thread cannot pin one.

        :meth:`shutdown_request` is what releases the descriptor on this
        branch; the superclass's own ``process_request`` releases it on every
        other one, including the thread's failure paths.
        """
        if not metrics.CONNECTIONS.admit(_MAX_CONNECTIONS):
            self._refuse_connection(request, client_address)
            return
        try:
            super().process_request(request, client_address)
        except BaseException:
            # Thread creation is the one thing the superclass can fail at, and
            # a slot taken and never handed to a thread is a slot the cap
            # loses for the life of the process — exactly the failure the cap
            # exists for.  The socket goes with it: no thread will ever serve
            # this request.
            metrics.CONNECTIONS.release()
            self.shutdown_request(request)
            raise

    def _refuse_connection(self, request: Any, client_address: Any) -> None:
        """Answer the 503 and close, so the client learns rather than hanging.

        The response is written by hand on the raw socket: there is no WSGI
        request here, so there is no environ and no handler to route a 503
        through, and a silent close would read to the client as a network
        fault rather than as a server that is busy.

        The peer is in the line for the reason
        :meth:`_QuietTimeoutRequestHandler.log_error` gives: nothing downstream
        of the accept runs, so one stalled client holding the cap open and a
        server that is merely busy produce the same count and no way to tell
        them apart.
        """
        body = b'{"error": "too many connections", "code": "rate_limited"}'
        with contextlib.suppress(OSError):
            request.sendall(
                b"HTTP/1.1 503 Service Unavailable\r\n"
                b"Content-Type: application/json\r\n"
                b"Connection: close\r\n"
                b"Retry-After: 5\r\n"
                + f"Content-Length: {len(body)}\r\n\r\n".encode("ascii")
                + body
            )
        _log.warning(
            "Refusing a connection from %s: %d/%d already open",
            (client_address[0] if client_address else "") or "unknown peer",
            self._connections_open,
            _MAX_CONNECTIONS,
        )
        self.shutdown_request(request)

    def process_request_thread(self, request: Any, client_address: Any) -> None:
        """One connection, one thread: the slot is released on every exit.

        The release wraps the whole superclass call, which already runs
        ``shutdown_request`` in its own ``finally``, so the counter and the
        descriptor cannot disagree about which connections are live.
        """
        try:
            super().process_request_thread(request, client_address)
        finally:
            metrics.CONNECTIONS.release()


# Hard deadline for every socket operation on a client connection (the request
# read and each response write).  Without it a half-open TCP peer (crashed
# laptop, dropped NAT mapping) or an SSE client that stops reading pins its
# handler thread forever: ThreadingMixIn caps neither threads nor connections,
# so wedged peers silently accumulate until process exit.  With the deadline,
# socket.timeout unwinds the stalled op and the thread exits, releasing the
# connection and (for /api/events) its bounded SSE slot.
#
# It is a per-OPERATION deadline, not a budget for the connection's life, so
# it says nothing about how long a stream may run: an idle /api/events
# response blocks on its event queue, not on the socket, and a deadline well
# under the SSE heartbeat serves it indefinitely.  What the value does decide
# is how slow a client may be before a write is cut mid-body.
#
# Also a DEFAULT rather than a constant: the same dashboard sits behind a
# direct connection on a workstation and behind a slow reverse proxy in a
# container, and the deadline that protects the first wedges the second.
# :func:`configure_transport` installs the resolved value.
_CLIENT_SOCKET_TIMEOUT_SECONDS = config.DEFAULT_CLIENT_TIMEOUT_SECONDS

#: How long an idle keep-alive connection waits for its next request before the
#: handler thread gives up and the socket closes.  The per-connection deadline
#: above covers a request in flight; a browser holding a connection open
#: between loads must not pin a thread for that whole deadline, and
#: ThreadingMixIn starts a thread per connection.  15 s is longer than any
#: real page load's asset burst, so a connection survives a slow load and dies
#: soon after the tab goes quiet.
_KEEPALIVE_IDLE_SECONDS = 15

# Longest request line the server will look at. The read asks for one byte
# more, so a line over the limit arrives whole and is refused rather than
# parsed as a truncated request.
_MAX_REQUEST_LINE = 65536

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

    def log_error(self, format: str, *args: Any) -> None:
        """Report a request the transport rejected, through the app's logger.

        Every one of these fails BEFORE a Bottle route exists, so nothing
        downstream logs it: an over-long request line (:meth:`_serve_requests`
        answers 414), a malformed one, an unsupported version, headers over the
        limit.  The stdlib default writes them to ``sys.stderr`` in
        ``http.server``'s own format, which carries no level, no timestamp
        format and no request id, so they land beside the app's structured
        lines as unparseable noise that a log filter drops.  A client stuck in
        a rejection loop was therefore invisible in the one place the operator
        reads, while the rejection itself reached the client.

        The peer address is included because these never reach a route: it is
        the only thing that separates one misbehaving client from a scanner.
        ``send_error`` quotes the request line, the method and the version it
        rejected, all of which are attacker-controlled, so a line-breaking
        byte in one of them would forge log entries.  What keeps that out of
        the log is upstream: ``parse_request`` builds those messages with a
        ``%r``, so the attacker bytes are already quoted by the time
        ``send_error`` logs the text with its own ``%s`` (the version number,
        the one unquoted value, is digits by the time it gets there).  This
        module does not escape the text
        itself, and cannot without reaching up into ``server`` for
        ``_log_safe`` — an edge the level order forbids a transport leaf to
        take.  So the guarantee rests on the stdlib's formatting, not on this
        code: a caller that passes a raw string as *args* would put unescaped
        request bytes in the log, and a new one has to keep passing the
        request's bytes through a repr.  There is no request id to carry: the
        id is minted in ``before_request``, which a transport rejection never
        reaches.
        """
        _log.warning(
            "Transport rejected a request from %s: %r",
            self.address_string() or "unknown peer",
            format % args,
        )


class _KeepAliveRequestHandler(_QuietTimeoutRequestHandler):
    """Handler that serves every request on a connection, not just the first.

    wsgiref's stock handler is HTTP/1.0 and its ``handle`` reads one request
    line and returns, so the connection closed after every response: loading
    the dashboard opened a fresh TCP connection for the shell, the bundle,
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
        """Serve every request on the connection, then return on the deadline.

        Both exceptions below are the CLOSE PATH, not a fault: the readline
        that times out is an idle keep-alive connection hitting
        :data:`_KEEPALIVE_IDLE_SECONDS`, and the ConnectionError is a peer that
        went away mid-loop.  ``socketserver`` prints a full traceback for
        anything escaping ``handle()``, so an unwrapped timeout buried a
        working dashboard under a dozen lines of noise for every browser tab
        that idled past the deadline.  Nothing is lost by swallowing them: the
        connection is being closed either way, and a real fault in a handler
        arrives through the app, not through the request-line read.
        """
        with contextlib.suppress(TimeoutError, ConnectionError):
            self._serve_requests()

    def _serve_requests(self) -> None:
        self.raw_requestline = self.rfile.readline(_MAX_REQUEST_LINE + 1)
        while self.raw_requestline:
            if len(self.raw_requestline) > _MAX_REQUEST_LINE:
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
            self.raw_requestline = self.rfile.readline(_MAX_REQUEST_LINE + 1)

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
