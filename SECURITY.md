# Security Policy

## Supported versions

The current release line is `4.x`. `recoverage` is a single-developer,
single-machine tool: it is supported on the version the maintainer ships, and
older versions receive no backports.

| Version | Supported |
|---------|-----------|
| 4.x (current; `__version__` in `src/recoverage/__init__.py`, tagged `v4.3.0`) | yes |
| < 4.0.0 | no |

The supported line is what `__version__` says, so a build that disagrees with
the tag is the thing to look at first rather than this table.

## Reporting a vulnerability

No reporting address is recorded in this repository. Until one is, a report
belongs on the project's GitHub issue tracker
(`https://github.com/relumea/recoverage`, the `Repository` URL in
`pyproject.toml`), which is the only contact channel the repository names. Do
not open a public issue for a vulnerability that is already exploited or that
discloses private project material until a private channel exists.

There is no documented path from a report to a shipped fix, and no security
owner or review cadence is recorded either. Those are gaps, not policy, and
this document does not fill them with a guess.

## Deployment assumption

`recoverage serve` binds loopback by default (`config.DEFAULT_BIND`,
`src/recoverage/config.py`) and is unauthenticated unless a token is
configured. A non-loopback bind is refused at startup without
`--allow-remote` (`cli._remote_bind_gate`, `src/recoverage/cli.py`), and
`--allow-remote` without `--token` is an acknowledgement, not a requirement:
every host that can reach the port then reads the whole project, which is
sources under `<project>/src`, original binaries, raw byte slices and
disassembly. That is the deployment's assumption, not a defect, and it is the
first entry in the risk-ranked table in
[`docs/THREAT_MODEL.md`](docs/THREAT_MODEL.md).

The bundled listener speaks no TLS, so a non-loopback deployment has no
transport security either, and the token travels as a URL parameter. The model
names that as risk 4. The share-link form is narrowed on the client side: `/`
exchanges `?token=` for an HttpOnly cookie (`server.set_auth_cookie` in
`src/recoverage/server.py`, named by symbol rather than by line) and the SPA
then removes the parameter from
`window.location` (`web/app/App.tsx`), so the value does not stay in the
address bar, the current history entry or a bookmark. That is a client-side
window, not a transport change: the request line, an upstream proxy's access
log, a pasted link, and a URL copied before the page settles all still carry
the bearer value, so a token shared as a link should be read as disclosed to
every system that saw the request.

## Backups hold a copy of the project

`recoverage backup` writes every coverage document into one tar beside the
project (`../backups/` by default, or `$RECOVERAGE_BACKUP_DIR`). Since 4.3 the
coverage documents are the only durable state in the package — `history` and
`verify_results` are carried forward from the previous document and
`rebrew coverage build` cannot reproduce them — so that archive is the only copy of
them that outlives the tree, and losing it is not something a regen repairs.

Members are written `0o600` and every member's size and sha256 are recorded in
the archive's `manifest.json`, which `recoverage restore` re-checks in full
before it writes anything. There is no encryption and no at-rest integrity
beyond those digests, so an archive that reaches a shared filesystem, a
container volume or second storage should be read as a disclosed copy of the
project's reverse-engineering output, and `$RECOVERAGE_BACKUP_DIR` deserves the
same scrutiny as any other environment input.

`recoverage restore ARCHIVE` replaces the coverage documents from that file,
which is the same directory every served page reads. It takes no
authentication, because it is a local command and the holder of the filesystem
is the trust. It refuses to overwrite a document whose bytes differ unless
`--force` is given, and `--force` overrides that check and no other. A restore
is not logged through the package's logger and leaves no marker in the served
output, so a rollback and a rebuild are indistinguishable to a reader. The model
carries that as risks 12 and 13, boundary 9, and unmitigated 16 and 17;
`docs/RECOVERY.md` carries the operational drill.

## Running under a WSGI host

`recoverage.webapp.app` (`src/recoverage/webapp.py`) is the same fully routed
application, and a WSGI host may serve it directly instead of running
`recoverage serve`. Two things a reader should know before choosing that:

- The controls `serve` installs as a side effect of starting are the host's to
  install. `server.configure_security(...)`, in `src/recoverage/server.py`,
  sets the bearer token, the CORS allowlist and the `Host` allowlist, and
  every one of its defaults is off: no token, no CORS, and no `Host`
  validation. A host that mounts the app without calling it serves the whole
  project unauthenticated, and `cli._remote_bind_gate` in
  `src/recoverage/cli.py` does not apply: it is the CLI's acknowledgement
  rather than a property of the app.
- The connection cap, the per-connection deadline and the keep-alive framing
  live in `src/recoverage/devserver.py`, not in the app. Behind a WSGI host they
  are whatever the host enforces, which is the boundary the model ranks.

`docs/THREAT_MODEL.md` carries this as boundary 8 and folds it into risk 1.

## Threat model

`docs/THREAT_MODEL.md` is the maintained model: the attack surface, the trust
boundaries, the risks ranked by exploitability and impact, the mitigations that
exist in code with file references, the ones that do not, and the abuse cases.
Its scope statement says which deployment it covers; claims outside that scope
are not addressed there.

Its header records the date and the commit it was last read against, so a
reader can tell a current model from a stale one, and a change to
`src/recoverage/` landing after that commit is unreviewed until the model names
it. Every claim in that file carries a file reference.
