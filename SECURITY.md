# Security Policy

## Supported versions

The current release line is `4.x`. `recoverage` is a single-developer,
single-machine tool: it is supported on the version the maintainer ships, and
older versions receive no backports.

| Version | Supported |
|---------|-----------|
| 4.x (current; `__version__` at `src/recoverage/__init__.py:42`, tagged `v4.2.0`) | yes |
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
names that as risk 4.

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
