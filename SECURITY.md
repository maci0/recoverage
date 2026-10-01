# Security Policy

## Supported versions

The current release line is `4.x`. `recoverage` is a single-developer,
single-machine tool: it is supported on the version the maintainer ships, and
older versions receive no backports.

| Version | Supported |
|---------|-----------|
| 4.x (current, `__version__` at `src/recoverage/__init__.py:42`; `4.1.2` is tagged `v4.1.2`) | yes |
| < 4.0.0 | no |

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

`recoverage serve` binds loopback and is unauthenticated by default. On
`--allow-remote` without `--token` every host that can reach the port reads the
whole project: sources under `<project>/src`, original binaries, raw byte
slices and disassembly. That is the deployment's assumption, not a defect, and
it is the first entry in the risk-ranked table in
[`docs/THREAT_MODEL.md`](docs/THREAT_MODEL.md).

## Threat model

`docs/THREAT_MODEL.md` is the maintained model: the attack surface, the trust
boundaries, the risks ranked by exploitability and impact, the mitigations that
exist in code with file references, the ones that do not, and the abuse cases.
Its scope statement says which deployment it covers; claims outside that scope
are not addressed there.
