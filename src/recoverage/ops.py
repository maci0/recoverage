"""The op worker the relumea backend dispatches coverage calls to.

The backend names each call ``recoverage.<op>`` with a JSON request and reads a
JSON reply (contract: the backend's ``internal/engines/recoverage`` package and
its generated ``contracts/dispatch/recoverage.schema.json``).  Two ops are
answered here:

``recoverage.coverage_gate`` compares one target's sections with a threshold
and replies with the verdict document ``recoverage check --json`` prints.  A
threshold no section meets is still a reply: the gate result is data, not a
refusal.

``recoverage.coverage_export`` renders one target as JSON, CSV or Markdown and
replies with the body a redirected ``recoverage export`` writes, so the backend
serves recoverage's formatting instead of a second copy of it.

One transport: ``recoverage ops call <op>`` reads the request on stdin and
writes the reply on stdout.  A refusal writes ``{"error", "detail", "status"}``
on stdout and exits ``EXIT_ERROR``.

A request names an absolute ``project_dir`` and the ``sha256`` of a target's
binary; the target is resolved through rebrew's project config, the same rule
the CLI's target names follow.  With ``--workspace`` configured the project
path must resolve inside it.
"""

from __future__ import annotations

import hashlib
import json
import logging
import re
import sys
import typing
from dataclasses import MISSING, dataclass, fields
from pathlib import Path
from typing import Any
lazy from collections.abc import Callable, Mapping

import typer
lazy from rebrew.coverage_toml import CoverageTomlError
lazy from rebrew.workspace import CONFIG_NAME

lazy from recoverage import reporting
lazy from recoverage._paths import project_override

_log = logging.getLogger("recoverage")

#: Exit code of a refusal.
EXIT_ERROR = 2

#: Largest request body accepted.  Both requests are a project path, a digest
#: and one option, so anything near this size is not a request.
MAX_REQUEST_BYTES = 1 << 20

#: Largest reply written.  The backend reads at most this much (its
#: ``dispatch.MaxReply``), so a larger reply is refused here, with a reason.
MAX_REPLY_BYTES = 64 << 20

#: Detail characters kept from a failure.
DETAIL_MAX_CHARS = 400

INVALID_REQUEST = "invalid-request"
UNKNOWN_OP = "unknown-op"
TARGET_NOT_FOUND = "target-not-found"
COVERAGE_NOT_FOUND = "coverage-not-found"
ENGINE_ERROR = "engine-error"

_SHA256 = re.compile(r"[0-9a-f]{64}\Z")


class OpsError(Exception):
    """A refusal: a detail safe to show, a stable code, and an HTTP status."""

    def __init__(self, detail: str, *, code: str = ENGINE_ERROR, status: int = 500) -> None:
        super().__init__(detail)
        self.code = code
        self.status = status


def _invalid(detail: str) -> OpsError:
    return OpsError(detail, code=INVALID_REQUEST, status=400)


def _bounded(text: str) -> str:
    """*text* on one line, cut at :data:`DETAIL_MAX_CHARS`."""
    return " ".join(text.split())[:DETAIL_MAX_CHARS]


def error_body(code: str, detail: str, status: int) -> bytes:
    """The refusal reply the transport writes."""
    return json.dumps({"error": code, "detail": detail, "status": status}).encode()


# ---------------------------------------------------------------------------
# Worker configuration
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class WorkerConfig:
    """Where the worker may read projects from.

    ``workspace`` is the directory every request ``project_dir`` must resolve
    inside; None means the request is trusted with any absolute path.
    """

    workspace: Path | None = None


def _existing_dir(value: Path | None, flag: str) -> Path | None:
    if value is None:
        return None
    if not value.is_absolute() or not value.is_dir():
        typer.secho(
            f"Error: {flag} must be an absolute path to an existing directory: {value}",
            fg=typer.colors.RED,
            err=True,
        )
        raise typer.Exit(EXIT_ERROR)
    return value.resolve()


def confined_dir(config: WorkerConfig, text: str, what: str) -> Path:
    """The absolute directory *text*, resolved; inside the workspace when one is set."""
    path = Path(text)
    if not path.is_absolute():
        raise _invalid(f"{what} must be an absolute path")
    resolved = path.resolve()
    if config.workspace is not None and not resolved.is_relative_to(config.workspace):
        raise _invalid(f"{what} must be inside the worker workspace")
    return resolved


def project_root(config: WorkerConfig, project_dir: str) -> Path:
    """The rebrew project at *project_dir* (see :func:`confined_dir`)."""
    root = confined_dir(config, project_dir, "project_dir")
    if not (root / CONFIG_NAME).is_file():
        raise _invalid("project_dir is not a rebrew project (no rebrew-project.toml)")
    return root


# ---------------------------------------------------------------------------
# Requests (field names and required fields follow the backend's Go types)
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class GateRequest:
    """One target to gate: its project, its binary digest, and the threshold."""

    project_dir: str
    sha256: str
    min_coverage: float
    section: str = ""


@dataclass(frozen=True)
class ExportRequest:
    """One target to render: its project, its binary digest, and the format."""

    project_dir: str
    sha256: str
    format: str


def _decode(value: Any, hint: Any, where: str) -> Any:
    """Check one JSON value against the field type *hint*."""
    if hint is str:
        if type(value) is not str:
            raise _invalid(f"{where} must be a string")
        return value
    if hint is float:
        # A JSON integer is the same number: Go writes 50 for a whole
        # percentage and 87.5 for the rest.
        if type(value) not in (int, float) or not -1e308 < value < 1e308:
            raise _invalid(f"{where} must be a number")
        return float(value)
    return _invalid(f"{where} has an unsupported type")


def parse_request[T](cls: type[T], raw: Any, where: str = "request") -> T:
    """Build *cls* from a decoded JSON object, refusing unknown and missing fields."""
    if type(raw) is not dict:
        raise _invalid(f"{where} must be a JSON object")
    hints = typing.get_type_hints(cls)
    known = {spec.name: spec for spec in fields(cls)}  # type: ignore[arg-type]
    unknown = sorted(set(raw) - set(known))
    if unknown:
        raise _invalid(f"{where} has unknown fields: {', '.join(unknown)}")
    values: dict[str, Any] = {}
    for name, spec in known.items():
        if name in raw:
            values[name] = _decode(raw[name], hints[name], f"{where}.{name}")
        elif spec.default is MISSING and spec.default_factory is MISSING:
            raise _invalid(f"{where} is missing {name}")
    return cls(**values)


# ---------------------------------------------------------------------------
# Target resolution and statistics
# ---------------------------------------------------------------------------


def _file_sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1 << 20), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _resolve_target(root: Path, sha256: str) -> str:
    """The target of *root* whose binary hashes to *sha256*."""
    from rebrew.workspace import read_config, target_binary, targets_table

    wanted = sha256
    if not _SHA256.match(wanted):
        raise _invalid("sha256 must be 64 lowercase hexadecimal characters")
    for name, entry in targets_table(read_config(root)).items():
        binary = target_binary(root, entry)
        if binary is not None and binary.is_file() and _file_sha256(binary) == wanted:
            return name
    raise OpsError(
        f"no target of project_dir has a binary with sha256 {wanted}",
        code=TARGET_NOT_FOUND,
        status=404,
    )


def _target_stats(root: Path, target: str) -> dict[str, Any]:
    """One target's ``_section_stats``, or a refusal naming what is missing."""
    from recoverage.documents import load_all, unreadable
    from recoverage.server import _section_stats

    # Inside an op the request's project is authoritative: RECOVERAGE_SNAPSHOTS
    # selects the dashboard's portable exports, not this call's project.
    try:
        with project_override(root):
            snapshots = load_all(root)
            failures = unreadable(root)
    except CoverageTomlError as exc:
        raise OpsError(f"cannot read coverage for project_dir: {exc}", code=ENGINE_ERROR) from exc
    snapshot = snapshots.get(target)
    if snapshot is None:
        for _name, failed_target, reason in failures:
            if failed_target == target:
                raise OpsError(
                    f"coverage document for target {target} is unreadable: {reason}",
                    code=ENGINE_ERROR,
                )
        raise OpsError(
            f"no coverage document for target {target}",
            code=COVERAGE_NOT_FOUND,
            status=404,
        )
    try:
        return _section_stats(snapshot)
    except CoverageTomlError as exc:
        raise OpsError(
            f"cannot read coverage statistics for target {target}: {exc}",
            code=ENGINE_ERROR,
        ) from exc


# ---------------------------------------------------------------------------
# Ops
# ---------------------------------------------------------------------------


def coverage_gate(config: WorkerConfig, request: GateRequest) -> Mapping[str, Any]:
    """Compare one target's sections with ``min_coverage``."""
    if not 0.0 <= request.min_coverage <= 100.0:
        raise _invalid("min_coverage must be between 0 and 100")
    root = project_root(config, request.project_dir)
    target = _resolve_target(root, request.sha256)
    stats = _target_stats(root, target)
    outcome = reporting.gate(
        [(target, stats)],
        min_coverage=request.min_coverage,
        section=request.section or None,
    )
    reply = outcome.document()
    if outcome.reason is not None:
        reply["reason"] = outcome.reason
    return reply


def coverage_export(config: WorkerConfig, request: ExportRequest) -> Mapping[str, Any]:
    """Render one target as JSON, CSV or Markdown."""
    if request.format not in reporting.EXPORT_FORMATS:
        wanted = ", ".join(reporting.EXPORT_FORMATS)
        raise _invalid(f"format must be one of {wanted}, got {request.format!r}")
    root = project_root(config, request.project_dir)
    target = _resolve_target(root, request.sha256)
    stats = _target_stats(root, target)
    return {
        "format": request.format,
        "content_type": reporting.CONTENT_TYPES[request.format],
        "body": reporting.render_export(request.format, [{"target": target, **stats}]),
    }


@dataclass(frozen=True)
class Op:
    """One wire op: its request type and the function that answers it."""

    request: type
    run: Callable[[WorkerConfig, Any], Mapping[str, Any]]


#: Every op of the backend's recoverage contract, by wire name.
OPS: dict[str, Op] = {
    "recoverage.coverage_gate": Op(GateRequest, coverage_gate),
    "recoverage.coverage_export": Op(ExportRequest, coverage_export),
}


def _answer(config: WorkerConfig, name: str, body: bytes) -> Mapping[str, Any]:
    op = OPS.get(name)
    if op is None:
        raise OpsError(f"unknown op: {_bounded(name)}", code=UNKNOWN_OP, status=404)
    if len(body) > MAX_REQUEST_BYTES:
        raise OpsError(
            f"request exceeds {MAX_REQUEST_BYTES} bytes", code=INVALID_REQUEST, status=413
        )
    try:
        raw = json.loads(body)
    except json.JSONDecodeError, UnicodeDecodeError:
        raise _invalid("request is not JSON") from None
    request: Any = parse_request(op.request, raw)
    try:
        return op.run(config, request)
    except OpsError:
        raise
    except typer.Exit as exc:
        raise OpsError(
            f"recoverage refused {name} (exit {exc.exit_code})", code=ENGINE_ERROR
        ) from None
    except Exception:  # the engine is a trust boundary: log the cause, answer a fixed detail
        _log.exception("%s failed", name)
        raise OpsError(f"{name} failed; the worker log has the cause") from None


def dispatch(config: WorkerConfig, name: str, body: bytes) -> tuple[int, bytes]:
    """Answer one call: ``(200, reply)`` or ``(status, refusal)``."""
    try:
        reply = json.dumps(_answer(config, name, body), allow_nan=False).encode()
    except OpsError as exc:
        return exc.status, error_body(exc.code, str(exc), exc.status)
    except TypeError, ValueError:
        _log.exception("%s produced a reply that is not JSON", name)
        return 500, error_body(ENGINE_ERROR, f"{name} produced a reply that is not JSON", 500)
    if len(reply) > MAX_REPLY_BYTES:
        return 500, error_body(ENGINE_ERROR, f"reply exceeds {MAX_REPLY_BYTES} bytes", 500)
    return 200, reply


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

app = typer.Typer(
    help="Answer the relumea backend's recoverage ops over stdin/stdout.",
    rich_markup_mode="rich",
    epilog=(
        "[bold]Examples:[/bold]\n\n"
        "  recoverage ops call recoverage.coverage_gate\n\n"
        "  recoverage ops call recoverage.coverage_export --workspace /srv/relumea\n\n"
        "Backend setup: the Go tree's docs/DISPATCH.md."
    ),
)

_WORKSPACE_HELP = "Directory every request project_dir must resolve inside"


@app.command("call")
def call_command(
    op: str = typer.Argument(..., help="Wire op name, such as recoverage.coverage_gate"),
    workspace: Path | None = typer.Option(
        None, "--workspace", envvar="RECOVERAGE_OPS_WORKSPACE", help=_WORKSPACE_HELP
    ),
) -> None:
    """Answer one op: the JSON request on stdin, the reply on stdout.

    A refusal prints {"error","detail","status"} on stdout and exits 2.
    """
    config = WorkerConfig(_existing_dir(workspace, "--workspace"))
    body = sys.stdin.buffer.read(MAX_REQUEST_BYTES + 1)
    status, reply = dispatch(config, op, body)
    sys.stdout.buffer.write(reply + b"\n")
    sys.stdout.flush()
    if status != 200:
        raise typer.Exit(EXIT_ERROR)
