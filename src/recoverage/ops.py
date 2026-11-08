"""The op worker the relumea backend dispatches coverage calls to.

The backend names each call ``recoverage.<op>`` with a JSON request and reads a
JSON reply (contract: the backend's ``internal/engines/recoverage`` package and
its generated ``contracts/dispatch/recoverage.schema.json``).  Four ops are
answered here:

``recoverage.coverage_plan`` lists the staged coverage inputs a retained
snapshot carries, including absences, so the backend can plan a build before
one runs.

``recoverage.coverage_gate`` compares one target's sections with a threshold
and replies with the verdict document ``recoverage check --json`` prints.  A
threshold no section meets is still a reply: the gate result is data, not a
refusal.

``recoverage.coverage_map`` returns the dashboard's section cells and their
canonical statistics for one target.

``recoverage.coverage_export`` renders one target as JSON, CSV or Markdown and
replies with the body a redirected ``recoverage export`` writes, so the backend
serves recoverage's formatting instead of a second copy of it.

Two transports: ``recoverage ops call <op>`` reads the request on stdin and
writes the reply on stdout; a refusal writes ``{"error", "code", "detail", "status"}``
on stdout and exits ``EXIT_ERROR``.  ``recoverage ops serve`` answers
``POST /<op>`` over HTTP with rebrew's ops server (bearer token, host check,
concurrency bound, ``/health``), calling the same :func:`dispatch`.

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
import tempfile
import typing
from dataclasses import MISSING, dataclass, field, fields, replace
from pathlib import Path
from typing import Any
lazy from collections.abc import Callable, Mapping

import typer
lazy from rebrew.coverage_toml import CoverageTomlError
lazy from rebrew.workspace import CONFIG_NAME

from recoverage.config import RecoError, json_depth_exceeds
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

#: Compiled once at import rather than per allowed-hosts entry. The port
#: is a real port, not any five digits: ``:0`` and ``:99999`` name no
#: listener, and the rebrew server compares the request's Host against
#: this list verbatim, so accepting them would allow-list a spelling no
#: client can legitimately send while refusing nothing.
_ALLOWED_HOST = re.compile(
    r"[a-z0-9][a-z0-9.-]*(?::(?:[1-9][0-9]{0,3}|[1-5][0-9]{4}|6[0-4][0-9]{3}"
    r"|65[0-4][0-9]{2}|655[0-2][0-9]|6553[0-5]))?"
)


class OpsError(RecoError):
    """A refusal: a detail safe to show, a stable code, and an HTTP status."""

    def __init__(self, detail: str, *, code: str = ENGINE_ERROR, status: int = 500) -> None:
        super().__init__(detail)
        self.code = code
        self.status = status


class InvalidRequestError(OpsError):
    """The request was malformed or failed validation (HTTP 400)."""

    def __init__(self, detail: str) -> None:
        super().__init__(detail, code=INVALID_REQUEST, status=400)


class NotFoundError(OpsError):
    """The named op, target, or coverage was not found (HTTP 404)."""

    def __init__(self, detail: str, *, code: str) -> None:
        super().__init__(detail, code=code, status=404)


class ConflictError(OpsError):
    """The request conflicts with retained evidence state (HTTP 409)."""

    def __init__(self, detail: str) -> None:
        super().__init__(detail, code="coverage-input-invalid", status=409)


def _invalid(detail: str) -> OpsError:
    return InvalidRequestError(detail)


def _bounded(text: str) -> str:
    """*text* on one line, cut at :data:`DETAIL_MAX_CHARS`.

    The cut never lands inside a grapheme cluster: a base character whose
    combining mark, format character (ZWJ/ZWNJ) or emoji modifier follows it
    keeps its continuation, so an NFD-spelled detail, a ZWJ emoji sequence or
    a skin-tone modifier is never severed from the glyph it belongs to.  The
    result may run a few code points past :data:`DETAIL_MAX_CHARS` to keep
    that continuation, the cheaper trade than a severed mark re-colouring or
    re-accenting nothing.
    """
    from recoverage.server import truncate_text

    return truncate_text(" ".join(text.split()), DETAIL_MAX_CHARS)


def error_body(code: str, detail: str, status: int) -> bytes:
    """The refusal reply the transport writes, mirroring the HTTP error envelope."""
    return json.dumps({"error": code, "code": code, "detail": detail, "status": status}).encode()


# ---------------------------------------------------------------------------
# Worker configuration
# ---------------------------------------------------------------------------


@dataclass(frozen=True, kw_only=True)
class WorkerConfig:
    """Where the worker may read projects from.

    ``workspace`` is the directory every request ``project_dir`` must resolve
    inside; None means the request is trusted with any absolute path.
    """

    workspace: Path | None = None
    filestore: Path | None = None


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
class RetainedFile:
    """One retained source file: its path in the snapshot and the object that holds its bytes."""

    path: str
    digest: str
    size: int
    key: str = ""
    url: str = ""


@dataclass(frozen=True, kw_only=True)
class RetainedRequest:
    """The retained snapshot a request names: its files, rebrew target and binary object."""

    files: list[RetainedFile] = field(default_factory=list)
    rebrew_target: str = ""
    binary_key: str = ""
    binary_url: str = ""
    coverage_input: dict[str, Any] = field(default_factory=dict)
    coverage_input_digest: str = ""
    verification_records: list[dict[str, Any]] = field(default_factory=list)


@dataclass(frozen=True, kw_only=True)
class GateRequest(RetainedRequest):
    """One target to gate: its project, its binary digest, and the threshold."""

    project_dir: str
    sha256: str
    min_coverage: float
    section: str = ""
    metric: str = "identified"


@dataclass(frozen=True, kw_only=True)
class PlanRequest(RetainedRequest):
    """Plan the readset for retained coverage inputs."""

    project_dir: str
    sha256: str


@dataclass(frozen=True, kw_only=True)
class MapRequest(RetainedRequest):
    """One target to map."""

    project_dir: str
    sha256: str


@dataclass(frozen=True, kw_only=True)
class ExportRequest(RetainedRequest):
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
    if hint is int:
        if type(value) is not int:
            raise _invalid(f"{where} must be an integer")
        return value
    if hint == list[RetainedFile]:
        if type(value) is not list:
            raise _invalid(f"{where} must be an array")
        return [parse_request(RetainedFile, item, f"{where}[{i}]") for i, item in enumerate(value)]
    if hint == dict[str, Any]:
        if type(value) is not dict:
            raise _invalid(f"{where} must be a JSON object")
        return value
    if hint == list[dict[str, Any]]:
        if type(value) is not list or any(type(item) is not dict for item in value):
            raise _invalid(f"{where} must be an array of objects")
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
    raise NotFoundError(
        f"no target of project_dir has a binary with sha256 {wanted}",
        code=TARGET_NOT_FOUND,
    )


def _target_snapshot(root: Path, target: str) -> Any:
    """Load one target, or refuse with the reason it is missing."""
    from recoverage.documents import load_all, unreadable

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
        raise NotFoundError(
            f"no coverage document for target {target}",
            code=COVERAGE_NOT_FOUND,
        )
    return snapshot


def _trusted_snapshot(root: Path, target: str, trusted: Any) -> Any:
    from rebrew.config import load_config
    from rebrew.coverage_project import trusted_project_coverage

    return trusted_project_coverage(load_config(root, target=target), trusted)


def _verified_section_bytes(section: Any, trusted: Any) -> int:
    """Count exact cells only inside authenticated function extents."""
    if section.va is None:
        return 0
    ranges: list[list[int]] = []
    for record in sorted(trusted.records, key=lambda item: item.va):
        if record.status != "EXACT":
            continue
        start, end = record.va, record.va + record.size
        if ranges and start <= ranges[-1][1]:
            ranges[-1][1] = max(ranges[-1][1], end)
        else:
            ranges.append([start, end])
    covered: list[list[int]] = []
    for cell in sorted(section.cells, key=lambda item: item.start):
        if cell.state != "exact":
            continue
        lo, hi = section.va + cell.start, section.va + cell.end
        if hi <= lo:
            continue
        cursor = 0
        while cursor < len(ranges) and ranges[cursor][1] <= lo:
            cursor += 1
        while cursor < len(ranges) and ranges[cursor][0] < hi:
            start = max(lo, ranges[cursor][0])
            end = min(hi, ranges[cursor][1])
            if covered and start <= covered[-1][1]:
                covered[-1][1] = max(covered[-1][1], end)
            else:
                covered.append([start, end])
            cursor += 1
    return sum(end - start for start, end in covered)


def _snapshot_stats(snap: Any, trusted: Any = None) -> dict[str, Any]:
    from recoverage.reporting import coverage_pct
    from recoverage.server import _section_stats

    stats = _section_stats(snap)
    if trusted is not None:
        stats["coverage_metric"] = "identified"
        for name, sec in stats["sections"].items():
            verified = _verified_section_bytes(snap.sections[name], trusted)
            sec["verified_bytes"] = verified
            sec["verified_pct"] = coverage_pct(verified, sec["total_bytes"])
    return stats


def _target_stats(root: Path, target: str, trusted: Any = None) -> dict[str, Any]:
    try:
        snap = (
            _target_snapshot(root, target)
            if trusted is None
            else _trusted_snapshot(root, target, trusted)
        )
        return _snapshot_stats(snap, trusted)
    except CoverageTomlError as exc:
        raise OpsError(
            f"cannot read coverage statistics for target {target}: {exc}",
            code=ENGINE_ERROR,
        ) from exc


# ---------------------------------------------------------------------------
# Ops
# ---------------------------------------------------------------------------


def coverage_plan(config: WorkerConfig, request: PlanRequest) -> Mapping[str, Any]:
    """List the independently discovered staged coverage inputs, including absences."""
    from rebrew.coverage_input_contract import (
        CoverageInputError,
        plan_coverage_config,
        plan_coverage_readset,
    )

    if (
        not request.files
        or not request.rebrew_target
        or not (request.binary_key or request.binary_url)
    ):
        raise _invalid("coverage plan requires a retained snapshot")
    root = project_root(config, request.project_dir)
    try:
        config_view, sources = plan_coverage_config(root, request.rebrew_target)
        return {
            "readset": plan_coverage_readset(root, request.rebrew_target),
            "source_paths": sources,
            "config": config_view,
        }
    except CoverageInputError as exc:
        raise _invalid(str(exc)) from None


def coverage_gate(
    config: WorkerConfig, request: GateRequest, trusted: Any = None
) -> Mapping[str, Any]:
    """Compare one target's sections with ``min_coverage``."""
    if not 0.0 <= request.min_coverage <= 100.0:
        raise _invalid("min_coverage must be between 0 and 100")
    metric = request.metric or "identified"
    if metric not in ("identified", "verified"):
        raise _invalid("metric must be identified or verified")
    if metric == "verified" and trusted is None:
        raise ConflictError(
            "verified coverage requires retained evidence",
        )
    root = project_root(config, request.project_dir)
    target = request.rebrew_target or _resolve_target(root, request.sha256)
    stats = _target_stats(root, target, trusted)
    outcome = reporting.gate(
        [(target, stats)],
        min_coverage=request.min_coverage,
        section=request.section or None,
        covered_key="verified_bytes" if metric == "verified" else "covered_bytes",
        zero_is_untracked=metric != "verified",
    )
    reply = outcome.document()
    reply["metric"] = metric
    if trusted is not None:
        for result in reply["results"]:
            section = stats["sections"][result["section"]]
            result["verified_bytes"] = section["verified_bytes"]
            result["verified_pct"] = section["verified_pct"]
            if metric == "verified":
                result["coverage_pct"] = section["verified_pct"]
    if outcome.reason is not None:
        reply["reason"] = outcome.reason
    return reply


def coverage_map(
    config: WorkerConfig, request: MapRequest, trusted: Any = None
) -> Mapping[str, Any]:
    """Return the dashboard's section cells and their canonical statistics."""
    from recoverage.server import _bucket_row, _cell_json

    root = project_root(config, request.project_dir)
    target = request.rebrew_target or _resolve_target(root, request.sha256)
    snap = (
        _target_snapshot(root, target)
        if trusted is None
        else _trusted_snapshot(root, target, trusted)
    )
    return {
        "target": target,
        "sections": {
            name: {
                "target": target,
                "name": name,
                "va": sec.va,
                "size": sec.size,
                "fileOffset": sec.file_offset,
                "unitBytes": sec.unit_bytes,
                "columns": sec.columns,
                "cells": [_cell_json(cell) for cell in sec.cells],
            }
            for name, sec in snap.sections.items()
        },
        "section_cell_stats": {
            name: _bucket_row(sec) for name, sec in snap.sections.items() if sec.cells
        },
        "stats": _snapshot_stats(snap, trusted),
    }


def coverage_export(
    config: WorkerConfig, request: ExportRequest, trusted: Any = None
) -> Mapping[str, Any]:
    """Render one target as JSON, CSV or Markdown."""
    if request.format not in (*reporting.EXPORT_FORMATS, "decomp.dev"):
        wanted = ", ".join((*reporting.EXPORT_FORMATS, "decomp.dev"))
        raise _invalid(f"format must be one of {wanted}, got {request.format!r}")
    root = project_root(config, request.project_dir)
    target = request.rebrew_target or _resolve_target(root, request.sha256)
    if request.format == "decomp.dev":
        from rebrew.config import load_config
        from rebrew.report import generate_decomp_dev_report

        with tempfile.TemporaryDirectory(prefix="recoverage-report-") as directory:
            output = Path(directory) / "report.json"
            cfg = load_config(root, target=target)
            if trusted is None:
                generate_decomp_dev_report(cfg, output)
            else:
                generate_decomp_dev_report(cfg, output, trusted=trusted)
            body = output.read_text(encoding="utf-8")
        return {"format": request.format, "content_type": "application/json", "body": body}
    stats = _target_stats(root, target, trusted)
    return {
        "format": request.format,
        "content_type": reporting.CONTENT_TYPES[request.format],
        "body": reporting.render_export(request.format, [{"target": target, **stats}]),
    }


@dataclass(frozen=True)
class Op:
    """One wire op: its request type and the function that answers it."""

    request: type
    #: ``run(config, request)``; a scoring op also takes the verified evidence third.
    run: Callable[..., Mapping[str, Any]]


#: Every op of the backend's recoverage contract, by wire name.
OPS: dict[str, Op] = {
    "recoverage.coverage_plan": Op(PlanRequest, coverage_plan),
    "recoverage.coverage_gate": Op(GateRequest, coverage_gate),
    "recoverage.coverage_map": Op(MapRequest, coverage_map),
    "recoverage.coverage_export": Op(ExportRequest, coverage_export),
}


def _answer(config: WorkerConfig, name: str, body: bytes) -> Mapping[str, Any]:
    op = OPS.get(name)
    if op is None:
        raise NotFoundError(f"unknown op: {_bounded(name)}", code=UNKNOWN_OP)
    if len(body) > MAX_REQUEST_BYTES:
        raise OpsError(
            f"request exceeds {MAX_REQUEST_BYTES} bytes", code=INVALID_REQUEST, status=413
        )
    try:
        if json_depth_exceeds(body):
            raise _invalid("request is not JSON")
        raw = json.loads(body)
    except json.JSONDecodeError, UnicodeDecodeError, RecursionError:
        raise _invalid("request is not JSON") from None
    request: Any = parse_request(op.request, raw)
    try:
        snapshot_fields = (
            "files",
            "rebrew_target",
            "binary_key",
            "binary_url",
            "coverage_input",
            "coverage_input_digest",
            "verification_records",
        )
        if any(key in raw for key in snapshot_fields):
            # The backend supplies a complete retained manifest; never use project_dir here.
            try:
                from rebrew.ops import (
                    FlagSearchFile,
                    confined_snapshot_config,
                    retained_target_snapshot,
                )
                from rebrew.ops import (
                    OpsError as RebrewOpsError,
                )
                from rebrew.ops import (
                    WorkerConfig as RebrewWorkerConfig,
                )
            except ImportError:
                raise OpsError("retained snapshots require the pinned rebrew worker") from None
            try:
                worker = RebrewWorkerConfig(filestore=config.filestore, workspace=config.workspace)
                files = [
                    FlagSearchFile(**{f.name: getattr(entry, f.name) for f in fields(entry)})
                    for entry in request.files
                ]
                with retained_target_snapshot(
                    worker,
                    files,
                    request.rebrew_target,
                    request.sha256,
                    request.binary_key,
                    request.binary_url,
                ) as root:
                    from rebrew.config import load_config

                    confined_snapshot_config(load_config(root, target=request.rebrew_target), root)
                    staged = replace(request, project_dir=str(root))
                    if name == "recoverage.coverage_plan":
                        return op.run(config, staged)
                    required = ("coverage_input", "coverage_input_digest", "verification_records")
                    if any(key not in raw for key in required):
                        raise ConflictError(
                            "retained coverage requires the complete input envelope",
                        )
                    from rebrew.coverage_input_contract import (
                        CoverageInputError,
                        validate_coverage_execution,
                    )
                    from rebrew.workspace.status import TrustedCoverage, TrustedVerification

                    def validate() -> None:
                        validate_coverage_execution(
                            root,
                            request.rebrew_target,
                            request.sha256,
                            request.coverage_input,
                            request.coverage_input_digest,
                            request.verification_records,
                        )

                    try:
                        validate()
                        try:
                            trusted = TrustedCoverage(
                                tuple(
                                    TrustedVerification(
                                        source=row["source"],
                                        va=row["va"],
                                        size=row["size"],
                                        status=row["status"],
                                        match_count=row["match_count"],
                                    )
                                    for row in request.verification_records
                                )
                            )
                        except (KeyError, TypeError, ValueError) as exc:
                            raise _invalid(
                                f"verification_records entry is malformed: {exc}"
                            ) from None
                        reply = op.run(config, staged, trusted)
                        validate()
                        return reply
                    except CoverageInputError as exc:
                        raise ConflictError(str(exc)) from None
            except RebrewOpsError as exc:
                raise OpsError(str(exc), code=exc.code, status=exc.status) from None
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


def dispatch_json(config: WorkerConfig, name: str, request: Mapping[str, Any]) -> tuple[int, Any]:
    """Answer one call from a dict: ``(200, reply)`` or ``(status, refusal)``.

    Convenience over :func:`dispatch` for in-process callers; the reply and
    refusal are parsed JSON values rather than wire bytes.
    """
    status, body = dispatch(config, name, json.dumps(request).encode())
    try:
        return status, json.loads(body)
    except ValueError:
        return status, body


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
    filestore: Path | None = typer.Option(
        None, "--filestore", envvar="RECOVERAGE_OPS_FILESTORE", help="Retained object store"
    ),
) -> None:
    """Answer one op: the JSON request on stdin, the reply on stdout.

    A refusal prints {"error","code","detail","status"} on stdout and exits 2.
    """
    config = WorkerConfig(
        workspace=_existing_dir(workspace, "--workspace"),
        filestore=_existing_dir(filestore, "--filestore"),
    )
    body = sys.stdin.buffer.read(MAX_REQUEST_BYTES + 1)
    status, reply = dispatch(config, op, body)
    sys.stdout.buffer.write(reply + b"\n")
    sys.stdout.flush()
    if status != 200:
        raise typer.Exit(EXIT_ERROR)


#: Environment variable holding the bearer token ``serve`` requires.
TOKEN_ENV = "RECOVERAGE_OPS_TOKEN"  # noqa: S105  # a variable name, not a credential

#: Shortest accepted bearer token, the length rebrew's server requires.
PORT_ENV = "RECOVERAGE_OPS_PORT"
HOST_ENV = "RECOVERAGE_OPS_HOST"
MIN_TOKEN_BYTES = 32

#: Calls answered at once; the next is refused 503 with Retry-After.  A map call peaks near 115 MiB.
DEFAULT_CONCURRENCY = 2

#: Upper bound on simultaneous calls, so a typo reads as a refusal rather
#: than a worker that admits thousands of 115 MiB calls at once.
MAX_CONCURRENCY = 64


@app.command("serve")
def serve_command(
    port: str | None = typer.Option(
        None, "--port", envvar=PORT_ENV, help="TCP port; 0 picks a free one"
    ),
    host: str = typer.Option(
        "127.0.0.1", "--host", envvar=HOST_ENV, help="Address to bind (loopback by default)"
    ),
    workspace: Path | None = typer.Option(
        None, "--workspace", envvar="RECOVERAGE_OPS_WORKSPACE", help=_WORKSPACE_HELP + " (required)"
    ),
    filestore: Path | None = typer.Option(
        None, "--filestore", envvar="RECOVERAGE_OPS_FILESTORE", help="Retained object store"
    ),
    concurrency: str | None = typer.Option(
        None,
        "--concurrency",
        envvar="RECOVERAGE_OPS_CONCURRENCY",
        help="Calls answered at once; the next is refused 503 with Retry-After",
    ),
    allowed_hosts: str = typer.Option(
        "",
        "--allowed-hosts",
        envvar="RECOVERAGE_OPS_ALLOWED_HOSTS",
        help="Comma-separated exact additional HTTP Host authorities, including ports",
    ),
) -> None:
    """Serve POST /<op> over HTTP until interrupted or terminated.

    Every request needs Authorization: Bearer $RECOVERAGE_OPS_TOKEN.  --workspace
    is required: every project path a request names must lie inside it, and the
    retained snapshots a call builds are written under it.
    """
    import os
    import signal
    import threading

    from rebrew import ops as rebrew_ops

    from recoverage import config as _config

    # Typer/click's INT coercion accepts Unicode digits and ``1_0`` spellings,
    # so parse the concurrency through the same ASCII floor the dashboard
    # settings use; the flag and env var are one setting.
    parse_ascii_int = _config.parse_ascii_int

    # Misspelled RECOVERAGE_* names are a startup error everywhere else
    # (``_check_env_or_exit``); ``ops serve`` must not silently accept them
    # just because it never went through the dashboard's env check.
    try:
        _config.check_unknown_vars()
    except _config.ConfigError as exc:
        typer.secho(f"Error: {exc}", fg=typer.colors.RED, err=True)
        raise typer.Exit(EXIT_ERROR) from None

    if port is None:
        typer.secho(
            f"Error: serve needs --port (or {PORT_ENV})",
            fg=typer.colors.RED,
            err=True,
        )
        raise typer.Exit(EXIT_ERROR)
    try:
        resolved_port = parse_ascii_int(port.strip())
    except ValueError:
        typer.secho(
            f"Error: --port (or {PORT_ENV}) is not an integer",
            fg=typer.colors.RED,
            err=True,
        )
        raise typer.Exit(EXIT_ERROR) from None

    if concurrency is None:
        resolved_concurrency = DEFAULT_CONCURRENCY
    else:
        try:
            resolved_concurrency = parse_ascii_int(concurrency.strip())
        except ValueError:
            typer.secho(
                "Error: --concurrency (or RECOVERAGE_OPS_CONCURRENCY) is not an integer",
                fg=typer.colors.RED,
                err=True,
            )
            raise typer.Exit(EXIT_ERROR) from None
        if not 1 <= resolved_concurrency <= MAX_CONCURRENCY:
            typer.secho(
                f"Error: --concurrency (or RECOVERAGE_OPS_CONCURRENCY) must be "
                f"between 1 and {MAX_CONCURRENCY}",
                fg=typer.colors.RED,
                err=True,
            )
            raise typer.Exit(EXIT_ERROR)

    # A token that carries surrounding whitespace would never match a
    # stripped bearer header, so refuse it at startup like the dashboard
    # token rather than silently stripping it to a usable value.
    from recoverage.config import ConfigError, validate_bind, validate_token

    # --port/--host are one setting with the dashboard's RECOVERAGE_PORT/
    # RECOVERAGE_BIND: without the same floor an out-of-range port or a
    # host:port/URL spelled as host reaches socket.bind() as a traceback
    # (OverflowError/gaierror) instead of a startup error naming the flag.
    try:
        host = validate_bind(host, "--host")
        if not 0 <= resolved_port <= 65535:
            raise ConfigError(f"--port: {resolved_port} is not in the range 0-65535")
    except ConfigError as exc:
        typer.secho(f"Error: {exc}", fg=typer.colors.RED, err=True)
        raise typer.Exit(EXIT_ERROR) from None

    raw_token = os.environ.get(TOKEN_ENV)
    try:
        token = validate_token(raw_token, TOKEN_ENV) or ""
    except ConfigError as exc:
        typer.secho(f"Error: {exc}", fg=typer.colors.RED, err=True)
        raise typer.Exit(EXIT_ERROR) from None
    # Length in the bytes the environment carried, not code points: an
    # environment value is decoded with surrogateescape, so a token holding
    # a non-UTF-8 byte carries U+DC80..U+DCFF, which a strict UTF-8 encode
    # refuses and turns the length check into a traceback at startup.
    # ``os.fsencode`` is its exact inverse.  Valid UTF-8 text is unchanged.
    if len(os.fsencode(token)) < MIN_TOKEN_BYTES:
        typer.secho(
            f"Error: {TOKEN_ENV} must hold at least {MIN_TOKEN_BYTES} bytes",
            fg=typer.colors.RED,
            err=True,
        )
        raise typer.Exit(EXIT_ERROR)
    if workspace is None:
        typer.secho(
            "Error: serve needs --workspace (or RECOVERAGE_OPS_WORKSPACE)",
            fg=typer.colors.RED,
            err=True,
        )
        raise typer.Exit(EXIT_ERROR)
    worker = WorkerConfig(
        workspace=_existing_dir(workspace, "--workspace"),
        filestore=_existing_dir(filestore, "--filestore"),
    )
    hosts = frozenset(item.strip().lower() for item in allowed_hosts.split(",") if item.strip())
    if any(not _ALLOWED_HOST.fullmatch(item) for item in hosts):
        typer.secho(
            "Error: --allowed-hosts must contain exact DNS names and optional ports",
            fg=typer.colors.RED,
            err=True,
        )
        raise typer.Exit(EXIT_ERROR)

    def answer(config: rebrew_ops.WorkerConfig, name: str, body: bytes) -> tuple[int, bytes]:
        return dispatch(worker, name, body)

    # rebrew's handler calls its module-level dispatch for every POST; this process serves only
    # recoverage's ops, so the name is rebound to ours.
    rebrew_ops.dispatch = answer
    server = rebrew_ops.OpsServer(
        (host, resolved_port),
        rebrew_ops.WorkerConfig(worker.filestore, worker.workspace),
        token,
        resolved_concurrency,
        hosts,
    )
    typer.echo(f"serving recoverage ops on http://{host}:{server.server_port}")

    def stop(_signum: int, _frame: object) -> None:
        with server.idle:
            if server.draining:
                return
            server.draining = True
        threading.Thread(target=server.shutdown, daemon=True).start()

    # SIGTERM on POSIX, SIGBREAK on Windows (the Windows arm in
    # cli._stop_on_sigterm): a handler for a signal the platform cannot
    # deliver would leave the graceful drain unreachable there.
    _names = [name for name in ("SIGTERM", "SIGBREAK") if hasattr(signal, name)]
    _previous = {getattr(signal, name): signal.getsignal(getattr(signal, name)) for name in _names}
    for _signum in _previous:
        signal.signal(_signum, stop)
    try:
        server.serve_forever()
    finally:
        server.server_close()
        with server.idle:
            server.draining = True
            drained = server.idle.wait_for(lambda: server.active == 0, timeout=30)
            if not drained:
                _log.warning(
                    "Ops server shutdown: %d request(s) still active after 30s drain timeout",
                    server.active,
                )
        for _signum, _handler in _previous.items():
            signal.signal(_signum, _handler)
