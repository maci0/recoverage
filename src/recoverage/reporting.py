"""The coverage report in every spelling the CLI and the ops print.

``recoverage stats``, ``recoverage export``, ``recoverage check`` and the
``recoverage.coverage_*`` ops the backend dispatches are one report: the same
rows in the same order, the same escaping, the same verdict rule.  This module
holds that shape once.  It reads no file, no environment and no stream; it
takes the per-target statistics :func:`recoverage.server._section_stats`
returns and gives back rows, text or a verdict.

The table itself stays in ``cli`` because it is Rich markup, but it fills its
cells from :func:`section_row`, so a column added here reaches all four
surfaces instead of three.
"""

from __future__ import annotations

import json
import os
from collections.abc import Iterable, Iterator, Mapping
from dataclasses import dataclass
from typing import Any
lazy import csv
lazy import io

from rebrew.utils import floor_pct

lazy from recoverage.server import pct_1dp

#: Per-section values the table, CSV and Markdown renders all print, in the
#: order they print them.  ONE list: `stats`, `export --format csv` and
#: `export --format md` are the same table in three spellings, and a key added
#: to one and forgotten in another renders a header and a body that disagree.
#: The table and the Markdown export head the verdict columns with the tokens
#: the dashboard prints (EXACT, RELOC, NEAR, STUB); the CSV keeps the JSON
#: keys, which are what a script joins on.  Every format lists the sections in
#: the order the coverage document does, which is the load order rebrew writes
#: and the order the dashboard's tabs follow, not alphabetical (which put .bss
#: first and the section carrying the work last).
SECTION_COLUMNS: tuple[str, ...] = (
    "size_bytes",
    "total_cells",
    "exact",
    "reloc",
    "near_match",
    "stub",
    "coverage_pct",
)

#: The CSV header: the per-target key, then the columns above.
CSV_HEADER: tuple[str, ...] = ("target", "section", *SECTION_COLUMNS)

#: The formats ``recoverage export`` and the export op accept, and the media
#: type each body is written as.
EXPORT_FORMATS: tuple[str, ...] = ("json", "csv", "md")
CONTENT_TYPES: Mapping[str, str] = {
    "json": "application/json",
    "csv": "text/csv; charset=utf-8",
    "md": "text/markdown; charset=utf-8",
}

#: Leading characters spreadsheets (Excel, LibreOffice) interpret as formulas
#: or control sequences when a CSV cell starts with them.
_CSV_FORMULA_PREFIXES = ("=", "+", "-", "@", "\t", "\r")

#: Line terminators a Markdown reader breaks on and `str.splitlines` splits on,
#: beyond the CR and LF the table's own rows are made of.  A section name or
#: target id carrying U+2028 or U+2029 came from a PE image, so it is a value a
#: hostile sample plants, and it turns one table row into two: the export
#: renders ragged and the row after it reads as a section that does not exist.
#: Folding them to a space is what the CR/LF arms already do, and it keeps the
#: value recognisable, which an escape sequence would not.
_MD_LINE_BREAKS = str.maketrans(
    {
        "\r": " ",
        "\n": " ",
        "\u2028": " ",
        "\u2029": " ",
    }
)

#: The one character a pipe inside a table cell ends, and the escape the export
#: writes in its place (GFM's own spelling, so the file stays readable).
_MD_PIPE = "\\|"

#: Markdown header and separator.  Figures right-aligned, the way the table
#: prints them, and the same column count as :data:`SECTION_COLUMNS` or the
#: table renders ragged.
_MD_HEADER = "| Section | Size | Cells | EXACT | RELOC | NEAR | STUB | Coverage |"
_MD_SEPARATOR = "|---------|-----:|------:|------:|------:|-----:|-----:|---------:|"


def section_row(sec: Mapping[str, Any]) -> list[Any]:
    """One section's :data:`SECTION_COLUMNS` values, in that order.

    ``.get(..., 0)`` for every key, not a mix: a NULL section size is
    schema-legal (.bss carries one) and reaches the report as 0 from
    ``_section_stats``, so a missing key and a zero-sized section read the
    same in every format.
    """
    return [sec.get(field, 0) for field in SECTION_COLUMNS]


def csv_safe(value: Any) -> Any:
    """Neutralize spreadsheet formula injection (CWE-1236) in exported cells.

    Target ids and section names originate in analyzed PE binaries, so a
    malicious sample can plant a section named ``=HYPERLINK(...)`` or
    ``@SUM(...)`` that Excel executes when the exported file is opened.
    Prefixing with an apostrophe forces text interpretation (the standard
    OWASP mitigation); a non-string cell (the numbers the rows carry) passes
    through untouched.  A string that merely looks numeric is prefixed like any
    other, because ``-`` and ``+`` are formula prefixes too.
    """
    if isinstance(value, str) and value.startswith(_CSV_FORMULA_PREFIXES):
        return f"'{value}"
    return value


def csv_row(target: str, section: str, sec: Mapping[str, Any]) -> list[Any]:
    """One CSV row: the target, the section, then its :func:`section_row`."""
    return [csv_safe(target), csv_safe(section), *section_row(sec)]


def md_safe(value: str) -> str:
    """*value* as one Markdown table cell: pipes escaped, line breaks folded."""
    return value.replace("|", _MD_PIPE).translate(_MD_LINE_BREAKS)


def markdown_lines(stats: Iterable[Mapping[str, Any]]) -> Iterator[str]:
    """The Markdown table, target by target, one line per row.

    Blank line between targets, never before the first one, so a redirected
    file does not start with an empty line.
    """
    for index, data in enumerate(stats):
        if index:
            yield ""
        yield f"## {md_safe(data['target'])}\n"
        yield _MD_HEADER
        yield _MD_SEPARATOR
        for sec_name, sec in data["sections"].items():
            size, cells, exact, reloc, near_match, stub, coverage_pct = section_row(sec)
            yield (
                f"| {md_safe(sec_name)}"
                f" | {size:,} B | {cells:,}"
                f" | {exact:,} | {reloc:,} | {near_match:,}"
                f" | {stub:,} | {pct_1dp(coverage_pct):.1f}% |"
            )


def markdown_text(stats: Iterable[Mapping[str, Any]]) -> str:
    """The whole Markdown document, ending in one newline per line."""
    lines = list(markdown_lines(stats))
    return "".join(line + "\n" for line in lines)


def csv_text(stats: Iterable[Mapping[str, Any]]) -> str:
    """The whole CSV document, rows ending in the platform's line ending.

    ``os.linesep`` for the same reason the CLI stream switches stdout's
    newline translation off: a line break inside a quoted cell is then written
    exactly once, and the row ending is the platform's native one.
    """
    buffer = io.StringIO(newline="")
    writer = csv.writer(buffer, lineterminator=os.linesep)
    writer.writerow(CSV_HEADER)
    for data in stats:
        for sec_name, sec in data["sections"].items():
            writer.writerow(csv_row(data["target"], sec_name, sec))
    return buffer.getvalue()


def json_text(stats: Iterable[Mapping[str, Any]]) -> str:
    """The JSON export body: the items envelope a piped ``export`` writes."""
    items = list(stats)
    return json.dumps({"items": items, "total": len(items)}, separators=(",", ":")) + "\n"


def render_export(output_format: str, stats: Iterable[Mapping[str, Any]]) -> str:
    """*stats* rendered in *output_format*: the body a redirected export writes."""
    items = list(stats)
    if output_format == "json":
        return json_text(items)
    if output_format == "csv":
        return csv_text(items)
    if output_format == "md":
        return markdown_text(items)
    raise ValueError(f"unknown export format: {output_format}")


@dataclass(frozen=True)
class Verdict:
    """One section's gate outcome: the document row and the human line."""

    target: str
    section: str
    status: str
    extras: Mapping[str, Any]
    human: str

    def document(self) -> dict[str, Any]:
        """The JSON object ``check --json`` lists under ``results``."""
        return {
            "target": self.target,
            "section": self.section,
            "status": self.status,
            **self.extras,
        }


@dataclass(frozen=True)
class GateOutcome:
    """Every verdict of one gate run, and why it passed or did not.

    *reason* is set when nothing could be compared, which is a failure the
    caller reports rather than a verdict; *passed* is false then.
    """

    passed: bool
    min_coverage: float
    verdicts: tuple[Verdict, ...]
    checked: int
    compared: int
    skipped_targets: tuple[str, ...]
    reason: str | None

    def document(self) -> dict[str, Any]:
        """The JSON object ``check --json`` prints."""
        return {
            "passed": self.passed,
            "min_coverage": self.min_coverage,
            "results": [verdict.document() for verdict in self.verdicts],
        }


def section_verdict(
    pct: float,
    untracked: bool,
    section_requested: bool,
    min_coverage: float,
    *,
    target: str,
    section: str,
) -> Verdict:
    """Classify one section against the gate.

    *pct* is the UNROUNDED coverage percentage — callers recompute it from
    the raw covered/total byte counts, because the gate must decide on the
    true ratio: comparing the 2dp display value _section_stats stores lets
    99.9997% pass a --min-coverage 100 gate.  The quoted value is the same
    floored-to-2dp percentage /stats serves (server.coverage_pct), so a
    verdict never quotes a number the dashboard does not, and a FAIL line
    cannot read "coverage 100.00% < 100.00%".

    Sections whose cells are all "none" carry no coverage signal — the grid
    only records match states in .text — so they must not fail the gate.
    An explicitly requested untracked section still fails: the user asked to
    gate something that is not being recorded.
    """
    if untracked and section_requested:
        return Verdict(
            target,
            section,
            "FAIL",
            {"reason": "no tracked cells; coverage is not recorded for this section"},
            "has no tracked cells; coverage is not recorded for this section",
        )
    if untracked:
        return Verdict(
            target,
            section,
            "SKIP",
            {"reason": "no tracked cells; coverage is not recorded"},
            "has no tracked cells; coverage is not recorded",
        )
    # Compare the unrounded ratio, print it floored to 2dp (see docstring).
    # The /100 denominator cancels the helper's own x100: what matters is that
    # the value is floored, so 99.9997% cannot be quoted as 100.00% beside a
    # FAIL verdict that just compared it against 100.00%.
    shown = floor_pct(pct, 100, 2)
    if pct < min_coverage:
        return Verdict(
            target,
            section,
            "FAIL",
            {"coverage_pct": shown},
            f"coverage {shown:.2f}% < {min_coverage:.2f}%",
        )
    return Verdict(
        target,
        section,
        "PASS",
        {"coverage_pct": shown},
        f"coverage {shown:.2f}% >= {min_coverage:.2f}%",
    )


def gate(
    stats: Iterable[tuple[str, Mapping[str, Any]]],
    *,
    min_coverage: float,
    section: str | None = None,
) -> GateOutcome:
    """Compare each target's sections with *min_coverage*.

    *stats* pairs each target name with the ``_section_stats`` result for it,
    in the order the caller wants the verdicts printed.  A target without
    *section* is listed in ``skipped_targets`` rather than failing: it has
    nothing the user asked to gate.
    """
    failed = False
    checked = 0
    compared = 0
    verdicts: list[Verdict] = []
    skipped: list[str] = []
    for target, data in stats:
        sections = data["sections"]
        if section:
            if section not in sections:
                skipped.append(target)
                continue
            sections = {section: sections[section]}

        for sec_name, sec in sections.items():
            checked += 1
            covered = sec.get("covered_bytes") or 0
            untracked = covered <= 0
            if not untracked:
                compared += 1
            # Gate on the unrounded byte ratio; sec["coverage_pct"] is
            # display-rounded to 2dp (see section_verdict).  total_bytes == 0
            # implies covered == 0 (cell spans are non-negative, so covered <=
            # total), i.e. an untracked section whose verdict never reads pct,
            # so no fallback value can reach a comparison.
            total_bytes = sec.get("total_bytes") or 0
            pct = covered / total_bytes * 100 if total_bytes else 0.0
            verdict = section_verdict(
                pct,
                untracked,
                bool(section),
                min_coverage,
                target=target,
                section=sec_name,
            )
            if verdict.status == "FAIL":
                failed = True
            verdicts.append(verdict)

    reason: str | None = None
    if checked == 0:
        reason = "no sections matched; nothing was checked"
    elif compared == 0 and not failed:
        # Every section was skipped as untracked and nothing failed — a
        # project with no recorded coverage must not pass vacuously.  An
        # explicit --section on an untracked section already produced a FAIL
        # verdict above; that verdict must reach the caller instead of being
        # replaced by this generic error.
        reason = "no tracked sections; nothing was checked"
    return GateOutcome(
        passed=not failed and reason is None,
        min_coverage=min_coverage,
        verdicts=tuple(verdicts),
        checked=checked,
        compared=compared,
        skipped_targets=tuple(skipped),
        reason=reason,
    )
