"""Potato Mode — zero-JS, server-side HTML renderer for the recoverage dashboard.

Generates complete HTML pages using only HTML attributes for styling (no CSS, no JS).
Uses Bottle's SimpleTemplate engine for layout and Pygments for optional syntax
highlighting via inline <font> tags.
"""

from __future__ import annotations

import base64
import contextlib
import functools
import importlib.util
import json
import logging
import re
import sqlite3
import struct
import textwrap
import threading
from collections.abc import Callable, Iterable
from datetime import UTC, datetime
from html import escape as _html_escape
from pathlib import Path
from typing import Any
from urllib.parse import ParseResult, parse_qs, urlparse
from urllib.parse import quote as _url_quote

from bottle import HTTPResponse, SimpleTemplate  # type: ignore[import-untyped]

from recoverage import __version__
from recoverage._paths import _db_path
from recoverage.disasm import HAS_CAPSTONE, get_disassembly
from recoverage.server import (
    CACHE_NO_STORE,
    CACHE_REVALIDATE,
    NOT_DATA_MARKER_SQL,
    _cells_json_rows,
    _compressed,
    _escape_like,
    _etag_or_304,
    _evict_oldest,
    _fn_json_sql,
    _format_hex_dump,
    _global_json_sql,
    _load_dll,
    _load_metadata,
    _lookup_by_va_or_name,
    _newest_mtime_ns,
    _open_db,
    _snapshot_db_mtime,
    _verify_one_select,
    app,
    folded_like_clause,
    like_match,
    request,
    resolve_targets,
    response,
)

_log = logging.getLogger("recoverage")

# --- UI Constants ---
# Every state rebrew's build_db can write to cells.state needs a key here, or
# the grid falls back to COLORS["none"] and paints the cell as an undocumented
# gap.  That fallback is a data-fidelity bug, not a cosmetic one: build_db
# counts 'verified' as an exact match (section_cell_stats folds it into
# exact_count) and covered_bytes covers every state != 'none', so a VERIFIED
# byte shown as "undocumented" contradicts the number printed beside it.  The
# problem states (tooling failures and unclassified annotations) share one
# colour: they are distinguishable from a gap, which is the point, without
# spending nine legend rows on states an operator cannot act on individually.
_COLORS_PROBLEM = "#a855f7"
COLORS = {
    "exact": "#10b981",
    "reloc": "#0ea5e9",
    "near_match": "#f59e0b",
    # Legacy spelling of near_match (rebrew DB_FORMAT.md); same yellow.
    "near_matching": "#f59e0b",
    # Post-verify semantic promotion — bold cyan per rebrew DB_FORMAT.md.
    "proven": "#06b6d4",
    # SIZE_MISMATCH state — yellow per rebrew DB_FORMAT.md.
    "size_mismatch": "#f59e0b",
    "stub": "#ef4444",
    "padding": "#C0C0D4",
    "data": "#8b5cf6",
    "thunk": "#f97316",
    "none": "#3F4958",
    # Data-metadata verdicts.  VERIFIED is a match (build_db counts it as
    # exact); DRIFT and UNCHECKED are not.  One violet for all three problem
    # states, matching the SPA's --other-bg.
    "verified": "#10b981",
    "drift": _COLORS_PROBLEM,
    "unchecked": _COLORS_PROBLEM,
    "compile_error": _COLORS_PROBLEM,
    "extract_error": _COLORS_PROBLEM,
    "invalid_va": _COLORS_PROBLEM,
    "missing_file": _COLORS_PROBLEM,
    "missing_size": _COLORS_PROBLEM,
    "skip": _COLORS_PROBLEM,
    "unknown": _COLORS_PROBLEM,
}
BG_COLOR = "#0f1216"
PANEL_COLOR = "#151a21"
# Empty progress-bar track: --none (white 0.05) composited over PANEL_COLOR.
TRACK_COLOR = "#22272e"
CODE_BG_COLOR = "#0a0d14"  # darker than panel, matches --code-bg rgba(0,0,0,0.26) on #0f1216
BORDER_COLOR = "#1c2a38"  # subtle cyan-tinted dark, matches rgba(6,182,212,0.15) on dark bg
TEXT_COLOR = "#e7edf4"
MUTED_COLOR = "#8b949e"
ACCENT_COLOR = "#06b6d4"
# The four section-heading accents, one per pane kind.  The SPA paints the
# same four from --accent-c-source, --accent-asm, --accent-data, and
# --accent-bytes, so the hexes live in two files; a pane that reads blue in
# one renderer and cyan in the other is drift nobody would notice on a
# screenshot.  TestSectionAccentsMatchSpa pins the two sets together.
ACCENT_C_SOURCE = "#3b82f6"
ACCENT_ASM = "#ef4444"
ACCENT_DATA = "#a855f7"
ACCENT_BYTES = "#10b981"
SANS_FONT = "system-ui, -apple-system, Segoe UI, Roboto, Arial, sans-serif"
MONO_FONT = "SFMono-Regular, Consolas, Liberation Mono, Courier New, monospace"

# Struct format tuples for Data Inspector: (min_bytes, label, struct_format)
_INT_FMTS: list[tuple[int, str, str]] = [
    (1, "int8", "<b"),
    (1, "uint8", "<B"),
    (2, "int16", "<h"),
    (2, "uint16", "<H"),
    (4, "int32", "<i"),
    (4, "uint32", "<I"),
]

TRANSPARENT_GIF = "data:image/gif;base64,R0lGODlhAQABAIAAAAAAAP///yH5BAEAAAAALAAAAAABAAEAAAIBRAA7"

SCANLINE_PNG = (
    "data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAAAEAAAADCAYAAABS3WWC"
    "AAAADElEQVR4nGNgQAYaAAA3AClW0vESAAAAAElFTkSuQmCC"
)


def _svg_uri(svg: str) -> str:
    """Inline an SVG document as a base64 data URI."""
    return "data:image/svg+xml;base64," + base64.b64encode(svg.encode("utf-8")).decode("utf-8")


# Stretched behind the topbar table as its background image.
def _make_topbar_svg() -> str:
    """Generate a 1x80 vertical gradient SVG data URI for the topbar."""
    svg = (
        '<svg xmlns="http://www.w3.org/2000/svg" width="1" height="80">'
        "<defs>"
        '<linearGradient id="grad" x1="0%" y1="0%" x2="0%" y2="100%">'
        f'<stop offset="0%" style="stop-color:{BG_COLOR};stop-opacity:1" />'
        f'<stop offset="100%" style="stop-color:{PANEL_COLOR};stop-opacity:1" />'
        "</linearGradient>"
        "</defs>"
        '<rect width="1" height="80" fill="url(#grad)" />'
        "</svg>"
    )
    return _svg_uri(svg)


TOPBAR_SVG = _make_topbar_svg()

PANEL_HDR_PNG = (
    "data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAAAEAAAAYCAYAAAA7zJfa"
    "AAAAYUlEQVR4nCXEWQJDMABF0buJKhIZRdC5Oux/Zc+H83HI61+k5Sfi/BWxfkSo"
    "m/DTW/jyEq48hRsfYsh3YfNN2HQVJl6ECavowyI6P4vOVdG6SbRDEWc7isZm0Zgk"
    "Tn082gH6xSG4aTtBqgAAAABJRU5ErkJggg=="
)


def _dot_uri(fill_hex: str) -> str:
    """12px rounded-square swatch data URI in *fill_hex*, for legend keys."""
    svg = (
        '<svg xmlns="http://www.w3.org/2000/svg" width="12" height="12">'
        f'<rect x="0.5" y="0.5" width="11" height="11" rx="3" fill="{fill_hex}"'
        f' stroke="{BORDER_COLOR}"/></svg>'
    )
    return _svg_uri(svg)


# Derived from COLORS so a legend key can never drift from the block colour it
# documents (these were six hand-encoded PNG blobs, and the states without one —
# data, thunk — rendered on the grid with nothing in the legend to explain them).
DOT_PNGS = {state: _dot_uri(color) for state, color in COLORS.items()}

# ── Progress bar SVG ────────────────────────────────────────


#: Width of the progress bar's lattice, in viewBox units.  Percentages are
#: scaled against it, and it is the hard right edge: no segment list may draw
#: past it (see _progress_svg).
TRACK_UNITS = 700

#: Height of the bar, in viewBox units.  Only the corner radius's half
#: depends on it.
TRACK_HEIGHT = 32


def _progress_svg(segments: tuple[tuple[str, float], ...]) -> str:
    """SVG (data URI) with one colored segment per (state, pct), rounded corners.

    viewBox-only (no fixed width/height): the <td> renders it at 100% width
    via width="100%", so the bar fills any viewport — a fixed 700px lattice
    overflowed phones and clipped the stats text mid-word.  Segment geometry
    is in 0..TRACK_UNITS viewBox units; the browser scales it to the cell width.

    Deliberately uncached: the segment list is rebuilt per render, and a memo
    keyed on the float percentages would pin entries without ever hitting."""
    svg = [
        (
            f'<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 {TRACK_UNITS} {TRACK_HEIGHT}"'
            ' preserveAspectRatio="none">'
            f'<defs><clipPath id="rc"><rect width="{TRACK_UNITS}" height="{TRACK_HEIGHT}"'
            ' rx="10" ry="10"/></clipPath></defs>'
            f'<rect width="{TRACK_UNITS}" height="{TRACK_HEIGHT}" fill="{TRACK_COLOR}" rx="10" ry="10"/>'
            '<g clip-path="url(#rc)">'
        )
    ]

    # A segment list summing past 100% would otherwise run off the right end
    # of the track, where the rounded-corner clipPath silently eats it: the
    # last band lost its tail instead of the bar growing.  Clamp to the width
    # still free, so the track is the hard bound no input list can pass.
    current_x = 0.0
    for status, pct in segments:
        seg_w = min(TRACK_UNITS * pct / 100.0, TRACK_UNITS - current_x)
        if seg_w <= 0:
            continue
        hex_color = COLORS.get(status, TRACK_COLOR)
        svg.append(
            f'<rect x="{current_x:.2f}" y="0" width="{seg_w:.2f}"'
            f' height="{TRACK_HEIGHT}" fill="{hex_color}"/>'
        )
        current_x += seg_w

    svg.append("</g></svg>")

    return _svg_uri("".join(svg))


def _make_pill_caps(height: int, fill_hex: str, border_hex: str) -> tuple[str, str]:
    """Generate left-cap and right-cap SVG data URIs for a pill shape."""
    radius = height // 2
    r = radius - 0.5
    h1 = height - 0.5
    left_svg = f'<svg xmlns="http://www.w3.org/2000/svg" width="{radius}" height="{height}" viewBox="0 0 {radius} {height}"><path d="M{radius},0.5 A{r},{r} 0 0,0 {radius},{h1}" fill="{fill_hex}" stroke="{border_hex}" stroke-width="1"/></svg>'
    right_svg = f'<svg xmlns="http://www.w3.org/2000/svg" width="{radius}" height="{height}" viewBox="0 0 {radius} {height}"><path d="M0,0.5 A{r},{r} 0 0,1 0,{h1}" fill="{fill_hex}" stroke="{border_hex}" stroke-width="1"/></svg>'

    return _svg_uri(left_svg), _svg_uri(right_svg)


def _make_pill_mid_tile(height: int, fill_hex: str, border_hex: str) -> str:
    """Generate a 1px-wide tile SVG with top/bottom border and fill.
    Used as background for the middle cell of a pill."""
    h1 = height - 1
    svg = f'<svg xmlns="http://www.w3.org/2000/svg" width="1" height="{height}" viewBox="0 0 1 {height}">'
    svg += f'<rect x="0" y="0" width="1" height="{height}" fill="{fill_hex}"/>'
    svg += f'<rect x="0" y="0" width="1" height="1" fill="{border_hex}"/>'
    svg += f'<rect x="0" y="{h1}" width="1" height="1" fill="{border_hex}"/>'
    svg += "</svg>"
    return _svg_uri(svg)


# Pre-compute section tab pill cap images
ACTIVE_L, ACTIVE_R = _make_pill_caps(32, "#1a3a4a", border_hex="#06b6d4")
INACTIVE_L, INACTIVE_R = _make_pill_caps(32, "#182230", border_hex="#2a3a4a")
ACTIVE_MID = _make_pill_mid_tile(32, "#1a3a4a", "#06b6d4")
INACTIVE_MID = _make_pill_mid_tile(32, "#182230", "#2a3a4a")

# Pre-compute filter pill cap images
FILTER_ACT_L, FILTER_ACT_R = _make_pill_caps(32, "#162438", border_hex="#2a6fdb")
FILTER_INACT_L, FILTER_INACT_R = _make_pill_caps(32, "#182230", border_hex="#2a3a4a")
FILTER_ACT_MID = _make_pill_mid_tile(32, "#162438", "#2a6fdb")
FILTER_INACT_MID = _make_pill_mid_tile(32, "#182230", "#2a3a4a")

R_LOGO_SVG = (
    "data:image/svg+xml;base64,"
    "PHN2ZyB4bWxucz0naHR0cDovL3d3dy53My5vcmcvMjAwMC9zdmcnIHZpZXdCb3g9JzAg"
    "MCAxMDAgMTAwJz48ZGVmcz48ZmlsdGVyIGlkPSdnJz48ZmVHYXVzc2lhbkJsdXIgc3Rk"
    "RGV2aWF0aW9uPSczJyByZXN1bHQ9J2InLz48ZmVNZXJnZT48ZmVNZXJnZU5vZGUgaW49"
    "J2InLz48ZmVNZXJnZU5vZGUgaW49J1NvdXJjZUdyYXBoaWMnLz48L2ZlTWVyZ2U+PC9m"
    "aWx0ZXI+PHBhdHRlcm4gaWQ9J3MnIHdpZHRoPSc0JyBoZWlnaHQ9JzQnIHBhdHRlcm5V"
    "bml0cz0ndXNlclNwYWNlT25Vc2UnPjxyZWN0IHdpZHRoPSc0JyBoZWlnaHQ9JzInIGZp"
    "bGw9J3JnYmEoMCwyNTUsMjU1LDAuMiknLz48L3BhdHRlcm4+PC9kZWZzPjxyZWN0IHdp"
    "ZHRoPScxMDAnIGhlaWdodD0nMTAwJyByeD0nMTUnIGZpbGw9JyMwZjEyMTYnLz48cmVj"
    "dCB4PSc4JyB5PSc4JyB3aWR0aD0nODQnIGhlaWdodD0nODQnIHJ4PSc4JyBmaWxsPSd1"
    "cmwoI3MpJyBzdHJva2U9JyMwZmYnIHN0cm9rZS13aWR0aD0nNCcgZmlsdGVyPSd1cmwo"
    "I2cpJy8+PHRleHQgeD0nNTAnIHk9JzcyJyBmb250LWZhbWlseT0nbW9ub3NwYWNlJyBm"
    "b250LXNpemU9JzY1JyBmb250LXdlaWdodD0nYm9sZCcgZmlsbD0nIzBmZicgdGV4dC1h"
    "bmNob3I9J21pZGRsZScgZmlsdGVyPSd1cmwoI2cpJz5SPC90ZXh0Pjwvc3ZnPg=="
)

# One row per colour a reader has to be able to name.  data (purple) and thunk
# (orange) cells used to render with no legend entry, so those blocks had no
# way to be identified; the SPA greys them out, Potato Mode keeps the colours
# (docs/DESIGN.md "Potato Mode still colors those states"), so they get rows.
# `problem` names all nine states sharing _COLORS_PROBLEM at once, and the
# states that share an existing row's colour (near_matching, verified) need no
# entry of their own.  COLORS, not this list, is what must cover every state.
LEGEND_ITEMS = [
    ("none", "undocumented"),
    ("exact", "exact"),
    ("reloc", "reloc"),
    ("near_match", "near-match"),
    ("stub", "stub"),
    ("proven", "proven"),
    ("data", "data"),
    ("thunk", "thunk"),
    ("padding", "padding"),
    ("compile_error", "problem"),
]


# --- HTML Helpers ---


def _hex_logo_svg(label: str, color: str) -> str:
    """Generate a hex-shaped SVG logo as a base64 data-URI image tag."""
    font_size = 26 if len(label) > 2 else 42
    safe_label = _html_escape(label)
    safe_alt = _html_escape(label)
    svg = (
        f'<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 100 100" width="20" height="20">'
        f'<polygon points="50,5 90,27.5 90,72.5 50,95 10,72.5 10,27.5"'
        f' fill="{color}" fill-opacity="0.15" stroke="{color}"'
        f' stroke-width="6" stroke-linejoin="round"/>'
        f'<text x="50" y="54" dominant-baseline="middle" text-anchor="middle"'
        f' fill="{color}" font-family="monospace" font-weight="800"'
        f' font-size="{font_size}">{safe_label}</text></svg>'
    )
    return f'<img src="{_svg_uri(svg)}" width="20" height="20" border="0" alt="{safe_alt}">'


def _section_heading(label: str, color: str, title: str) -> str:
    """Render a section heading with a hex logo + title text.

    ``title`` is escaped here, not by the caller: the heading is built by
    string concatenation into element content, so a caller that forgot the
    escape would emit a DB-sourced section or file name as live markup.
    Callers pass the raw text.
    """
    logo = _hex_logo_svg(label, color)
    return (
        f'<table border="0" cellpadding="0" cellspacing="4"><tr>'
        f'<td valign="middle">{logo}</td>'
        f'<td valign="middle">'
        f'<h2><font size="3">{_esc(title)}</font></h2>'
        f"</td></tr></table><br>"
    )


def _code_block_raw(highlighted_html: str) -> str:
    """Wrap pre-highlighted HTML in a code block table."""
    return (
        f'<table width="100%" border="0" cellpadding="10" cellspacing="1" bgcolor="{BORDER_COLOR}">'
        f'<tr><td bgcolor="{CODE_BG_COLOR}"><font face="{MONO_FONT}" size="2">'
        f"<pre>{highlighted_html}</pre></font></td></tr></table><br>"
    )


def _detail_rows(
    data_dict: dict[str, Any],
    skip_fields: set[str],
    hex_fields: set[str],
    val_fn: Callable[[str, Any, str], str] | None = None,
) -> str:
    """Generate <tr> rows for a key-value detail table, skipping absent values."""
    rows: list[str] = []
    for k, v in data_dict.items():
        if k in skip_fields:
            continue
        # NULL/empty cells are noise, not information: a test DB function
        # carries ~8 of them (ghidra_name, similarity, size_reason...), which
        # buried the rows that name the function.  The SPA panel renders the
        # same fields conditionally, so both surfaces omit the same absence.
        if v is None or v == "" or v == [] or v == {}:
            continue
        if k in hex_fields:
            val = _esc(_format_va(v))
        else:
            sv = str(v)
            val = _esc(_wrap_text(sv, 40)) if len(sv) > 40 else _esc(sv)
        if val_fn:
            val = val_fn(k, v, val)
        rows.append(
            f'<tr><th bgcolor="{PANEL_COLOR}" width="28%">'
            f'<font size="1" color="{MUTED_COLOR}"><b>{_esc(k)}</b></font></th>'
            f'<td bgcolor="{PANEL_COLOR}">'
            f'<font face="Courier New, monospace" size="1">{val}</font></td></tr>'
        )
    return "".join(rows)


# --- Pygments Highlighting ---


def _highlight_tokens(tokens: Iterable[tuple[Any, str]], color_map: dict[Any, str]) -> str:
    """Convert Pygments (token_type, value) pairs to <font color> HTML."""
    parts: list[str] = []
    for ttype, value in tokens:
        escaped = _html_escape(value)
        tt = ttype
        color = None
        while tt:
            if tt in color_map:
                color = color_map[tt]
                break
            tt = getattr(tt, "parent", None)
        if color:
            parts.append(f'<font color="{color}">{escaped}</font>')
        else:
            parts.append(escaped)
    return "".join(parts)


@functools.lru_cache(maxsize=1)
def _pygments() -> tuple[Any, dict[Any, str], Any, dict[Any, str]] | None:
    """(CLexer, c_colors, NasmLexer, asm_colors), or None when unavailable.

    ONE lazy loader for the optional pygments stack: the availability probe,
    both lexers, and both color maps share one import gate and one lifetime,
    so they share one cache.
    """
    # find_spec imports only the parent package; a missing pygments raises
    # ModuleNotFoundError, an ImportError, which the guard below catches.
    try:
        if importlib.util.find_spec("pygments.lexers") is None:
            return None
    except ImportError:
        return None
    from pygments.lexers import CLexer, NasmLexer  # type: ignore[import-untyped]
    from pygments.token import (  # type: ignore[import-untyped]
        Comment,
        Keyword,
        Name,
        Number,
        Operator,
        Punctuation,
        String,
    )

    base = {
        Comment: "#6a9955",
        Keyword: "#569cd6",
        Keyword.Type: "#4ec9b0",
        String: "#ce9178",
        Operator: "#d4d4d4",
        Punctuation: "#d4d4d4",
    }
    c_colors = {
        **base,
        Comment.Preproc: "#c586c0",
        Number: "#b5cea8",
        Name.Function: "#dcdcaa",
    }
    asm_colors = {
        **base,
        Name.Builtin: "#dcdcaa",
        Name.Function: "#dcdcaa",
        Name.Label: "#9cdcfe",
        Name.Variable: "#9cdcfe",
        Number: "#b5cea8",
        Number.Hex: "#b5cea8",
        Number.Integer: "#b5cea8",
    }
    return CLexer(), c_colors, NasmLexer(), asm_colors


_HEX_ADDR_RE = re.compile(r"0x[0-9a-f]{8}")


def _split_asm_line(line: str) -> tuple[str, str] | None:
    """(addr, code) for disassembly lines shaped ``0xADDR  MNEMONIC``, else None."""
    if line.startswith("0x") and "  " in line:
        addr_end = line.index("  ")
        return line[:addr_end], line[addr_end:]
    return None


def _highlight_c(code: str) -> str:
    """Syntax-highlight C code using Pygments tokens and <font> tags (no CSS)."""
    pg = _pygments()
    if pg is None:
        return _html_escape(code)
    c_lexer, c_colors, _, _ = pg
    return _highlight_tokens(c_lexer.get_tokens(code), c_colors)


def _highlight_asm(text: str, target: str) -> str:
    """Syntax-highlight x86 assembly using Pygments tokens and <font> tags (no CSS).

    Addresses and bare hex references become search links into *target*'s grid.
    """

    def _addr_link(addr: str) -> str:
        return (
            f'<a href="?target={_url_quote(target)}&search={_url_quote(addr.strip())}">'
            f'<font color="#858585">{_html_escape(addr)}</font></a>'
        )

    def _link_hex_refs(html: str) -> str:
        return _HEX_ADDR_RE.sub(
            lambda m: (
                f'<a href="?target={_url_quote(target)}&search={_url_quote(m.group(0))}">'
                f"{m.group(0)}</a>"
            ),
            html,
        )

    def _plain_line(line: str) -> str:
        return _link_hex_refs(_html_escape(line))

    pg = _pygments()
    if pg is None:
        # Same body as _plain_line, bound late so the else branch can rebind it.
        _render_code = lambda code: _link_hex_refs(_html_escape(code))  # noqa: E731 — late bind
    else:
        _, _, lexer, colors = pg

        def _render_code(code: str) -> str:
            return _link_hex_refs(_highlight_tokens(lexer.get_tokens(code), colors).rstrip("\n"))

    # One loop for both: only the code half's rendering differs between the
    # pygments and no-pygments paths, and the address half is identical.
    result_lines: list[str] = []
    for line in text.splitlines():
        split = _split_asm_line(line)
        if split is None:
            result_lines.append(_plain_line(line))
        else:
            addr_part, code_part = split
            result_lines.append(_addr_link(addr_part) + _render_code(code_part))
    return "\n".join(result_lines)


def _highlight_hex(text: str) -> str:
    """Syntax-highlight hex dump using <font> tags (no CSS)."""
    result_lines: list[str] = []
    for line in text.splitlines():
        if len(line) >= 10 and line[8:10] == "  " and "|" in line:
            offset = line[:8]
            rest = line[8:]
            pipe_start = rest.rfind("  |")
            if pipe_start >= 0:
                hex_part = rest[: pipe_start + 2]
                ascii_part = rest[pipe_start + 2 :]
                out = f'<font color="#858585">{_html_escape(offset)}</font>'
                out += f'<font color="#4ec9b0">{_html_escape(hex_part)}</font>'
                out += '<font color="#858585">|</font>'
                inner = ascii_part[1:-1] if len(ascii_part) >= 2 else ascii_part
                ascii_pieces: list[str] = []
                for ch in inner:
                    if ch == ".":
                        ascii_pieces.append('<font color="#858585">.</font>')
                    else:
                        ascii_pieces.append(f'<font color="#6a9955">{_html_escape(ch)}</font>')
                out += "".join(ascii_pieces)
                out += '<font color="#858585">|</font>'
                result_lines.append(out)
            else:
                result_lines.append(_html_escape(line))
        elif line.startswith("... ("):
            result_lines.append(f'<font color="#858585">{_html_escape(line)}</font>')
        else:
            result_lines.append(_html_escape(line))
    return "\n".join(result_lines)


# --- Data Helpers ---


def _wrap_text(text: str, width: int = 45) -> str:
    """Hard-wrap text to a specific width for HTML display."""
    lines: list[str] = []
    for line in text.splitlines():
        if len(line) > width:
            lines.extend(
                textwrap.wrap(line, width, break_long_words=True, replace_whitespace=False)
            )
        else:
            lines.append(line)
    return "\n".join(lines)


def _esc(text: object) -> str:
    """HTML-escape text for safe rendering."""
    return _html_escape(str(text))


_MAX_RAW_READ = 1 << 20  # 1 MiB — more than any plausible function or data cell

# Sort key standing in for a section row with no VA, so sections without one
# land after every real address. Above the 64-bit VA ceiling, and an int so the
# key list stays one comparable type.
_SECTION_VA_MAX = 1 << 64


def _get_raw_bytes(file_offset: int, size: int, target: str) -> bytes | None:
    """Read raw bytes from the target DLL using the shared DLL cache."""
    size = min(size, _MAX_RAW_READ)
    dll_data = _load_dll(target)
    if dll_data is None:
        return None
    end = file_offset + size
    if file_offset < 0 or end > len(dll_data):
        return None
    return dll_data[file_offset:end]


def _extract_annotations(code: str) -> list[tuple[str, str]]:
    """Extract annotation comments (NOTE, BLOCKER, SOURCE) from C source."""
    annotations: list[tuple[str, str]] = []
    for line in code.splitlines():
        line = line.strip()
        for tag in ("NOTE", "BLOCKER", "SOURCE"):
            prefix = f"// {tag}:"
            if line.startswith(prefix):
                text = line[len(prefix) :].strip()
                annotations.append((tag, text))
    return annotations


def _format_data_inspector(raw_bytes: bytes | None) -> str:
    """Format raw bytes as a Data Inspector table (like the main UI)."""
    if not raw_bytes:
        return ""

    parts: list[str] = []
    parts.append(
        _section_heading("{}", ACCENT_DATA, "Data Inspector")
        + f'<table width="100%" border="0" cellpadding="3" cellspacing="1"'
        f' bgcolor="{BORDER_COLOR}">'
    )

    def _row(label: str, value: object) -> None:
        parts.append(
            f'<tr><th bgcolor="{PANEL_COLOR}" width="35%">'
            f'<font size="1" color="{MUTED_COLOR}"><b>{_esc(label)}</b></font></th>'
            f'<td bgcolor="{PANEL_COLOR}">'
            f'<font face="Courier New, monospace" size="1">{_esc(value)}</font></td></tr>'
        )

    b = raw_bytes
    for min_len, label, fmt in _INT_FMTS:
        if len(b) >= min_len:
            _row(label, str(struct.unpack_from(fmt, b)[0]))
    if len(b) >= 4:
        _row("float32", f"{struct.unpack_from('<f', b)[0]:.6g}")
    if len(b) >= 8:
        _row("float64", f"{struct.unpack_from('<d', b)[0]:.6g}")

    null_terminated = b[:64].split(b"\x00")[0]
    ascii_str = "".join(chr(x) if 32 <= x < 127 else "." for x in null_terminated)
    if ascii_str:
        display = ascii_str if len(ascii_str) <= 40 else ascii_str[:37] + "..."
        _row("string (ascii)", display)

    parts.append("</table><br>")
    return "".join(parts)


def _cell_file_offset(cell: dict[str, Any], sec_data: dict[str, Any] | None) -> int | None:
    """Calculate file offset for a cell from its section metadata."""
    if not sec_data:
        return None
    sec_file_offset = sec_data.get("fileOffset")
    if not sec_file_offset:
        return None
    return int(sec_file_offset) + cell.get("start", 0)


def _format_va(val: int | str) -> str:
    """Format a VA value as hex string."""
    if isinstance(val, int):
        return f"0x{val:08x}"
    s = str(val)
    if s.startswith(("0x", "0X")):
        return s
    try:
        return f"0x{int(s):08x}"
    except ValueError:
        return s


def _build_url(
    target: str,
    section: str,
    filters: set[str] | None = None,
    idx: int | None = None,
    search: str | None = None,
    page: int | None = None,
) -> str:
    """Build the relative "?target=...&section=..." URL.

    Options that are ``None``, an empty set, or an empty string are omitted.
    ``idx`` is the exception: it is emitted whenever it is not ``None``, so
    cell index 0 keeps its ``&idx=0`` and the reader's position survives the
    round trip.
    """
    url = "?target=" + _url_quote(target) + "&section=" + _url_quote(section)
    if filters:
        url += "&filter=" + _url_quote(",".join(sorted(filters)))
    if idx is not None:
        url += "&idx=" + str(idx)
    if search:
        url += "&search=" + _url_quote(search)
    if page:
        url += "&page=" + str(page)
    return url


# ── SimpleTemplate: Page Layout ─────────────────────────────────────

_PAGE_SRC = r"""<!DOCTYPE html>
<html lang="en">
<head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1"><title>ReCoverage - Potato Mode</title><link rel="icon" href="data:image/svg+xml,%3Csvg%20xmlns%3D%27http%3A%2F%2Fwww.w3.org%2F2000%2Fsvg%27%20viewBox%3D%270%200%20100%20100%27%3E%3Ctext%20y%3D%27.9em%27%20font-size%3D%2790%27%3E%F0%9F%A5%94%3C%2Ftext%3E%3C%2Fsvg%3E"></head>
<body bgcolor="{{BG_COLOR}}" text="{{TEXT_COLOR}}" background="{{SCANLINE_PNG}}" link="{{COLORS['reloc']}}" vlink="{{COLORS['reloc']}}" alink="{{COLORS['exact']}}">
<font face="{{SANS_FONT}}">
<a href="#grid-container"><font size="1" color="{{MUTED_COLOR}}">[Skip to grid]</font></a>
<main>
<!-- Page wrapper: the grid is a fixed-width lattice (grid_columns x cell_w), so
     on a narrow viewport it is wider than the window.  Without this wrapper the
     width="100%" chrome below (topbar, divider, layout, footer) resolves against
     the VIEWPORT while the grid pushes the document wider, leaving the header
     and footer visibly cut off mid-page with an unpainted band beside them.  A
     shrink-to-fit outer cell makes those percentages resolve against the content
     width instead, so the chrome spans the whole scrollable page. -->
<table id="page" width="100%" border="0" cellpadding="0" cellspacing="0"><tr><td>

<!-- Top Bar -->
<table id="topbar" width="100%" border="0" cellpadding="4" cellspacing="0" background="{{TOPBAR_PNG}}">
  <tr>
    <td valign="middle">
      <table id="logo" border="0" cellpadding="0" cellspacing="0">
        <tr>
          <td><img src="{{R_LOGO_SVG}}" width="48" height="32" border="0" alt="R"></td>
          <td valign="middle" nowrap><h1><a href="/"><font face="{{MONO_FONT}}" size="5" color="{{TEXT_COLOR}}">&nbsp;<b>ReCoverage</b></font></a></h1>&nbsp;<a href="/"><font face="{{MONO_FONT}}" size="1" color="{{MUTED_COLOR}}">[SPA]</font></a>&nbsp;<a href="{{functions_nav_url}}"><font face="{{MONO_FONT}}" size="1" color="{{MUTED_COLOR}}">[Functions]</font></a></td>
        </tr>
      </table>
    </td>
    <td valign="middle" width="100%">
      <table id="section-tabs" border="0" cellpadding="0" cellspacing="4"><tr>
      % for s_name, s_url, s_active, s_key in section_tab_data:
        <td valign="middle">
        <!-- The <a> wraps the whole pill table, not just the label.  Wrapping
             only the text made the clickable area the ~20px glyph while the
             32px pill around it looked like the button and did nothing. -->
        % if s_active:
          <a href="{{s_url}}" accesskey="{{s_key}}"><table border="0" cellpadding="0" cellspacing="0"><tr><td><img src="{{ACTIVE_L}}" width="16" height="32" border="0" alt=""></td><td background="{{ACTIVE_MID}}" height="32" nowrap><font face="{{MONO_FONT}}" size="3" color="#ffffff"><b>{{s_name}}</b></font></td><td><img src="{{ACTIVE_R}}" width="16" height="32" border="0" alt=""></td></tr></table></a>
        % else:
          <a href="{{s_url}}" accesskey="{{s_key}}"><table border="0" cellpadding="0" cellspacing="0"><tr><td><img src="{{INACTIVE_L}}" width="16" height="32" border="0" alt=""></td><td background="{{INACTIVE_MID}}" height="32" nowrap><font face="{{MONO_FONT}}" size="3" color="{{MUTED_COLOR}}">{{s_name}}</font></td><td><img src="{{INACTIVE_R}}" width="16" height="32" border="0" alt=""></td></tr></table></a>
        % end
        </td>
      % end
      </tr></table>
    </td>
  </tr>
  <tr>
    <td valign="middle" colspan="2">
      <table id="controls" border="0" cellpadding="0" cellspacing="2" width="100%">
        % if progress:
        <tr><td colspan="4" valign="middle" width="100%" align="center">
          <!-- Fluid bar: the SVG is viewBox-only, so width="100%" stretches
               it to the cell on any viewport instead of overflowing a phone
               with a fixed 700px lattice.  The stats sit in a second cell
               below the bar (same contract as the SPA's stats row): overlaying
               them on the image clipped mid-word on narrow screens, because
               the text width is fixed while the image shrinks. -->
          <table id="progress-bar" width="100%" border="0" cellpadding="0" cellspacing="1"><tr>
            <td align="center" height="14"><img src="{{progress_bar_png}}" width="100%" height="14" border="0" alt=""></td>
          </tr><tr>
            <td align="center"><font face="{{MONO_FONT}}" size="2" color="{{TEXT_COLOR}}"><b>{{progress['sec_size']}}</b>b &middot; <b>{{progress['matched_fn']}}/{{progress['total_fn']}}</b> matched &middot; <b>{{"%.1f" % progress['coverage_pct']}}%</b></font></td>
          </tr></table>
        </td></tr>
        % end
        <!-- Search and target share the first row; the filter pills take
             their own second row.  As one row the three groups need ~1000px,
             which overflowed a 390px phone and clipped the filters (E/R/M/S/P
             half off-screen).  Two rows wrap at whatever width the viewport
             gives them. -->
        <tr>
        <td valign="middle" nowrap>
          <form id="search-form" action="/potato" method="GET"><input type="hidden" name="target" value="{{target}}"><input type="hidden" name="section" value="{{section}}">
          % if active_filters:
            <input type="hidden" name="filter" value="{{','.join(sorted(active_filters))}}">
          % end
          <label for="search-input"><font size="1" color="{{MUTED_COLOR}}">Search:&nbsp;</font></label><input id="search-input" type="text" name="search" size="14" value="{{search_query}}" placeholder="Search VA or name..." accesskey="s"> <input type="submit" value="Go"></form>
        </td>
        <!-- Spacer cells, not &nbsp; text: <form> is a block box, so a leading
             text node in the same cell pushed the form onto its own line and
             left the Search and Target groups on staggered baselines. -->
        <td width="16"></td>
        <td valign="middle" nowrap>
          <form id="target-form" action="/potato" method="GET">
            <input type="hidden" name="section" value="{{section}}">
            <label for="target-select"><font size="1" color="{{MUTED_COLOR}}">Target:&nbsp;</font></label><select id="target-select" name="target">
            % for t in targets:
              <option value="{{t['id']}}" {{"selected" if t['id'] == target else ""}}>{{t['name']}}</option>
            % end
            </select>
            <input type="submit" value="Go">
          </form>
        </td>
        <td valign="middle" width="100%"></td>
        </tr>
        <tr>
        <td valign="middle" colspan="4">
          <table id="filters" border="0" cellpadding="0" cellspacing="4"><tr>
            % for fb_href, fb_label, fb_color, fb_active, fb_key in filter_btn_data:
              <td valign="middle">
              <!-- Anchor wraps the whole pill: see the section-tab note above.
                   These are the worst case — a single-letter label gave E/R/M/S/P
                   a 10px-wide hit target inside a 32px-wide pill. -->
              % if fb_active:
                <a href="{{fb_href}}" accesskey="{{fb_label[0].lower()}}"><table border="0" cellpadding="0" cellspacing="0"><tr><td><img src="{{FILTER_ACT_L}}" width="16" height="32" border="0" alt=""></td><td background="{{FILTER_ACT_MID}}" height="32" nowrap><font face="{{MONO_FONT}}" size="3" color="{{fb_color}}"><b>{{fb_label}}</b></font></td><td><img src="{{FILTER_ACT_R}}" width="16" height="32" border="0" alt=""></td></tr></table></a>
              % else:
                <a href="{{fb_href}}" accesskey="{{fb_label[0].lower()}}"><table border="0" cellpadding="0" cellspacing="0"><tr><td><img src="{{FILTER_INACT_L}}" width="16" height="32" border="0" alt=""></td><td background="{{FILTER_INACT_MID}}" height="32" nowrap><font face="{{MONO_FONT}}" size="3" color="{{fb_color}}">{{fb_label}}</font></td><td><img src="{{FILTER_INACT_R}}" width="16" height="32" border="0" alt=""></td></tr></table></a>
              % end
              </td>
            % end
          </tr></table>
        </td>
        </tr>
        % if search_query:
        <tr><td colspan="4" valign="middle" nowrap><font size="1" color="{{ACCENT_COLOR}}">Searching: &quot;{{search_query}}&quot; ({{search_match_count}} matches)</font>
        % if search_match_count == 0:
        <font size="1" color="{{MUTED_COLOR}}"> - no matches. Check the spelling, or search by VA.</font>
        % end
        <a href="{{clear_search_url}}"><font size="1" color="{{MUTED_COLOR}}">[Clear search]</font></a></td></tr>
        % end
        </table>
    </td>
  </tr>
</table>
<table id="topbar-divider" width="100%" border="0" cellpadding="0" cellspacing="0" bgcolor="#1c2a38"><tr><td height="1"></td></tr></table>

<table id="layout" width="100%" border="0" cellpadding="14" cellspacing="0">
  <!-- Map and panel stack as separate rows.  As side-by-side cells the
       fixed-width grid lattice plus the panel's width floor forced the page
       past 500px on a 390px phone, clipping both.  Stacked, each takes the
       full width; the panel follows the map like the SPA below 1300px. -->
  % if view == "functions":
  <tr>
    <td valign="top" width="100%">
      {{!functions_html}}
    </td>
  </tr>
    % else:
  <tr>
    <td valign="top" width="100%">
      <table id="map" width="100%" border="1" cellpadding="0" cellspacing="0" bgcolor="{{PANEL_COLOR}}" bordercolor="{{BORDER_COLOR}}">        <tr><td id="map-header" background="{{PANEL_HDR_PNG}}" cellpadding="8">&nbsp;<font color="{{MUTED_COLOR}}" size="2"><b>Coverage Map - {{section}}</b></font> <font color="{{MUTED_COLOR}}" size="1"> ({{block_count}} blocks)</font>
        % if sec_stats.get('total', 0) > 0:
          <br>&nbsp;<font face="{{MONO_FONT}}" size="1" color="{{MUTED_COLOR}}">E:<font color="{{COLORS['exact']}}">{{sec_stats['exact']}}</font> R:<font color="{{COLORS['reloc']}}">{{sec_stats['reloc']}}</font> M:<font color="{{COLORS['near_match']}}">{{sec_stats['near_match']}}</font> S:<font color="{{COLORS['stub']}}">{{sec_stats['stub']}}</font> P:<font color="{{COLORS['padding']}}">{{sec_stats.get('padding', 0)}}</font> &#x2502; {{sec_stats['pct']}}% covered</font>
        % end
        </td></tr>
        <tr><td bgcolor="{{PANEL_COLOR}}" cellpadding="8">
          <!-- Two keys per row in a fixed 2-column lattice: nine keys as a
               single row need ~900px, which overflowed the map cell on phones
               and wrapped mid-key ("near- / match") once it could wrap.
               One key per row fixed the wrap but cost ~200px of vertical
               space for a legend.  Fixed pairs fit a 390px phone (each pair
               is ~260px) and cost half the height. -->
          <table id="legend" border="0" cellpadding="0" cellspacing="2">
          % for i in range(0, len(LEGEND_ITEMS), 2):
            <tr>
            % for leg_key, leg_label in LEGEND_ITEMS[i:i+2]:
              <td valign="middle"><img src="{{DOT_PNGS[leg_key]}}" width="12" height="12" border="0" alt=""></td><td valign="middle" nowrap><font face="{{MONO_FONT}}" size="1" color="{{MUTED_COLOR}}">{{leg_label}}&nbsp;&nbsp;</font></td>
            % end
            </tr>
          % end
          </table>
          <table id="grid-container" border="1" cellpadding="8" cellspacing="0" bordercolor="{{BORDER_COLOR}}" bgcolor="{{BG_COLOR}}" width="100%">
          <!-- Labels the grid for the "[Skip to grid]" target, which lands here.
               It deliberately does NOT repeat the panel header directly above
               ("Coverage Map - {{section}} ({{block_count}} blocks)") — rendered
               back to back, the two read as the same heading printed twice. -->
          <caption align="left"><font size="1" color="{{MUTED_COLOR}}">Click a block to inspect it.</font></caption>
          <tr><td>
          <font size="1"><center>{{!grid_html}}</center></font>
          </td></tr></table>
        </td></tr>
      </table>
  </tr>
  <tr>
    <td valign="top" width="100%">
      <table id="panel" width="100%" border="1" cellpadding="0" cellspacing="0" bgcolor="{{PANEL_COLOR}}" bordercolor="{{BORDER_COLOR}}">
        <tr><td id="panel-header" background="{{PANEL_HDR_PNG}}" cellpadding="8">&nbsp;<font color="{{MUTED_COLOR}}" size="2"><b>Block Details</b></font></td></tr>
        <tr><td height="1" bgcolor="{{BORDER_COLOR}}"></td></tr>
        <tr><td id="panel-content" bgcolor="{{PANEL_COLOR}}" cellpadding="14" valign="top">{{!panel_html}}</td></tr>
      </table>
    </td>
  </tr>
    % end
</table>
<table id="footer" width="100%" border="0" cellpadding="8" cellspacing="0"><tr>
<td><font face="{{MONO_FONT}}" size="1" color="{{MUTED_COLOR}}">recoverage v{{version}}
% if db_mtime:
 &middot; DB updated {{db_mtime}}
% end
</font></td>
<td align="right"><font face="{{MONO_FONT}}" size="1" color="{{MUTED_COLOR}}">HTML5</font></td>
</tr></table>
</td></tr></table>
</main>
</font></body></html>"""

_PAGE_TPL = SimpleTemplate(source=_PAGE_SRC)


# ── SimpleTemplate: Detail Panel ────────────────────────────────────

_PANEL_SRC = r"""
% if not has_cell:
<table width="100%" border="0" cellpadding="10" cellspacing="1" bgcolor="{{BORDER_COLOR}}"><tr><td bgcolor="{{PANEL_COLOR}}" align="center"><font size="3" color="{{MUTED_COLOR}}"><b>Select a block</b></font><br><br><font color="{{MUTED_COLOR}}">Click any colored block in the grid to view details.</font></td></tr></table>
% else:
<table width="100%" border="0" cellpadding="0" cellspacing="0"><tr><td>&nbsp;<font size="2"><b>Block {{idx}}</b></font>
% if prev_url:
<a href="{{prev_url}}"><font size="1">&laquo; Prev</font></a>
% end
% if next_url:
<a href="{{next_url}}"><font size="1">Next &raquo;</font></a>
% end
</td></tr></table>
<table width="100%" border="0" cellpadding="3" cellspacing="1" bgcolor="{{BORDER_COLOR}}"><tr><td bgcolor="{{PANEL_COLOR}}"><font size="1" color="{{MUTED_COLOR}}"><b>Range:</b></font></td><td bgcolor="{{PANEL_COLOR}}"><font face="Courier New, monospace" size="1">{{cell_range}}</font></td></tr><tr><td bgcolor="{{PANEL_COLOR}}"><font size="1" color="{{MUTED_COLOR}}"><b>State:</b></font></td><td bgcolor="{{PANEL_COLOR}}"><font face="Courier New, monospace" size="1" color="{{state_color}}"><b>{{state_upper}}</b></font></td></tr>
% if cell_label:
<tr><td bgcolor="{{PANEL_COLOR}}"><font size="1" color="{{MUTED_COLOR}}"><b>Label:</b></font></td><td bgcolor="{{PANEL_COLOR}}"><font face="Courier New, monospace" size="1">{{cell_label}}</font></td></tr>
% end
% if parent_function:
<tr><td bgcolor="{{PANEL_COLOR}}"><font size="1" color="{{MUTED_COLOR}}"><b>Parent:</b></font></td><td bgcolor="{{PANEL_COLOR}}"><font face="Courier New, monospace" size="1"><a href="{{parent_url}}"><font color="{{ACCENT_COLOR}}">{{parent_function}}</font></a></font></td></tr>
% end
</table>
  % if not funcs:
<font color="{{MUTED_COLOR}}"><i>No functions in this block.</i></font><br>
    % if hex_dump_html:
{{!hex_heading}}
{{!hex_dump_html}}
      % if inspector_html:
{{!inspector_html}}
      % end
    % end
  % elif fn_data:
&nbsp;<font size="2"><b>Function Details</b></font>
    % if badge_html:
 {{!badge_html}}<br>
    % else:
<br>
    % end
<table width="100%" border="0" cellpadding="3" cellspacing="1" bgcolor="{{BORDER_COLOR}}">{{!detail_rows_html}}</table>
    % if annotations:
&nbsp;<font size="2"><b>Annotations</b></font><br>
<table width="100%" border="0" cellpadding="3" cellspacing="1" bgcolor="{{BORDER_COLOR}}">
      % for tag, text in annotations:
        % tag_color = COLORS.get("stub", "#ef4444") if tag == "BLOCKER" else ACCENT_COLOR
<tr><td bgcolor="{{PANEL_COLOR}}" width="25%"><font size="1" color="{{tag_color}}"><b>{{tag}}</b></font></td><td bgcolor="{{PANEL_COLOR}}"><font face="Courier New, monospace" size="1">{{text}}</font></td></tr>
      % end
</table>
    % end
    % if code_html:
{{!c_heading}}
{{!code_html}}
    % end
    % if asm_html:
{{!asm_heading}}
{{!asm_html}}
    % end
    % if bytes_html:
{{!bytes_heading}}
{{!bytes_html}}
      % if inspector_html:
{{!inspector_html}}
      % end
    % end
  % elif gl_data:
&nbsp;<font size="2"><b>Global Variable</b></font><br>
<table width="100%" border="0" cellpadding="3" cellspacing="1" bgcolor="{{BORDER_COLOR}}">{{!gl_detail_rows}}</table>
  % else:
<font color="{{MUTED_COLOR}}"><i>Unknown: {{fn_name}}</i></font>
  % end
% end
"""

_PANEL_TPL = SimpleTemplate(source=_PANEL_SRC)


# ── Rendering Logic ─────────────────────────────────────────────────


def _db_unavailable_page() -> HTTPResponse:
    """503 HTML page for an unreadable/unqueryable coverage.db in Potato Mode.

    ONE definition shared by the connect guard in :func:`render_potato` and
    the query-failure tail of :func:`handle_potato`, so both surfaces carry
    the same message (the two inline copies had already drifted: "to create
    it" vs "to create or rebuild it").
    """
    return HTTPResponse(
        status=503,
        body=(
            '<!DOCTYPE html><html lang="en"><head><meta charset="utf-8">'
            '<meta name="viewport" content="width=device-width, initial-scale=1">'
            "<title>ReCoverage — database unavailable</title></head>"
            f'<body bgcolor="{BG_COLOR}" text="{TEXT_COLOR}">'
            f'<font face="{MONO_FONT}">'
            '<table width="100%" height="90%" border="0"><tr><td align="center" valign="middle">'
            "<h1>Database unavailable</h1>"
            f'<p><font color="{MUTED_COLOR}">Run '
            "'rebrew catalog &amp;&amp; rebrew build-db' to create or rebuild it,"
            ' then <a href="/potato">retry Potato Mode</a> or '
            '<a href="/">open the SPA</a>.</font></p>'
            "</td></tr></table></font></body></html>"
        ),
        headers={"Content-Type": "text/html; charset=utf-8", "Cache-Control": "no-store"},
    )


def render_potato(parsed_url: ParseResult) -> str:
    """Render the Potato Mode page for *parsed_url*'s query string.

    Raises the 503 page from :func:`_db_unavailable_page` when coverage.db
    cannot be opened; the route below does not catch it, so it leaves the
    route as a response rather than a render error.
    """
    qs = parse_qs(parsed_url.query, keep_blank_values=True)
    target = qs.get("target", [""])[0]
    section = qs.get("section", [".text"])[0]
    filter_str = ",".join(qs.get("filter", [""]))
    active_filters = {f.strip() for f in filter_str.split(",") if f.strip()}
    idx_str = qs.get("idx", [""])[0]
    search_query = qs.get("search", [""])[0].strip()
    view = qs.get("view", [""])[0]
    sort_key = qs.get("sort", ["va"])[0]
    status_filter = qs.get("status", [""])[0]
    page_str = qs.get("page", [""])[0]

    db_path = _db_path()
    try:
        conn = _open_db(db_path)
    except sqlite3.Error:
        _log.warning("Potato mode: database unavailable at %s", db_path)
        # Signal failure, not a 200 page: monitoring and scripts must see the
        # DB outage (same contract as the API's 503 db_unavailable).
        raise _db_unavailable_page() from None

    with contextlib.closing(conn):
        c = conn.cursor()
        return _render_potato_inner(
            c,
            target,
            section,
            active_filters=active_filters,
            idx_str=idx_str,
            search_query=search_query,
            view=view,
            sort_key=sort_key,
            status_filter=status_filter,
            page_str=page_str,
        )


# ── HTTP surface ───────────────────────────────────────────────────
#
# The /potato route lives with the renderer it serves, not in recoverage.ui:
# the handler's only job is ETag + cache policy around render_potato.


@app.get("/potato")
def handle_potato() -> bytes | Any:
    try:
        # WAL-aware snapshot (see _snapshot_db_mtime), not raw st_mtime: a
        # rebuild that commits only to -wal must still mint a new ETag or
        # browsers keep a stale 304.  Same contract as /data, /asm, /bytes.
        qs = request.query_string
        if isinstance(qs, bytes):
            qs = qs.decode("utf-8", errors="replace")
        # Redact token from ETag input so query-string ETag doesn't leak it.
        if "token=" in qs:
            qs = "&".join(p for p in qs.split("&") if not p.startswith("token="))
        etag = _etag_or_304(_snapshot_db_mtime(), qs)
        body = render_potato(urlparse(request.url)).encode("utf-8")
        # Every other DB-derived response carries an explicit cache policy;
        # /potato was the one surface sent with none, which leaves the browser
        # free to apply heuristic freshness and a shared cache free to store
        # and replay a page that may have been rendered for a token-bearing
        # client.  CACHE_REVALIDATE keeps the ETag's cheap 304s while forcing
        # revalidation before every reuse.
        resp_body = _compressed(body, "text/html; charset=utf-8", Cache_Control=CACHE_REVALIDATE)

        if etag:
            response.set_header("ETag", etag)
        return resp_body

    except sqlite3.Error:
        # A DB that opens but cannot answer queries is the same
        # db_unavailable condition render_potato's connect guard reports as
        # 503 — not an application bug.  One contract (and one page) for
        # both surfaces.
        _log.exception("Potato mode database query failed")
        return _db_unavailable_page()
    # json.JSONDecodeError needs no entry: it subclasses ValueError.
    except (OSError, ValueError, KeyError):
        _log.exception("Potato mode render failed")
        return HTTPResponse(
            status=500,
            body="<html><body>Internal server error</body></html>",
            headers={"Cache-Control": CACHE_NO_STORE},
        )


def _load_section_data(
    c: sqlite3.Cursor,
    target: str,
) -> tuple[dict[str, dict[str, Any]], dict[str, Any]]:
    data: dict[str, Any] = _load_metadata(c, target)

    c.execute(
        "SELECT name, va, size, fileOffset, columns FROM sections WHERE target = ?",
        (target,),
    )
    sections: dict[str, dict[str, Any]] = {}
    _sec_keys = ("name", "va", "size", "fileOffset", "columns")
    for row in c.fetchall():
        sec: dict[str, Any] = dict(zip(_sec_keys, row, strict=True))
        sec["cells"] = []
        sections[sec["name"]] = sec
    # PE load order (ascending VA), matching the SPA's sectionNames sort: the
    # section carrying the work (.text) leads instead of trailing an
    # alphabetical row.  Sections without a VA sort last, behind every real
    # address.
    sections = dict(
        sorted(
            sections.items(),
            key=lambda kv: _SECTION_VA_MAX if kv[1]["va"] is None else int(kv[1]["va"]),
        )
    )

    return sections, data


def _db_updated_mtime_ns() -> int | None:
    """Newest mtime_ns across coverage.db and its -wal sibling, or None.

    The footer's "DB updated" stamp must include -wal: a rebuild that commits
    only to the WAL leaves the main file's mtime untouched, and reading the
    main file alone would display a stale instant (same WAL-awareness contract
    as _snapshot_db_mtime, rendered as wall-clock time instead of folded into
    an opaque change token).
    """
    return _newest_mtime_ns(_db_path())


def _db_updated_label() -> str:
    """Render _db_updated_mtime_ns() as "YYYY-MM-DD HH:MM UTC" ("" when no DB)."""
    mtime_ns = _db_updated_mtime_ns()
    if mtime_ns is None:
        return ""
    return datetime.fromtimestamp(mtime_ns / 1e9, tz=UTC).strftime("%Y-%m-%d %H:%M UTC")


# Potato mode re-derived the grid input on EVERY page render: json.loads of
# the section's multi-MB cells payload plus a full-list merge pass (~120 ms
# measured at 25k cells) dominated each request even though the SQL beneath
# them was already memoized — every filter toggle, search, and pager click
# re-paid it.  Cache the derived (parsed, merged) pair instead, keyed by the
# WAL-aware snapshot + target + section + column count: a rebuild changes
# the fingerprint and misses, so the cache self-invalidates with the same
# contract as /data's memo.  Entries are read-only after publication (grid,
# pager, and panel only read them), so sharing across requests/threads is
# safe; each retained entry costs roughly what one render already allocated
# transiently, and _GRID_CACHE_MAX bounds retention across rebuilds.
_GRID_CACHE: dict[
    tuple[int, int, str, str, int],
    tuple[list[dict[str, Any]], list[dict[str, Any]]],
] = {}
_GRID_CACHE_LOCK = threading.Lock()
_GRID_CACHE_MAX = 4


def clear_cells_cache() -> None:
    """Clear the memoized potato grid payloads (called on DB rebuild)."""
    with _GRID_CACHE_LOCK:
        _GRID_CACHE.clear()
    with _POTATO_STATS_CACHE_LOCK:
        _POTATO_STATS_CACHE.clear()


def _load_grid_cells(
    c: sqlite3.Cursor, target: str, section: str, grid_columns: int
) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    """Return ``(cells, merged_cells)`` for *section*, memoized per DB snapshot.

    Only the requested section's JSON is fetched and decoded — sibling
    sections never render cells, so materializing their multi-MB payloads
    was pure waste.
    """
    snap = _snapshot_db_mtime()
    key = (*snap, target, section, int(grid_columns)) if snap is not None else None
    if key is not None:
        with _GRID_CACHE_LOCK:
            cached = _GRID_CACHE.get(key)
        if cached is not None:
            return cached

    rows = _cells_json_rows(c, target, section)
    # An unknown or cell-less section decodes to no cells: _cells_json_rows
    # returns no rows and the grid renders empty.
    cells: list[dict[str, Any]] = json.loads(rows[0][1]) if rows else []
    merged = _merge_cells(cells, grid_columns)
    entry = (cells, merged)

    # The cursor's read snapshot is older than `snap` whenever a rebuild
    # committed after render_potato's first query.  Caching that stale payload
    # under the NEW fingerprint poisons the memo: a broadcast that cleared the
    # cache can be overtaken by this insert, and nothing invalidates it until
    # the next rebuild.  Only publish when the watermark still holds.
    if key is not None and _snapshot_db_mtime() == snap:
        with _GRID_CACHE_LOCK:
            _evict_oldest(_GRID_CACHE, _GRID_CACHE_MAX)
            _GRID_CACHE[key] = entry
    return entry


# Per-section bucket stats for the map header (see _section_stats_cached).
_POTATO_STATS_CACHE: dict[tuple[int, int, str], dict[str, dict[str, Any]]] = {}
_POTATO_STATS_CACHE_LOCK = threading.Lock()
_POTATO_STATS_CACHE_MAX = 16


def _section_stats_cached(
    c: sqlite3.Cursor,
    target: str,
    sections: dict[str, dict[str, Any]],
    data: dict[str, Any],
) -> dict[str, dict[str, Any]]:
    """:func:`_compute_section_stats`, memoized per WAL-aware snapshot + target.

    Costs a query per call, yet the result changes only when the DB does, and
    every pager/filter click used to re-pay it.  All three inputs derive from
    the same DB state, so the snapshot alone keys the memo (same
    self-invalidating contract as _GRID_CACHE).  Entries are small — one dict
    per section — so the cap is generous.
    """
    snap = _snapshot_db_mtime()
    key = (*snap, target) if snap is not None else None
    if key is not None:
        with _POTATO_STATS_CACHE_LOCK:
            cached = _POTATO_STATS_CACHE.get(key)
        if cached is not None:
            return cached
    stats = _compute_section_stats(c, target, sections, data)
    # Same watermark re-check as _load_grid_cells: stats read through a cursor
    # whose snapshot predates a rebuild must not be filed under the new
    # fingerprint.
    if key is not None and _snapshot_db_mtime() == snap:
        with _POTATO_STATS_CACHE_LOCK:
            _evict_oldest(_POTATO_STATS_CACHE, _POTATO_STATS_CACHE_MAX)
            _POTATO_STATS_CACHE[key] = stats
    return stats


def _compute_section_stats(
    c: sqlite3.Cursor,
    target: str,
    sections: dict[str, dict[str, Any]],
    data: dict[str, Any],
) -> dict[str, dict[str, Any]]:
    # A non-object summary (valid JSON of another type in a foreign DB) would
    # crash .get() below with AttributeError — same guard as
    # server._section_stats applies to its own summary read.
    summary = data.get("summary", {})
    if not isinstance(summary, dict):
        summary = {}
    per_section_stats: dict[str, dict[str, Any]] = {}
    c.execute(
        "SELECT section_name, total_cells, exact_count, reloc_count, "
        "near_match_count, stub_count, padding_count FROM section_cell_stats WHERE target = ?",
        (target,),
    )
    for row in c.fetchall():
        sec_name_r, s_total, s_exact, s_reloc, s_near_match, s_stub, s_padding = row
        sec_summary_entry = summary.get(sec_name_r, summary)
        s_covered_bytes = sec_summary_entry.get("coveredBytes", 0)
        # `or 0`, not .get("size", 0): a NULL size is schema-legal (.bss-style
        # sections carry NULL columns like va/fileOffset) and dict.get returns
        # the stored None — which then raises TypeError on `> 0` below and
        # 500s the whole page.  Same "or" guard as the va/columns fallbacks in
        # _build_grid_html and _render_grid_view.
        s_sec_size = sections.get(sec_name_r, {}).get("size") or 0
        # Same rounding as server._section_stats (round to 2dp): int() floor
        # made the map header read "87% covered" beside the topbar's "88.0%"
        # for the same section.
        s_pct = round(s_covered_bytes / s_sec_size * 100, 2) if s_sec_size > 0 else 0
        per_section_stats[sec_name_r] = {
            "total": s_total,
            "exact": s_exact,
            "reloc": s_reloc,
            "near_match": s_near_match,
            "stub": s_stub,
            "padding": s_padding,
            "pct": s_pct,
        }
    return per_section_stats


#: Rows each search query may scan.  The cap bounds the work a single search
#: box keystroke can cause on a large project; ORDER BY keeps which rows those
#: are deterministic, since SQLite's scan order is otherwise arbitrary.
_SEARCH_ROW_LIMIT = 500


def _search_functions(c: sqlite3.Cursor, target: str, search_query: str) -> set[str]:
    search_matched_fns: set[str] = set()
    if not search_query:
        return search_matched_fns

    # A non-ASCII term gets a second, folded disjunct over the name columns:
    # SQLite's LIKE folds case for ASCII only, so "CAFÉ" would otherwise miss
    # "Café_Render" and an NFD spelling would miss its NFC twin.  The VA
    # columns are ASCII hex, so LIKE already folds them correctly.
    fn_folded_sql, fn_folded_params = folded_like_clause(["name", "symbol"], search_query)
    like_pat = _escape_like(search_query)
    fn_chain, fn_arity = like_match(["name", "vaStart", "symbol"])
    c.execute(
        f"SELECT name, vaStart FROM functions WHERE target = ? AND {fn_chain}"
        + (f" OR {fn_folded_sql}" if fn_folded_sql else "")
        + " ORDER BY name, vaStart LIMIT ?",
        (target, *([like_pat] * fn_arity), *fn_folded_params, _SEARCH_ROW_LIMIT),
    )
    for name, va_start in c.fetchall():
        search_matched_fns.add(name)
        if va_start:
            # Grid .text cells store the function's vaStart string (not the
            # name) in their `functions` field — the dimming test compares
            # cell entries against this set, so VA spellings must be included.
            search_matched_fns.add(va_start)
    # The address column is matched in both spellings _format_va can produce
    # (`0x%08x`, padded, and `0x%x`, unpadded) so an address copied out of a
    # Potato table matches when pasted into the search box.  printf('0x%x', va)
    # has no prefix and could never match either.
    # The row cap applies to rows selected, not to the returned set.
    g_folded_sql, g_folded_params = folded_like_clause(["name"], search_query)
    g_chain, g_arity = like_match(
        ["name", "'0x' || printf('%08x', va)", "'0x' || printf('%x', va)"]
    )
    c.execute(
        f"SELECT name FROM globals WHERE target = ? AND {g_chain}"
        + (f" OR {g_folded_sql}" if g_folded_sql else "")
        + " ORDER BY name LIMIT ?",
        (target, *([like_pat] * g_arity), *g_folded_params, _SEARCH_ROW_LIMIT),
    )
    search_matched_fns.update(row[0] for row in c.fetchall())
    return search_matched_fns


def _build_filter_data(
    target: str,
    section: str,
    active_filters: set[str],
    search_query: str,
) -> list[tuple[str, str, str, bool, str]]:
    filter_opts = [
        ("exact", "E", "e"),
        ("reloc", "R", "r"),
        ("near_match", "M", "m"),
        ("stub", "S", "s"),
        ("padding", "P", "p"),
    ]
    toggle_links = {
        f: _build_url(
            target,
            section,
            (
                (active_filters - {f}) or None
                if f in active_filters
                else (active_filters | {f}) or None
            ),
            search=search_query,
        )
        for f, _, _ in filter_opts
    }
    all_link = _build_url(target, section, search=search_query)
    filter_btn_data: list[tuple[str, str, str, bool, str]] = [
        (
            all_link,
            "All",
            TEXT_COLOR if not active_filters else MUTED_COLOR,
            not active_filters,
            "0",
        )
    ]
    filter_btn_data.extend(
        (toggle_links[f], label, COLORS[f], f in active_filters, key)
        for f, label, key in filter_opts
    )
    return filter_btn_data


def _build_progress(
    section: str,
    sec_data: dict[str, Any],
    data: dict[str, Any],
    sections: dict[str, dict[str, Any]],
) -> dict[str, Any] | None:
    if not sections:
        return None

    summary = data.get("summary", {})
    if not isinstance(summary, dict):
        # Valid JSON of another type (foreign DB): .get() below would raise
        # AttributeError.  Same guard as _compute_section_stats.
        summary = {}
    # `or 0`, not .get("size", 0): a NULL size is schema-legal and .get would
    # return the stored None, crashing every `sec_size > 0` guard below with
    # TypeError (which escapes handle_potato's except tuple as a raw 500).
    sec_size = sec_data.get("size") or 0
    sec_summ = summary.get(section, summary)
    covered_bytes = sec_summ.get("coveredBytes", 0)
    total_fn = sec_summ.get("totalFunctions", 0)
    exact_matches = sec_summ.get("exactMatches", 0)
    reloc_matches = sec_summ.get("relocMatches", 0)
    near_match_matches = sec_summ.get("nearMatchCount", 0)
    stub_matches = sec_summ.get("stubCount", 0)
    matched_fn = exact_matches + reloc_matches  # NEAR_MATCHING/STUB are not matched

    # ONE denominator for the whole bar.  .text's bar tracks FUNCTIONS (the
    # "matched" stat beside it is a function count), every other section's
    # tracks BYTES.  The two are different partitions of the section, so a
    # segment computed against the other one is not a share of this bar: the
    # padding band used to be bytes/sec_size even on the function-denominated
    # .text bar, where 500+200+100+100 matched of 1000 functions plus a 20 KB
    # padding run in a 100 KB section summed to 110%.  That clamped seg_none to
    # 0, so the unmatched functions were painted no grey at all, and
    # _progress_svg drew the trailing segments past the 700-unit track, which
    # clipped them.  Padding is a cell state with no function counterpart, so
    # it belongs only to the byte-denominated bar; on .text those bytes are
    # already inside the "none" remainder.
    padding_bytes = sec_summ.get("paddingBytes", 0)
    if section == ".text" and total_fn > 0:
        seg_exact = exact_matches / total_fn * 100
        seg_reloc = reloc_matches / total_fn * 100
        seg_near_match = near_match_matches / total_fn * 100
        seg_stub = stub_matches / total_fn * 100
        seg_padding = 0
    elif sec_size > 0:
        seg_exact = sec_summ.get("exactBytes", 0) / sec_size * 100
        seg_reloc = sec_summ.get("relocBytes", 0) / sec_size * 100
        seg_near_match = sec_summ.get("nearMatchBytes", 0) / sec_size * 100
        seg_stub = sec_summ.get("stubBytes", 0) / sec_size * 100
        seg_padding = padding_bytes / sec_size * 100
    else:
        seg_exact = seg_reloc = seg_near_match = seg_stub = seg_padding = 0

    # max(0, ...) still guards a summary whose state counts exceed its own
    # total (a foreign or hand-edited DB); it is not what keeps a mixed
    # denominator inside the track.
    seg_none = max(0, 100 - seg_exact - seg_reloc - seg_near_match - seg_stub - seg_padding)
    return {
        "sec_size": sec_size,
        "coverage_pct": (covered_bytes / sec_size * 100) if sec_size > 0 else 0,
        "total_fn": total_fn,
        "matched_fn": matched_fn,
        "segments": [
            ("exact", seg_exact),
            ("reloc", seg_reloc),
            ("near_match", seg_near_match),
            ("stub", seg_stub),
            ("padding", seg_padding),
            ("none", seg_none),
        ],
    }


def _merge_cells(cells: list[dict[str, Any]], grid_columns: int) -> list[dict[str, Any]]:
    """Merge adjacent cells with identical state+functions within a grid row.

    Invariant: sum of spans in output == sum of spans in input.
    Cells with state "none" are never merged (they represent undocumented gaps
    that should remain individually clickable).
    """
    if not cells:
        return []

    # The output list is built LAZILY, at the first merge.  Until one happens
    # the rows are the input cells unchanged, so they are handed back by
    # reference instead of copied.  The no-merge case is the common one by a
    # wide margin: merging needs a real match state on BOTH cells (see the guard
    # below) and the large sections are 99.7-100% "none" cells, so a 39k-cell
    # .text grid produces ZERO merged runs — 38,919 flushes for 38,918 cells.
    # Copying a row per cell cost ~26 ms of a ~49 ms cold render.
    #
    # Returning the parsed cells is safe because every consumer reads
    # span/end/state/functions off the cell (all present in the parsed JSON) and
    # reconstructs orig_idx from its own position when the key is absent — the
    # render loop defaults to page_offset + i, _grid_page to its enumerate pos.
    # For any row before the first merge those positions ARE the original
    # indices, which is why the untouched prefix needs no annotation.
    out: list[dict[str, Any]] | None = None
    start_idx = 0
    acc_span = 0
    acc_end: Any = None
    acc_col = 0
    acc_state: Any = None
    acc_fns: Any = None
    acc_cell: dict[str, Any] | None = None

    def flush() -> None:
        # No-op until the first merge: everything flushed before one is an
        # unmerged single cell, already covered by the `cells[:start_idx]` slice.
        if out is not None and acc_cell is not None:
            out.append({**acc_cell, "orig_idx": start_idx, "span": acc_span, "end": acc_end})

    for i, cell in enumerate(cells):
        state = cell.get("state")
        fns = cell.get("functions")
        span = int(cell.get("span", 1))
        if (
            acc_cell is not None
            and state not in ("none", None)
            and state == acc_state
            and fns == acc_fns
            and acc_col + span <= grid_columns
        ):
            if out is None:
                # First merge: every row before the pending run is untouched.
                out = cells[:start_idx]
            acc_span += span
            acc_end = cell.get("end")
            acc_col += span
            continue
        flush()
        start_idx = i
        acc_cell = cell
        acc_state = state
        acc_fns = fns
        acc_span = span
        acc_end = cell.get("end")
        # A run that would overflow the row starts over from this cell alone;
        # span is CHECK (span > 0) in the schema, so a pending run sitting on
        # the last column always overflows on the next cell.
        acc_col += span
        if acc_col > grid_columns:
            acc_col = span

    if out is None:
        return cells
    flush()
    return out


# One page of grid is this many rows × the section's column count (~2k cells at
# 64 columns, ~700 KB of table markup).  Potato Mode exists for clients that
# cannot run the SPA, and those are the last clients that should be handed a
# 7 MB response with 74k DOM nodes.
_GRID_PAGE_ROWS = 32


def _block_position(merged_cells: list[dict[str, Any]], idx: int) -> int | None:
    """Position in *merged_cells* of original cell *idx*, or None if absent.

    A merged row carries the ``orig_idx`` of the run it stands for; a row
    _merge_cells handed back unannotated (the no-merge fast path, and the
    prefix before the first merge) carries none, and its original index IS its
    own position — the same default the render loop applies.  Reading that
    sequence either way is strictly increasing, because a merge only ever
    collapses a run and stamps the index the run started at, so the row that
    follows it starts later.

    That monotonicity is what makes the search logarithmic.  Walking the list
    instead cost one dict lookup per cell of the whole section on every click
    that carries an ``?idx=``: 5.8 ms against a ~4 ms render on an 80k-cell
    .text, growing with the section.
    """
    lo, hi = 0, len(merged_cells)
    while lo < hi:
        mid = (lo + hi) // 2
        if merged_cells[mid].get("orig_idx", mid) < idx:
            lo = mid + 1
        else:
            hi = mid
    if lo < len(merged_cells) and merged_cells[lo].get("orig_idx", lo) == idx:
        return lo
    return None


def _grid_page(
    page_str: str,
    idx_str: str,
    merged_cells: list[dict[str, Any]],
    page_cells: int,
    page_count: int,
) -> int:
    """Resolve which grid page to render, clamped to 1..page_count.

    An explicit ?page= wins.  Otherwise a selected ?idx= pulls its own page into
    view, so following a link to a block never lands on a page without it.
    """
    if page_str:
        try:
            return max(1, min(page_count, int(page_str)))
        except ValueError:
            return 1
    if idx_str:
        try:
            idx = int(idx_str)
        except ValueError:
            return 1
        pos = _block_position(merged_cells, idx)
        if pos is not None:
            return max(1, min(page_count, pos // page_cells + 1))
    return 1


def _pager_html(
    target: str,
    section: str,
    active_filters: set[str],
    search_query: str,
    page: int,
    page_count: int,
) -> str:
    """Prev/Next links plus a page counter, in the surrounding table idiom."""
    filters = active_filters or None

    def link(p: int, text: str) -> str:
        if not 1 <= p <= page_count:
            return f'<font face="{MONO_FONT}" size="2" color="{MUTED_COLOR}">{text}</font>'
        href = _build_url(target, section, filters, search=search_query, page=p)
        return (
            f'<a href="{href}">'
            f'<font face="{MONO_FONT}" size="2" color="{ACCENT_COLOR}">{text}</font></a>'
        )

    return (
        f'<table id="pager" border="0" cellpadding="4" cellspacing="0"><tr>'
        f"<td>{link(page - 1, '[&lt; Prev]')}</td>"
        f'<td><font face="{MONO_FONT}" size="2" color="{MUTED_COLOR}">'
        f"&nbsp;Page {page} of {page_count}&nbsp;</font></td>"
        f"<td>{link(page + 1, '[Next &gt;]')}</td>"
        f"</tr></table>"
    )


#: Ceiling on a section's declared column count.  A sections row can claim a
#: lattice far wider than any real PE, and the sizing row emits one <td> per
#: column, so the cap is a response-size bound, applied wherever the count is
#: resolved.
_MAX_GRID_COLUMNS = 256


def _build_grid_html(
    merged_cells: list[dict[str, Any]],
    sec_data: dict[str, Any],
    grid_columns: int,
    active_filters: set[str],
    search_query: str,
    search_matched_fns: set[str],
    idx_str: str,
    target: str,
    section: str,
    page_offset: int = 0,
) -> str:
    """Render the coverage grid as an HTML table.

    grid_columns controls the number of cells per row. A sizing row of
    transparent cells is emitted first so the browser allocates uniform
    column widths regardless of colspan usage in data rows.

    *page_offset* is the index of this page's first row within the whole merged
    list, needed only to reconstruct ``orig_idx`` for rows that carry none:
    _merge_cells returns the parsed cells untouched when a section cannot merge
    anything, and those cells have no ``orig_idx`` of their own.
    """
    if grid_columns <= 0:
        raise ValueError(f"grid_columns must be positive, got {grid_columns}")
    grid_columns = min(grid_columns, _MAX_GRID_COLUMNS)
    # Fixed 12px lattice: at 64 columns that is ~770px, which overflowed a
    # 390px phone.  12px keeps blocks legible and tappable on desktop; narrow
    # sections render the same size, so every section shares one predictable
    # block size.
    cell_w = 12
    cell_h = 12
    sizing_tds = "".join(
        f'<td bgcolor="{BG_COLOR}" width="{cell_w}" height="1"></td>' for _ in range(grid_columns)
    )
    grid_html_parts = [
        (
            f'<table id="grid" border="1" frame="void" rules="all" cellpadding="0" cellspacing="0" bordercolor="{BG_COLOR}" bgcolor="{BG_COLOR}">'
            f"<tr>{sizing_tds}</tr><tr>"
        )
    ]

    # Link/attribute fragments that are identical for every cell on the page,
    # hoisted out of the loop (quoting + escaping ~2k times per render was
    # measurable).  The pieces reassemble to exactly what _build_url produces
    # for each cell: ?target&section[&filter]&idx=N[&search].
    link_prefix = f"?target={_url_quote(target)}&section={_url_quote(section)}" + (
        f"&filter={_url_quote(','.join(sorted(active_filters)))}" if active_filters else ""
    )
    link_suffix = f"&search={_url_quote(search_query)}" if search_query else ""

    # Selection target parsed ONCE for the whole page: comparing each cell's
    # orig_idx against it replaces a per-cell int() (up to ~2k parses/render).
    try:
        sel_idx: int | None = int(idx_str)
    except ValueError:
        sel_idx = None

    curr_col = 0
    # Sections without file backing (.bss) carry a NULL va (the api.py /asm
    # and /bytes endpoints document and guard this shape): fall back to 0 so
    # titles show file-relative offsets instead of raising TypeError on
    # None + int, which 500s the whole page.
    sec_va = sec_data.get("va") or 0
    for i, cell in enumerate(merged_cells):
        span = cell.get("span", 1)
        # Absent orig_idx means the no-merge fast path returned the parsed cells;
        # the global index is then this page's offset plus this position.
        orig_idx = cell.get("orig_idx", page_offset + i)
        if curr_col >= grid_columns:
            grid_html_parts.append("</tr><tr>")
            curr_col = 0

        state = cell.get("state", "none")

        dimmed = (active_filters and state != "none" and state not in active_filters) or (
            search_query and not any(fn in search_matched_fns for fn in cell.get("functions", []))
        )
        bgcolor = BG_COLOR if dimmed else COLORS.get(state, COLORS["none"])
        selected = orig_idx == sel_idx
        link = f"{link_prefix}&idx={orig_idx}{link_suffix}"
        funcs = cell.get("functions", [])
        title = (
            f"{hex(sec_va + cell.get('start', 0))}..{hex(sec_va + cell.get('end', 0))} | {state}"
        )
        if funcs:
            title += f" | {funcs[0]}"
        # The alt text IS the link's accessible name here, so it carries the
        # same address range the title does.  With state alone, thousands of
        # links announced as "none" with no way to tell them apart (WCAG 2.4.4).
        escaped_title = _esc(title)
        w = cell_w * span
        img = (
            f'<a href="{link}" title="{escaped_title}">'
            f'<img src="{TRANSPARENT_GIF}" width="{w}" height="{cell_h}" border="0" alt="{escaped_title}"></a>'
        )

        if selected:
            sel_img = (
                f'<a href="{link}" title="{escaped_title}">'
                f'<img src="{TRANSPARENT_GIF}" width="{w - 2}" height="{cell_h - 2}" border="0" alt="{escaped_title}">'
                f"</a>"
            )
            grid_html_parts.append(
                f'<td id="sel" bgcolor="{BG_COLOR}" width="{w}" height="{cell_h}" colspan="{span}">'
                f'<table border="1" cellpadding="0" cellspacing="0" bordercolor="{ACCENT_COLOR}" width="100%">'
                f'<tr><td bgcolor="{bgcolor}">{sel_img}</td></tr></table></td>'
            )
        else:
            grid_html_parts.append(
                f'<td bgcolor="{bgcolor}" width="{w}" height="{cell_h}" colspan="{span}">{img}</td>'
            )
        curr_col += span

    remaining = grid_columns - curr_col
    if remaining > 0:
        grid_html_parts.append(
            f'<td bgcolor="{BG_COLOR}" width="{cell_w * remaining}"'
            f' height="{cell_h}" colspan="{remaining}"></td>'
        )
    grid_html_parts.append("</tr></table>")
    return "".join(grid_html_parts)


def _render_function_list(
    c: sqlite3.Cursor,
    target: str,
    section: str,
    search_query: str,
    sort_key: str,
    status_filter: str,
) -> str:
    # SAFETY: order_by is whitelisted via allowed_sort dict (no user strings reach SQL).
    allowed_sort = {"name": "name", "size": "size", "status": "status", "va": "va"}
    order_by = allowed_sort.get(sort_key, "va")

    # Base filter: GLOBAL/DATA marker rows live in the functions table but are
    # data markers, not functions — same exclusion as the API list endpoint
    # and _section_stats, so both surfaces list the same rows.
    where = ["target = ?", NOT_DATA_MARKER_SQL]
    params: list[Any] = [target]
    if status_filter:
        where.append("status = ?")
        params.append(status_filter)
    if search_query:
        like = _escape_like(search_query)
        # The VA column below is printed by _format_va, which pads to eight
        # digits, so both that spelling and the bare one are matched: an
        # address copied out of this very table matches when pasted into the
        # search box.  printf('0x%x', va) has no prefix and could never match.
        where.append(
            "(name LIKE ? ESCAPE '\\' OR symbol LIKE ? ESCAPE '\\'"
            " OR ('0x' || printf('%08x', va)) LIKE ? ESCAPE '\\'"
            " OR ('0x' || printf('%x', va)) LIKE ? ESCAPE '\\')"
        )
        params.extend([like, like, like, like])

    where_sql = " AND ".join(where)
    # Cap the rendered list (same bound as the search above) so a large
    # project's ?view=functions page doesn't build a multi-MB HTML document on
    # every request.  ORDER BY keeps the cap deterministic.
    c.execute(
        "SELECT name, va, vaStart, size, status, module FROM functions "
        f"WHERE {where_sql} ORDER BY {order_by}, va LIMIT ?",
        [*params, _SEARCH_ROW_LIMIT],
    )
    rows = c.fetchall()

    base = f"?target={_url_quote(target)}&section={_url_quote(section)}&view=functions"
    if search_query:
        base += f"&search={_url_quote(search_query)}"
    if status_filter:
        base += f"&status={_url_quote(status_filter)}"

    parts = [
        f'<table width="100%" border="1" cellpadding="0" cellspacing="0" bordercolor="{BORDER_COLOR}" bgcolor="{PANEL_COLOR}">',
        (
            f'<tr><td background="{PANEL_HDR_PNG}" cellpadding="8">'
            f'<font color="{MUTED_COLOR}" size="2"><b>Functions</b></font> '
            f'<font size="1" color="{MUTED_COLOR}">({len(rows)} results)</font> '
            f'<a href="{_build_url(target, section, search=search_query)}"><font size="1" color="{ACCENT_COLOR}">[Grid View]</font></a>'
            f"</td></tr>"
        ),
        "<tr><td>",
        f'<table width="100%" border="1" cellpadding="6" cellspacing="0" bordercolor="{BORDER_COLOR}">',
        (
            f'<tr bgcolor="{PANEL_COLOR}">'
            f'<th><a href="{base}&sort=name"><font color="{MUTED_COLOR}">Name</font></a></th>'
            f'<th><a href="{base}&sort=va"><font color="{MUTED_COLOR}">VA</font></a></th>'
            f'<th><a href="{base}&sort=size"><font color="{MUTED_COLOR}">Size</font></a></th>'
            f'<th><a href="{base}&sort=status"><font color="{MUTED_COLOR}">Status</font></a></th>'
            f'<th><font color="{MUTED_COLOR}">Origin</font></th></tr>'
        ),
    ]

    # The same view, minus whichever criterion emptied it.  A bare "No
    # functions found." does not say the query caused it, and this list has no
    # other sign of the active search: the user is left hunting the form at the
    # top of the page for the box they just typed in.
    without_search = f"?target={_url_quote(target)}&section={_url_quote(section)}&view=functions"
    if status_filter:
        without_search += f"&status={_url_quote(status_filter)}"

    if not rows:
        if search_query:
            parts.append(
                f'<tr><td colspan="5"><font color="{MUTED_COLOR}">No functions match '
                f"&quot;{_esc(search_query)}&quot;. "
                f'<a href="{without_search}"><font color="{ACCENT_COLOR}">[Clear search]</font></a>'
                "</font></td></tr>"
            )
        elif status_filter:
            parts.append(
                f'<tr><td colspan="5"><font color="{MUTED_COLOR}">No functions with status '
                f"{_esc(status_filter)}. "
                f'<a href="{without_search}"><font color="{ACCENT_COLOR}">[Clear filter]</font></a>'
                "</font></td></tr>"
            )
        else:
            parts.append(
                f'<tr><td colspan="5"><font color="{MUTED_COLOR}">No functions found.</font></td></tr>'
            )
    else:
        # One row's link differs from the next only in the quoted name; the
        # quoted target is the same string 500 times, so it is built once
        # (same hoist as _build_grid_html's link_prefix).
        link_prefix = f"?target={_url_quote(target)}&section=.text&search="
        for name, va, _, size, status, module in rows:
            st = status or "none"
            color = COLORS.get(st.lower(), TEXT_COLOR)
            name_link = link_prefix + _url_quote(name)
            parts.append(
                "<tr>"
                f'<td><a href="{name_link}"><font color="{ACCENT_COLOR}">{_esc(name)}</font></a></td>'
                f'<td><font face="Courier New, monospace" size="2">{_esc(_format_va(va))}</font></td>'
                f'<td><font face="Courier New, monospace" size="2">{_esc(size)}</font></td>'
                f'<td><font color="{color}" face="Courier New, monospace" size="2"><b>{_esc(st.upper())}</b></font></td>'
                f'<td><font face="Courier New, monospace" size="2">{_esc(module or "")}</font></td>'
                "</tr>"
            )

    parts.append("</table></td></tr></table>")
    return "".join(parts)


def _section_tab_data(
    target: str,
    section: str,
    sections: dict[str, dict[str, Any]],
    active_filters: set[str] | None,
    search_query: str,
) -> list[tuple[str, str, bool, str]]:
    """(name, url, is_active, accesskey) for the section tabs.

    The accesskey is the section name's second character, falling back to the
    first: a one-character section name would otherwise index off the end of
    the string and 500 the whole page.
    """
    return [
        (
            s,
            _build_url(target, s, active_filters or None, search=search_query),
            s == section,
            s[1:2] or s[:1],
        )
        for s in sections
    ]


def _render_grid_view(
    c: sqlite3.Cursor,
    target: str,
    section: str,
    sec_data: dict[str, Any],
    sections: dict[str, dict[str, Any]],
    data: dict[str, Any],
    active_filters: set[str],
    idx_str: str,
    search_query: str,
    search_matched_fns: set[str],
    page_str: str,
) -> tuple[str, int, str, dict[str, Any]]:
    """Assemble the map view: (grid_html, block_count, panel_html, sec_stats).

    Linear pipeline over the section's cells — fetch, merge, paginate, render
    grid + detail panel.  Only the grid view calls this, so the functions view
    never pays any cells work (fetch, decode, or merge).
    """
    # A NULL columns value (schema-legal, like the NULL va/fileOffset a .bss
    # section carries) must fall back to 64, not TypeError on None <= 0 —
    # which escapes handle_potato's except tuple as a raw HTML 500.
    grid_columns = sec_data.get("columns") or 64
    if grid_columns <= 0:
        grid_columns = 64
    grid_columns = min(grid_columns, _MAX_GRID_COLUMNS)
    cells, merged_cells = _load_grid_cells(c, target, section, grid_columns)
    per_section_stats = _section_stats_cached(c, target, sections, data)
    block_count = len(merged_cells)

    # Paginate: one page is _GRID_PAGE_ROWS rows of the grid.
    page_cells = _GRID_PAGE_ROWS * grid_columns
    page_count = max(1, -(-block_count // page_cells))
    page = _grid_page(page_str, idx_str, merged_cells, page_cells, page_count)
    page_offset = (page - 1) * page_cells
    page_slice = merged_cells[page_offset : page_offset + page_cells]

    grid_html = _build_grid_html(
        merged_cells=page_slice,
        sec_data=sec_data,
        grid_columns=grid_columns,
        active_filters=active_filters,
        search_query=search_query,
        search_matched_fns=search_matched_fns,
        idx_str=idx_str,
        target=target,
        section=section,
        page_offset=page_offset,
    )
    if page_count > 1:
        grid_html += _pager_html(target, section, active_filters, search_query, page, page_count)
    sec_stats = per_section_stats.get(section, {})
    panel_html = _render_panel(
        c,
        cells,
        idx_str,
        target=target,
        section=section,
        data=data,
        sec_data=sec_data,
        active_filters=active_filters,
        search_query=search_query,
    )
    return grid_html, block_count, panel_html, sec_stats


def _render_potato_inner(
    c: sqlite3.Cursor,
    target: str,
    section: str,
    active_filters: set[str],
    idx_str: str,
    search_query: str,
    view: str,
    sort_key: str,
    status_filter: str,
    page_str: str,
) -> str:
    targets = resolve_targets(c)
    if not target and targets:
        # The SPA defaults to /api/targets[0]; the dropdown below renders the
        # same list, so both surfaces open on the same target.
        target = targets[0]["id"]

    sections, data = _load_section_data(c, target)
    if not data:
        return (
            '<!DOCTYPE html><html lang="en"><head><meta charset="utf-8">'
            '<meta name="viewport" content="width=device-width, initial-scale=1">'
            f"<title>ReCoverage — no data for {_esc(target)}</title></head>"
            f'<body bgcolor="{BG_COLOR}" text="{TEXT_COLOR}">'
            f'<font face="{MONO_FONT}">'
            '<table width="100%" height="90%" border="0"><tr><td align="center" valign="middle">'
            f"<h1>No data for target {_esc(target)}</h1>"
            f'<p><font color="{MUTED_COLOR}">Pick a built target from '
            '<a href="/potato">Potato Mode</a> or <a href="/">the SPA</a>.</font></p>'
            "</td></tr></table></font></body></html>"
        )

    if section not in sections and sections:
        section = next(iter(sections))

    sec_data: dict[str, Any] = sections.get(section, {})

    search_matched_fns = _search_functions(c, target, search_query)
    filter_btn_data = _build_filter_data(target, section, active_filters, search_query)
    progress = _build_progress(section, sec_data, data, sections)
    section_tab_data = _section_tab_data(
        target, section, sections, active_filters or None, search_query
    )

    # Defaults for whichever view the request selects.
    grid_html = ""
    block_count = 0
    panel_html = ""
    sec_stats: dict[str, Any] = {}
    functions_html = ""
    if view == "functions":
        functions_html = _render_function_list(
            c,
            target,
            section,
            search_query=search_query,
            sort_key=sort_key,
            status_filter=status_filter,
        )
    else:
        grid_html, block_count, panel_html, sec_stats = _render_grid_view(
            c,
            target,
            section,
            sec_data=sec_data,
            sections=sections,
            data=data,
            active_filters=active_filters,
            idx_str=idx_str,
            search_query=search_query,
            search_matched_fns=search_matched_fns,
            page_str=page_str,
        )

    clear_search_url = _build_url(target, section, active_filters or None)

    # The header's [Functions] link is built here, not from `{{target}}` /
    # `{{section}}` in the template: those get HTML-escaped only, so a target
    # or section holding "&" would append attacker-chosen query parameters to
    # this one href.  Every other href in the page goes through _build_url.
    functions_nav_url = f"?target={_url_quote(target)}&section={_url_quote(section)}&view=functions"

    progress_bar_png_uri = _progress_svg(tuple(progress["segments"])) if progress else ""

    db_mtime_str = _db_updated_label()

    return _PAGE_TPL.render(
        # Constants
        BG_COLOR=BG_COLOR,
        PANEL_COLOR=PANEL_COLOR,
        BORDER_COLOR=BORDER_COLOR,
        TEXT_COLOR=TEXT_COLOR,
        MUTED_COLOR=MUTED_COLOR,
        ACCENT_COLOR=ACCENT_COLOR,
        SANS_FONT=SANS_FONT,
        MONO_FONT=MONO_FONT,
        COLORS=COLORS,
        SCANLINE_PNG=SCANLINE_PNG,
        TOPBAR_PNG=TOPBAR_SVG,
        PANEL_HDR_PNG=PANEL_HDR_PNG,
        R_LOGO_SVG=R_LOGO_SVG,
        DOT_PNGS=DOT_PNGS,
        LEGEND_ITEMS=LEGEND_ITEMS,
        # Data
        target=target,
        section=section,
        functions_nav_url=functions_nav_url,
        view=view,
        active_filters=active_filters,
        search_query=search_query,
        search_match_count=len(search_matched_fns),
        clear_search_url=clear_search_url,
        targets=targets,
        section_tab_data=section_tab_data,
        filter_btn_data=filter_btn_data,
        progress=progress,
        progress_bar_png=progress_bar_png_uri,
        ACTIVE_L=ACTIVE_L,
        ACTIVE_R=ACTIVE_R,
        ACTIVE_MID=ACTIVE_MID,
        INACTIVE_L=INACTIVE_L,
        INACTIVE_R=INACTIVE_R,
        INACTIVE_MID=INACTIVE_MID,
        FILTER_ACT_L=FILTER_ACT_L,
        FILTER_ACT_R=FILTER_ACT_R,
        FILTER_ACT_MID=FILTER_ACT_MID,
        FILTER_INACT_L=FILTER_INACT_L,
        FILTER_INACT_R=FILTER_INACT_R,
        FILTER_INACT_MID=FILTER_INACT_MID,
        sec_stats=sec_stats,
        block_count=block_count,
        grid_html=grid_html,
        functions_html=functions_html,
        panel_html=panel_html,
        db_mtime=db_mtime_str,
        version=__version__,
    )


def _panel_base_ctx() -> dict[str, Any]:
    """Fresh template context: defaults for every panel state + color constants."""
    return {
        "has_cell": False,
        "idx": 0,
        "cell_range": "",
        "state_upper": "",
        "state_color": TEXT_COLOR,
        "funcs": [],
        "fn_data": None,
        "gl_data": None,
        "fn_name": "",
        "badge_html": "",
        "detail_rows_html": "",
        "annotations": [],
        "code_html": "",
        "c_heading": "",
        "asm_html": "",
        "asm_heading": "",
        "bytes_html": "",
        "bytes_heading": "",
        "hex_dump_html": "",
        "hex_heading": "",
        "inspector_html": "",
        "gl_detail_rows": "",
        "cell_label": "",
        "parent_function": "",
        "parent_url": "",
        "prev_url": "",
        "next_url": "",
        "target": "",
        "section": "",
        "PANEL_COLOR": PANEL_COLOR,
        "BORDER_COLOR": BORDER_COLOR,
        "MUTED_COLOR": MUTED_COLOR,
        "ACCENT_COLOR": ACCENT_COLOR,
        "COLORS": COLORS,
    }


def _render_original_bytes(raw_bytes: bytes, file_offset: int) -> str:
    """Hex dump of *raw_bytes* as an Original Bytes code block (shared by the
    empty-cell and function-detail panel paths so both stay in one format).

    The dump must NOT be re-wrapped: _format_hex_dump emits fixed-width
    16-byte lines (~78 chars), and _wrap_text(…, 72) split each one mid-row,
    orphaning the |ascii| column on its own line and defeating
    _highlight_hex's line-shape detection (offset/hex/ASCII colouring).
    """
    hex_dump = _format_hex_dump(raw_bytes, file_offset)
    return _code_block_raw(_highlight_hex(hex_dump))


def _panel_empty_cell_bytes(
    ctx: dict[str, Any],
    cell: dict[str, Any],
    sec_data: dict[str, Any] | None,
    target: str,
) -> None:
    """Fill hex dump + data inspector context for a cell with no functions."""
    cell_file_offset = _cell_file_offset(cell, sec_data)
    cell_size = cell.get("end", 0) - cell.get("start", 0)
    if cell_file_offset is None or cell_size <= 0:
        return
    raw_bytes = _get_raw_bytes(cell_file_offset, cell_size, target)
    if not raw_bytes:
        return
    ctx["hex_heading"] = _section_heading("01", ACCENT_BYTES, "Original Bytes")
    ctx["hex_dump_html"] = _render_original_bytes(raw_bytes, cell_file_offset)
    inspector = _format_data_inspector(raw_bytes)
    if inspector:
        ctx["inspector_html"] = inspector


def _panel_fn_attach_verify(c: sqlite3.Cursor, target: str, fn_data: dict[str, Any]) -> None:
    """Attach the latest `rebrew verify -o` record (byte_delta / diff_lines /
    code-similarity) so the detail panel shows verification stats the same
    way the SPA's last_verify does.  Keyed on the function's resolved VA
    (works for both name-form and VA-form cell references).  Best-effort:
    a function with no verify record just omits these rows."""
    fn_va_resolved = fn_data.get("va")
    if fn_va_resolved is None:
        return
    try:
        # Shared projection: the optional v6 columns are probed in ONE place,
        # so the panel's column set cannot drift from the API's.
        c.execute(
            f"{_verify_one_select(c.connection)} FROM verify_results WHERE target=? AND va=?",
            (target, int(fn_va_resolved)),
        )
        vr = c.fetchone()
    except (sqlite3.Error, ValueError, TypeError):
        return
    if not vr:
        return
    fn_data["last_verify_time"] = vr[0]
    if vr[1] is not None:
        fn_data["last_verify_delta"] = f"{vr[1]}B"
    if vr[2] is not None:
        fn_data["last_verify_diff_lines"] = vr[2]
    if vr[3] is not None:
        fn_data["last_verify_similarity"] = f"{vr[3]:.1f}%"
    keys = vr.keys()
    if "reg_delta" in keys and vr["reg_delta"] is not None:
        fn_data["last_verify_reg_delta"] = vr["reg_delta"]
    if "effective_match" in keys and vr["effective_match"]:
        fn_data["last_verify_effective"] = True


def _panel_fn_source_text(data: dict[str, Any], target: str, fn_data: dict[str, Any]) -> str | None:
    """Read the function's C source, or None when unresolvable.

    Path traversal is prevented by resolving and verifying the file stays
    inside the source tree.  Anchored at the PROJECT dir (cwd) — an older
    __file__-relative anchor resolved inside the recoverage package and
    silently failed every C-source load.
    """
    files = fn_data.get("files", [])
    if not files:
        return None
    # A non-object paths value (valid JSON of another type in a foreign DB)
    # would crash .get() below with AttributeError — which escapes
    # handle_potato's except tuple as a raw 500.  Same guard as the summary
    # reads in _compute_section_stats/_build_progress.
    paths = data.get("paths")
    default_source_root = f"/src/{target.lower()}"
    source_root = (
        paths.get("sourceRoot", default_source_root)
        if isinstance(paths, dict)
        else default_source_root
    )
    base = (Path.cwd().resolve() / source_root.lstrip("/")).resolve()
    raw = files[0]
    # Reject absolute paths and parent traversal before resolve
    if Path(raw).is_absolute() or ".." in Path(raw).parts:
        return None
    c_path = (base / raw).resolve()
    if not c_path.is_relative_to(base):
        return None
    try:
        with c_path.open(encoding="utf-8") as f:
            return f.read()
    except (OSError, UnicodeDecodeError):
        _log.debug("Source file not found: %s", c_path)
        return None


def _panel_function_detail(
    ctx: dict[str, Any],
    c: sqlite3.Cursor,
    target: str,
    section: str,
    data: dict[str, Any],
    fn_name: str,
) -> bool:
    """Populate *ctx* from the functions table for *fn_name*.

    Returns False when no function matches, leaving *ctx* untouched so the
    caller can try the globals table.
    """
    # Cell function entries are VA strings ("0x10001000"), matching the SPA's
    # /functions/<va> route; the shared lookup resolves them and falls back to
    # the name for legacy/name-form cells.
    fn_row = _lookup_by_va_or_name(c, "functions", _fn_json_sql(c.connection), target, fn_name)
    if not fn_row:
        return False

    fn_data = json.loads(fn_row[0])
    ctx["fn_data"] = fn_data
    _panel_fn_attach_verify(c, target, fn_data)

    hex_fields = {"va", "fileOffset"}
    skip_fields = {"files", "sha256", "is_thunk", "is_export"}
    if not fn_data.get("blocker"):
        skip_fields.add("blocker")
    if fn_data.get("blockerDelta") is None:
        skip_fields.add("blockerDelta")

    # Badges
    badges: list[str] = []
    if fn_data.get("is_thunk"):
        badges.append(
            f'<font color="{COLORS.get("near_match", "#f59e0b")}"><b>[IAT thunk]</b></font>'
        )
    if fn_data.get("is_export"):
        badges.append(f'<font color="{ACCENT_COLOR}"><b>[Exported]</b></font>')
    badge_html = " ".join(badges)
    if badge_html:
        badge_html += "<br><br>"
    ctx["badge_html"] = badge_html

    def _fn_val(k: str, v: Any, val: str) -> str:
        if k == "vaStart" and v:
            # Same jump contract as the asm address links: carry the address
            # as ?search= so the grid highlights this function's chunk instead
            # of merely switching to .text.
            va_link = _build_url(target, ".text", search=str(v))
            return f'<a href="{va_link}"><font color="{ACCENT_COLOR}">{val}</font></a>'
        # functions.similarity is stored as a 0-1 fraction (schema CHECK); the
        # SPA renders it scaled by 100 with a "%" (app.js), so Potato Mode must
        # too instead of showing the bare fraction.
        if k == "similarity" and isinstance(v, int | float) and not isinstance(v, bool):
            return f"{v * 100:.1f}%"
        return val

    ctx["detail_rows_html"] = _detail_rows(fn_data, skip_fields, hex_fields, _fn_val)

    # Source code + annotations
    files = fn_data.get("files", [])
    code_text = _panel_fn_source_text(data, target, fn_data)
    if code_text:
        ctx["annotations"] = _extract_annotations(code_text)
        ctx["c_heading"] = _section_heading("C", ACCENT_C_SOURCE, f"C Source ({files[0]})")
        ctx["code_html"] = _code_block_raw(_highlight_c(code_text))

    # Assembly (only meaningful for code cells)
    if section == ".text":
        asm_va = fn_data.get("va")
        asm_size = fn_data.get("size")
        asm_file_offset = fn_data.get("fileOffset")
        if (
            HAS_CAPSTONE
            and asm_va is not None
            and asm_size is not None
            and asm_file_offset is not None
        ):
            asm_text = get_disassembly(asm_va, asm_size, asm_file_offset, target)
            if asm_text:
                ctx["asm_heading"] = _section_heading("ASM", ACCENT_ASM, "Assembly")
                ctx["asm_html"] = _code_block_raw(
                    _highlight_asm(_wrap_text(asm_text, 55), target=target)
                )

    # Original Bytes (+ data inspector outside .text, where bytes are data)
    fn_file_offset = fn_data.get("fileOffset")
    fn_size = fn_data.get("size")
    if fn_file_offset is not None and fn_size is not None:
        raw_bytes = _get_raw_bytes(fn_file_offset, fn_size, target)
        if raw_bytes:
            ctx["bytes_heading"] = _section_heading("01", ACCENT_BYTES, "Original Bytes")
            ctx["bytes_html"] = _render_original_bytes(raw_bytes, fn_file_offset)
            if section != ".text":
                inspector = _format_data_inspector(raw_bytes)
                if inspector:
                    ctx["inspector_html"] = inspector
    return True


def _parent_url(
    parent_function: str,
    cells: list[dict[str, Any]],
    target: str,
    section: str,
    active_filters: set[str] | None,
    search_query: str,
) -> str:
    """Where the panel's Parent link goes: the parent's own block, selected.

    The name goes through _build_url, so a C++-mangled name (&, ?, #, spaces)
    cannot truncate the query string the way a hand-written href could.  A
    parent with no cell in this section (it lives elsewhere, or the section
    holds no cells) falls back to searching for it, which still gets the user
    to the function.
    """
    if not parent_function:
        return ""
    for i, candidate in enumerate(cells):
        if parent_function in (candidate.get("functions") or []):
            return _build_url(target, section, active_filters, idx=i, search=search_query) + "#sel"
    return _build_url(target, section, active_filters, search=parent_function)


def _render_panel(
    c: sqlite3.Cursor,
    cells: list[dict[str, Any]],
    idx_str: str,
    target: str,
    section: str,
    data: dict[str, Any],
    sec_data: dict[str, Any] | None = None,
    active_filters: set[str] | None = None,
    search_query: str = "",
) -> str:
    """Render the detail panel HTML (the block below the map)."""
    ctx = _panel_base_ctx()

    if not idx_str:
        return _PANEL_TPL.render(**ctx)

    try:
        idx = int(idx_str)
    except ValueError:
        return _PANEL_TPL.render(**ctx)

    if idx < 0 or idx >= len(cells):
        return _PANEL_TPL.render(**ctx)

    cell = cells[idx]
    state = cell.get("state", "none")
    funcs = cell.get("functions", [])
    # NULL va (file-unbacked .bss) falls back to 0: same guard as the grid
    # builder, so the panel's range row renders relative offsets instead of
    # raising TypeError on None + int.
    sec_va = (sec_data or {}).get("va") or 0

    prev_url = (
        _build_url(target, section, active_filters, idx=max(0, idx - 1), search=search_query)
        + "#sel"
        if idx > 0
        else ""
    )
    next_url = (
        _build_url(target, section, active_filters, idx=idx + 1, search=search_query) + "#sel"
        if idx < len(cells) - 1
        else ""
    )

    ctx.update(
        {
            "has_cell": True,
            "idx": idx,
            "cell_range": f"{hex(sec_va + cell.get('start', 0))} .. {hex(sec_va + cell.get('end', 0))}",
            "state_upper": state.upper(),
            "state_color": COLORS.get(state, TEXT_COLOR),
            "funcs": funcs,
            "cell_label": cell.get("label", ""),
            "parent_function": cell.get("parent_function", ""),
            "parent_url": _parent_url(
                cell.get("parent_function", ""),
                cells,
                target,
                section,
                active_filters,
                search_query,
            ),
            "prev_url": prev_url,
            "next_url": next_url,
            "target": target,
            "section": section,
        }
    )

    if not funcs:
        _panel_empty_cell_bytes(ctx, cell, sec_data, target)
        return _PANEL_TPL.render(**ctx)

    fn_name = funcs[0]
    ctx["fn_name"] = fn_name
    if not _panel_function_detail(ctx, c, target, section, data, fn_name):
        # ── Try globals table ────────────────────────────────────────
        # Same resolution order as the functions lookup above and as
        # GET /functions/<va>: cell entries may name a global by its VA string,
        # so VA candidates first, then the exact name for legacy name-form
        # cells.
        gl_row = _lookup_by_va_or_name(
            c, "globals", _global_json_sql(c.connection), target, fn_name
        )
        if gl_row:
            gl_data = json.loads(gl_row[0])
            ctx["gl_data"] = gl_data
            ctx["gl_detail_rows"] = _detail_rows(gl_data, skip_fields={"files"}, hex_fields=set())
        # else: no function and no global → "Unknown" branch in template

    return _PANEL_TPL.render(**ctx)
