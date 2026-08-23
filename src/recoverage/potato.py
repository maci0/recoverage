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
from urllib.parse import ParseResult, parse_qs
from urllib.parse import quote as _url_quote

from bottle import HTTPResponse, SimpleTemplate  # type: ignore[import-untyped]

from recoverage import __version__
from recoverage._paths import sqlite_ro_uri
from recoverage.server import (
    _FN_JSON_SQL,
    _GLOBAL_JSON_SQL,
    HAS_CAPSTONE,
    VA_MAX,
    _cells_json_rows,
    _db_path,
    _escape_like,
    _evict_oldest,
    _load_dll,
    _load_metadata,
    _snapshot_db_mtime,
    get_disassembly,
    resolve_targets,
)

_log = logging.getLogger("recoverage")

# --- UI Constants ---
COLORS = {
    "exact": "#10b981",
    "reloc": "#0ea5e9",
    "near_match": "#f59e0b",
    "stub": "#ef4444",
    "padding": "#C0C0D4",
    "data": "#8b5cf6",
    "thunk": "#f97316",
    "none": "#3F4958",
}
BG_COLOR = "#0f1216"
PANEL_COLOR = "#151a21"
CODE_BG_COLOR = "#0a0d14"  # darker than panel, matches --code-bg rgba(0,0,0,0.26) on #0f1216
BORDER_COLOR = "#1c2a38"  # subtle cyan-tinted dark, matches rgba(6,182,212,0.15) on dark bg
TEXT_COLOR = "#e7edf4"
MUTED_COLOR = "#8b949e"
ACCENT_COLOR = "#06b6d4"
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


# Topbar gradient
def _make_topbar_svg() -> str:
    """Generate a 1x80 vertical gradient SVG data URI for the topbar."""
    svg = (
        '<svg xmlns="http://www.w3.org/2000/svg" width="1" height="80">'
        "<defs>"
        '<linearGradient id="grad" x1="0%" y1="0%" x2="0%" y2="100%">'
        '<stop offset="0%" style="stop-color:#0f1723;stop-opacity:1" />'
        '<stop offset="100%" style="stop-color:#1e293b;stop-opacity:1" />'
        "</linearGradient>"
        "</defs>"
        '<rect width="1" height="80" fill="url(#grad)" />'
        "</svg>"
    )
    return "data:image/svg+xml;base64," + base64.b64encode(svg.encode("utf-8")).decode("utf-8")


TOPBAR_SVG = _make_topbar_svg()

PANEL_HDR_PNG = (
    "data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAAAEAAAAYCAYAAAA7zJfa"
    "AAAAYUlEQVR4nCXEWQJDMABF0buJKhIZRdC5Oux/Zc+H83HI61+k5Sfi/BWxfkSo"
    "m/DTW/jyEq48hRsfYsh3YfNN2HQVJl6ECavowyI6P4vOVdG6SbRDEWc7isZm0Zgk"
    "Tn082gH6xSG4aTtBqgAAAABJRU5ErkJggg=="
)

DOT_PNGS = {
    "exact": (
        "data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAAAgAAAAICAYAAADED76L"
        "AAAALElEQVR4nGNgIBYI7GycKrCz8RMUT8Um+R8NIxRBdaEr+ESSAvxWEHQkPgAA"
        "qPlFacmQSekAAAAASUVORK5CYII="
    ),
    "reloc": (
        "data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAAAgAAAAICAYAAADED76L"
        "AAAALElEQVR4nGNgIBbwLX05lW/py09QPBWb5H80jFAE1YWu4BNJCvBbQdCR+AAA"
        "6iRPqQXnp7YAAAAASUVORK5CYII="
    ),
    "near_match": (
        "data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAAAgAAAAICAYAAADED76L"
        "AAAALElEQVR4nGNgIBZ8ncc99es87k9QPBWb5H80jFAE1YWu4BNJCvBbQdCR+AAA"
        "Q/NP6VPcCMcAAAAASUVORK5CYII="
    ),
    "stub": (
        "data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAAAgAAAAICAYAAADED76L"
        "AAAALElEQVR4nGNgIBa8d3GZ+t7F5RMUT8Um+R8NIxRBdaEr+ESSAvxWEHQkPgAA"
        "tfZLCZAK8p8AAAAASUVORK5CYII="
    ),
    "padding": (
        "data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAAAgAAAAICAYAAADED76L"
        "AAAAE0lEQVR4nGM4cODKf3yYYWQoAACgS9TBQCUYVwAAAABJRU5ErkJggg=="
    ),
    "none": (
        "data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAAAgAAAAICAYAAADED76L"
        "AAAALElEQVR4nGNgIBZoGdlM1TKy+QTFU7FJ/kfDCEVQXegKPpGkAL8VBB2JDwAA"
        "MBQvKdOWrVAAAAAASUVORK5CYII="
    ),
}

# ── Progress bar SVG cache ──────────────────────────────────


@functools.lru_cache(maxsize=256)
def _progress_svg_cached(
    cache_key: tuple[tuple[str, float], ...],
    colors_key: tuple[tuple[str, str], ...],
    width: int,
    height: int,
    radius: int,
) -> str:
    """Inner LRU-cached SVG builder. All args must be hashable."""
    colors = dict(colors_key)
    svg = [
        f'<svg xmlns="http://www.w3.org/2000/svg" width="{width}" height="{height}" viewBox="0 0 {width} {height}">'
        f'<defs><clipPath id="rc"><rect width="{width}" height="{height}" rx="{radius}" ry="{radius}"/></clipPath></defs>'
        f'<rect width="{width}" height="{height}" fill="#1f2937" rx="{radius}" ry="{radius}"/>'
        '<g clip-path="url(#rc)">'
    ]

    current_x = 0.0
    for status, pct in cache_key:
        hex_color = colors.get(status, "#1f2937")
        seg_w = width * pct / 100.0
        if seg_w > 0:
            svg.append(
                f'<rect x="{current_x:.2f}" y="0" width="{seg_w:.2f}" height="{height}" fill="{hex_color}"/>'
            )
        current_x += seg_w

    svg.append("</g></svg>")

    return "data:image/svg+xml;base64," + base64.b64encode("".join(svg).encode("utf-8")).decode(
        "utf-8"
    )


def _make_progress_svg(
    segments: list[tuple[str, float]],
    colors: dict[str, str],
    width: int = 700,
    height: int = 32,
    radius: int = 10,
) -> str:
    """Generate an SVG with colored segments and rounded corners as a data: URI.
    `segments` is a list of (status_key, pct) pairs. LRU-cached (max 256 entries)."""
    return _progress_svg_cached(
        tuple(segments), tuple(sorted(colors.items())), width, height, radius
    )


def _make_pill_caps(height: int, fill_hex: str, border_hex: str | None = None) -> tuple[str, str]:
    """Generate left-cap and right-cap SVG data URIs for a pill shape."""
    radius = height // 2

    def _uri(svg: str) -> str:
        return "data:image/svg+xml;base64," + base64.b64encode(svg.encode("utf-8")).decode("utf-8")

    if border_hex:
        r = radius - 0.5
        h1 = height - 0.5
        left_svg = f'<svg xmlns="http://www.w3.org/2000/svg" width="{radius}" height="{height}" viewBox="0 0 {radius} {height}"><path d="M{radius},0.5 A{r},{r} 0 0,0 {radius},{h1}" fill="{fill_hex}" stroke="{border_hex}" stroke-width="1"/></svg>'
        right_svg = f'<svg xmlns="http://www.w3.org/2000/svg" width="{radius}" height="{height}" viewBox="0 0 {radius} {height}"><path d="M0,0.5 A{r},{r} 0 0,1 0,{h1}" fill="{fill_hex}" stroke="{border_hex}" stroke-width="1"/></svg>'
    else:
        left_svg = f'<svg xmlns="http://www.w3.org/2000/svg" width="{radius}" height="{height}" viewBox="0 0 {radius} {height}"><path d="M{radius},0 A{radius},{radius} 0 0,0 {radius},{height}" fill="{fill_hex}"/></svg>'
        right_svg = f'<svg xmlns="http://www.w3.org/2000/svg" width="{radius}" height="{height}" viewBox="0 0 {radius} {height}"><path d="M0,0 A{radius},{radius} 0 0,1 0,{height}" fill="{fill_hex}"/></svg>'

    return _uri(left_svg), _uri(right_svg)


def _make_pill_mid_tile(height: int, fill_hex: str, border_hex: str) -> str:
    """Generate a 1px-wide tile SVG with top/bottom border and fill.
    Used as background for the middle cell of a pill."""
    h1 = height - 1
    svg = f'<svg xmlns="http://www.w3.org/2000/svg" width="1" height="{height}" viewBox="0 0 1 {height}">'
    svg += f'<rect x="0" y="0" width="1" height="{height}" fill="{fill_hex}"/>'
    svg += f'<rect x="0" y="0" width="1" height="1" fill="{border_hex}"/>'
    svg += f'<rect x="0" y="{h1}" width="1" height="1" fill="{border_hex}"/>'
    svg += "</svg>"
    return "data:image/svg+xml;base64," + base64.b64encode(svg.encode("utf-8")).decode("utf-8")


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

LEGEND_ITEMS = [
    ("none", "undocumented"),
    ("exact", "exact"),
    ("reloc", "reloc"),
    ("near_match", "near-match"),
    ("stub", "stub"),
    ("padding", "padding"),
]


# --- HTML Helpers ---


def _hex_logo_svg(label: str, color: str) -> str:
    """Generate a hex-shaped SVG logo as a base64 data-URI image tag."""
    font_size = 26 if len(label) > 2 else 42
    svg = (
        f'<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 100 100" width="20" height="20">'
        f'<polygon points="50,5 90,27.5 90,72.5 50,95 10,72.5 10,27.5"'
        f' fill="{color}" fill-opacity="0.15" stroke="{color}"'
        f' stroke-width="6" stroke-linejoin="round"/>'
        f'<text x="50" y="54" dominant-baseline="middle" text-anchor="middle"'
        f' fill="{color}" font-family="monospace" font-weight="800"'
        f' font-size="{font_size}">{label}</text></svg>'
    )
    b64 = base64.b64encode(svg.encode("utf-8")).decode("utf-8")
    return (
        f'<img src="data:image/svg+xml;base64,{b64}"'
        f' width="20" height="20" border="0" alt="{label}">'
    )


def _section_heading(label: str, color: str, title: str) -> str:
    """Render a section heading with a hex logo + title text."""
    logo = _hex_logo_svg(label, color)
    return (
        f'<table border="0" cellpadding="0" cellspacing="4"><tr>'
        f'<td valign="middle">{logo}</td>'
        f'<td valign="middle">'
        f'<h2><font size="3">{title}</font></h2>'
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
    skip_fields: set[str] | tuple[str, ...] = (),
    hex_fields: set[str] | tuple[str, ...] = (),
    val_fn: Callable[[str, Any, str], str] | None = None,
) -> str:
    """Generate <tr> rows for a key-value detail table."""
    rows: list[str] = []
    for k, v in data_dict.items():
        if k in skip_fields:
            continue
        if k in hex_fields:
            val = _esc(_format_va(v))
        else:
            sv = str(v)
            val = _esc(wrap_text(sv, 40)) if len(sv) > 40 else _esc(sv)
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
def _pygments_available() -> bool:
    """Check if pygments is available (lazy, cached)."""
    # find_spec imports only the parent package; a missing pygments raises
    # ModuleNotFoundError (an ImportError) exactly like the old probe import.
    try:
        return importlib.util.find_spec("pygments.lexers") is not None
    except ImportError:
        return False


@functools.lru_cache(maxsize=1)
def _get_c_colors() -> dict[Any, str]:
    from pygments.token import (  # type: ignore[import-untyped]
        Comment,
        Keyword,
        Name,
        Number,
        Operator,
        Punctuation,
        String,
    )

    return {
        Comment: "#6a9955",
        Comment.Preproc: "#c586c0",
        Keyword: "#569cd6",
        Keyword.Type: "#4ec9b0",
        String: "#ce9178",
        Number: "#b5cea8",
        Name.Function: "#dcdcaa",
        Operator: "#d4d4d4",
        Punctuation: "#d4d4d4",
    }


@functools.lru_cache(maxsize=1)
def _get_asm_colors() -> dict[Any, str]:
    from pygments.token import (  # type: ignore[import-untyped]
        Comment,
        Keyword,
        Name,
        Number,
        Operator,
        Punctuation,
        String,
    )

    return {
        Comment: "#6a9955",
        Keyword: "#569cd6",
        Keyword.Type: "#4ec9b0",
        Name.Builtin: "#dcdcaa",
        Name.Function: "#dcdcaa",
        Name.Label: "#9cdcfe",
        Name.Variable: "#9cdcfe",
        Number: "#b5cea8",
        Number.Hex: "#b5cea8",
        Number.Integer: "#b5cea8",
        Operator: "#d4d4d4",
        Punctuation: "#d4d4d4",
        String: "#ce9178",
    }


@functools.lru_cache(maxsize=1)
def _get_c_lexer() -> Any:
    from pygments.lexers import CLexer  # type: ignore[import-untyped]

    return CLexer()


@functools.lru_cache(maxsize=1)
def _get_nasm_lexer() -> Any:
    from pygments.lexers import NasmLexer  # type: ignore[import-untyped]

    return NasmLexer()


_HEX_ADDR_RE = re.compile(r"0x[0-9a-f]{8}")


def _highlight_c(code: str) -> str:
    """Syntax-highlight C code using Pygments tokens and <font> tags (no CSS)."""
    if not _pygments_available():
        return _html_escape(code)

    return _highlight_tokens(_get_c_lexer().get_tokens(code), _get_c_colors())


def _highlight_asm(text: str, target: str = "") -> str:
    """Syntax-highlight x86 assembly using Pygments tokens and <font> tags (no CSS)."""

    def _addr_link(addr: str) -> str:
        return (
            f'<a href="?target={_url_quote(target)}&search={_url_quote(addr.strip())}">'
            f'<font color="#858585">{_html_escape(addr)}</font></a>'
        )

    def _link_hex_refs(html: str) -> str:
        if not target:
            return html

        return _HEX_ADDR_RE.sub(
            lambda m: (
                f'<a href="?target={_url_quote(target)}&search={_url_quote(m.group(0))}">'
                f"{m.group(0)}</a>"
            ),
            html,
        )

    if not _pygments_available():
        if target:
            lines = []
            for line in text.splitlines():
                if line.startswith("0x") and "  " in line:
                    addr_end = line.index("  ")
                    addr_part, code_part = line[:addr_end], line[addr_end:]
                    linked_code = _link_hex_refs(_html_escape(code_part))
                    lines.append(_addr_link(addr_part) + linked_code)
                else:
                    lines.append(_link_hex_refs(_html_escape(line)))
            return "\n".join(lines)
        return _html_escape(text)

    colors = _get_asm_colors()
    lexer = _get_nasm_lexer()
    result_lines: list[str] = []
    for line in text.splitlines():
        if line.startswith("0x") and "  " in line:
            addr_end = line.index("  ")
            addr_part, code_part = line[:addr_end], line[addr_end:]
            hl = _link_hex_refs(_highlight_tokens(lexer.get_tokens(code_part), colors).rstrip("\n"))
            if target:
                result_lines.append(_addr_link(addr_part) + hl)
            else:
                result_lines.append(f'<font color="#858585">{_html_escape(addr_part)}</font>' + hl)
        else:
            result_lines.append(_link_hex_refs(_html_escape(line)))
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


def wrap_text(text: str, width: int = 45) -> str:
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


def _format_hex_dump(raw_bytes: bytes, base_offset: int = 0, max_bytes: int = 256) -> str:
    """Format raw bytes as a classic hex dump (16 bytes per line)."""
    data = raw_bytes[:max_bytes]
    lines: list[str] = []
    for i in range(0, len(data), 16):
        chunk = data[i : i + 16]
        offset = f"{base_offset + i:08x}"
        hex_left = " ".join(f"{b:02x}" for b in chunk[:8])
        hex_right = " ".join(f"{b:02x}" for b in chunk[8:])
        ascii_repr = "".join(chr(b) if 32 <= b < 127 else "." for b in chunk)
        lines.append(f"{offset}  {hex_left:<23s}  {hex_right:<23s}  |{ascii_repr}|")
    if len(raw_bytes) > max_bytes:
        lines.append(f"... ({len(raw_bytes) - max_bytes} more bytes)")
    return "\n".join(lines)


_MAX_RAW_READ = 1 << 20  # 1 MiB — more than any plausible function or data cell


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
        _section_heading("{}", "#a855f7", "Data Inspector")
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

    null_terminated = b[:64].split(b"\x00")[0] if b[:64] else b""
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
    sec_file_offset = sec_data.get("fileOffset", 0)
    if not sec_file_offset:
        return None
    return sec_file_offset + cell.get("start", 0)


def _format_va(val: int | str) -> str:
    """Format a VA value as hex string."""
    if isinstance(val, int):
        return f"0x{val:08x}"
    s = str(val)
    if s.startswith("0x") or s.startswith("0X"):
        return s
    try:
        return f"0x{int(s):08x}"
    except (ValueError, TypeError):
        return s


def _build_url(
    target: str,
    section: str,
    filters: set[str] | None = None,
    idx: int | None = None,
    search: str | None = None,
    page: int | None = None,
) -> str:
    """Build a potato URL with the given parameters."""
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

<!-- Top Bar -->
<table id="topbar" width="100%" border="0" cellpadding="4" cellspacing="0" background="{{TOPBAR_PNG}}">
  <tr>
    <td valign="middle">
      <table id="logo" border="0" cellpadding="0" cellspacing="0">
        <tr>
          <td><img src="{{R_LOGO_SVG}}" width="48" height="32" border="0" alt="R"></td>
          <td valign="middle"><h1><a href="/"><font face="{{MONO_FONT}}" size="5" color="{{TEXT_COLOR}}">&nbsp;<b>ReCoverage</b></font></a></h1>&nbsp;<a href="/"><font face="{{MONO_FONT}}" size="1" color="{{MUTED_COLOR}}">[SPA]</font></a>&nbsp;<a href="?target={{target}}&section={{section}}&view=functions"><font face="{{MONO_FONT}}" size="1" color="{{MUTED_COLOR}}">[Functions]</font></a></td>
        </tr>
      </table>
    </td>
    <td valign="middle">
      <table id="section-tabs" border="0" cellpadding="0" cellspacing="4"><tr>
      % for s_name, s_url, s_active, s_pct_str, tab_idx in section_tab_data:
        <td valign="middle">
        % if s_active:
          <table border="0" cellpadding="0" cellspacing="0"><tr><td><img src="{{ACTIVE_L}}" width="16" height="32" border="0" alt=""></td><td background="{{ACTIVE_MID}}" height="32" nowrap><a href="{{s_url}}" accesskey="{{s_name[1]}}"><font face="{{MONO_FONT}}" size="3" color="#ffffff"><b>{{s_name}}</b></font></a></td><td><img src="{{ACTIVE_R}}" width="16" height="32" border="0" alt=""></td></tr></table>
        % else:
          <table border="0" cellpadding="0" cellspacing="0"><tr><td><img src="{{INACTIVE_L}}" width="16" height="32" border="0" alt=""></td><td background="{{INACTIVE_MID}}" height="32" nowrap><a href="{{s_url}}" accesskey="{{s_name[1]}}"><font face="{{MONO_FONT}}" size="3" color="{{MUTED_COLOR}}">{{s_name}}</font></a></td><td><img src="{{INACTIVE_R}}" width="16" height="32" border="0" alt=""></td></tr></table>
        % end
        </td>
      % end
      </tr></table>
    </td>
    % if progress:
    <td valign="middle">
      <table id="progress-bar" width="700" border="0" cellpadding="0" cellspacing="0"><tr>
        <td background="{{progress_bar_png}}" align="center" height="32"><font face="{{MONO_FONT}}" size="3" color="#ffffff"><b>{{progress['sec_size']}}</b>b &middot; <b>{{progress['matched_fn']}}/{{progress['total_fn']}}</b> matched &middot; <b>{{"%.1f" % progress['coverage_pct']}}%</b></font></td>
      </tr></table>
    </td>
    % end
    <td valign="middle" nowrap>
      <table id="controls" border="0" cellpadding="0" cellspacing="2"><tr>
        <td valign="middle">
          <form id="search-form" action="/potato" method="GET"><input type="hidden" name="target" value="{{target}}"><input type="hidden" name="section" value="{{section}}">
          % if active_filters:
            <input type="hidden" name="filter" value="{{','.join(sorted(active_filters))}}">
          % end
          <label for="search-input"><font size="1" color="{{MUTED_COLOR}}">Search:&nbsp;</font></label><input id="search-input" type="text" name="search" size="18" value="{{search_query}}" placeholder="Search VA or name..." accesskey="s"> <input type="submit" value="Go"></form>
          % if search_query:
            <br><font size="1" color="{{ACCENT_COLOR}}">Searching: &quot;{{search_query}}&quot; ({{search_match_count}} matches)</font> <a href="{{clear_search_url}}"><font size="1" color="{{MUTED_COLOR}}">[Clear search]</font></a>
          % end
        </td>
        <td valign="middle">
          <table id="filters" border="0" cellpadding="0" cellspacing="4"><tr>
            % for fb_href, fb_label, fb_color, fb_active, fb_key in filter_btn_data:
              <td valign="middle">
              % if fb_active:
                <table border="0" cellpadding="0" cellspacing="0"><tr><td><img src="{{FILTER_ACT_L}}" width="16" height="32" border="0" alt=""></td><td background="{{FILTER_ACT_MID}}" height="32" nowrap><a href="{{fb_href}}" accesskey="{{fb_label[0].lower()}}"><font face="{{MONO_FONT}}" size="3" color="{{fb_color}}"><b>{{fb_label}}</b></font></a></td><td><img src="{{FILTER_ACT_R}}" width="16" height="32" border="0" alt=""></td></tr></table>
              % else:
                <table border="0" cellpadding="0" cellspacing="0"><tr><td><img src="{{FILTER_INACT_L}}" width="16" height="32" border="0" alt=""></td><td background="{{FILTER_INACT_MID}}" height="32" nowrap><a href="{{fb_href}}" accesskey="{{fb_label[0].lower()}}"><font face="{{MONO_FONT}}" size="3" color="{{fb_color}}">{{fb_label}}</font></a></td><td><img src="{{FILTER_INACT_R}}" width="16" height="32" border="0" alt=""></td></tr></table>
              % end
              </td>
            % end
          </tr></table>
        </td>
        <td valign="middle">
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
      </tr></table>
    </td>
  </tr>
</table>
<table id="topbar-divider" width="100%" border="0" cellpadding="0" cellspacing="0" bgcolor="#1c2a38"><tr><td height="1"></td></tr></table>

<table id="layout" width="100%" border="0" cellpadding="14" cellspacing="0">
  <tr>
    % if view == "functions":
    <td valign="top" width="100%">
      {{!functions_html}}
    </td>
    % else:
    <td valign="top" width="75%">
      <table id="map" width="100%" border="1" cellpadding="0" cellspacing="0" bgcolor="{{PANEL_COLOR}}" bordercolor="{{BORDER_COLOR}}">
        <tr><td id="map-header" background="{{PANEL_HDR_PNG}}" cellpadding="8">&nbsp;<font color="{{MUTED_COLOR}}" size="2"><b>Coverage Map - {{section}}</b></font> <font color="{{MUTED_COLOR}}" size="1"> ({{block_count}} blocks)</font>
        % if sec_stats.get('total', 0) > 0:
          <font face="{{MONO_FONT}}" size="1" color="{{MUTED_COLOR}}"><font color="{{COLORS['exact']}}">E:{{sec_stats['exact']}}</font> <font color="{{COLORS['reloc']}}">R:{{sec_stats['reloc']}}</font> <font color="{{COLORS['near_match']}}">M:{{sec_stats['near_match']}}</font> <font color="{{COLORS['stub']}}">S:{{sec_stats['stub']}}</font> <font color="{{COLORS['padding']}}">P:{{sec_stats.get('padding', 0)}}</font> &#x2502; {{sec_stats['pct']}}% covered</font>
        % end
        </td></tr>
        <tr><td bgcolor="{{PANEL_COLOR}}" cellpadding="8">
          <table id="legend" border="0" cellpadding="0" cellspacing="4"><tr>
          % for leg_key, leg_label in LEGEND_ITEMS:
            <td valign="middle"><img src="{{DOT_PNGS[leg_key]}}" width="12" height="12" border="0" alt=""></td><td valign="middle"><font face="{{MONO_FONT}}" size="1" color="{{MUTED_COLOR}}">{{leg_label}}</font></td>
          % end
          </tr></table>
          <table id="grid-container" border="1" cellpadding="8" cellspacing="0" bordercolor="{{BORDER_COLOR}}" bgcolor="{{BG_COLOR}}" width="100%">
          <caption align="left"><font size="1" color="{{MUTED_COLOR}}">Coverage map - {{section}} ({{block_count}} blocks)</font></caption>
          <tr><td>
          <font size="1"><center>{{!grid_html}}</center></font>
          </td></tr></table>
        </td></tr>
      </table>
    </td>
    <td valign="top" width="25%">
      <table id="panel" width="100%" border="1" cellpadding="0" cellspacing="0" bgcolor="{{PANEL_COLOR}}" bordercolor="{{BORDER_COLOR}}">
        <tr><td id="panel-header" background="{{PANEL_HDR_PNG}}" cellpadding="8">&nbsp;<font color="{{MUTED_COLOR}}" size="2"><b>Block Details</b></font></td></tr>
        <tr><td height="1" bgcolor="{{BORDER_COLOR}}"></td></tr>
        <tr><td id="panel-content" bgcolor="{{PANEL_COLOR}}" cellpadding="14" valign="top">{{!panel_html}}</td></tr>
      </table>
    </td>
    % end
  </tr>
</table>
<table id="footer" width="100%" border="0" cellpadding="8" cellspacing="0"><tr>
<td><font face="{{MONO_FONT}}" size="1" color="{{MUTED_COLOR}}">recoverage v{{version}}
% if db_mtime:
 &middot; DB updated {{db_mtime}}
% end
</font></td>
<td align="right"><font face="{{MONO_FONT}}" size="1" color="{{MUTED_COLOR}}">HTML5</font></td>
</tr></table>
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
<tr><td bgcolor="{{PANEL_COLOR}}"><font size="1" color="{{MUTED_COLOR}}"><b>Parent:</b></font></td><td bgcolor="{{PANEL_COLOR}}"><font face="Courier New, monospace" size="1"><a href="?target={{target}}&section={{section}}&search={{parent_function}}"><font color="{{ACCENT_COLOR}}">{{parent_function}}</font></a></font></td></tr>
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


def render_potato(parsed_url: ParseResult) -> str:
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
        conn = sqlite3.connect(sqlite_ro_uri(db_path), uri=True)
    except sqlite3.Error:
        _log.warning("Potato mode: database unavailable at %s", db_path)
        # Signal failure, not a 200 page: monitoring and scripts must see the
        # DB outage (same contract as the API's 503 db_unavailable).
        raise HTTPResponse(
            status=503,
            body=(
                '<html><body bgcolor="#0f1216" text="#e7edf4">'
                "Database unavailable — run 'rebrew catalog --json &amp;&amp; "
                "rebrew build-db' to create it.</body></html>"
            ),
            headers={"Content-Type": "text/html; charset=utf-8", "Cache-Control": "no-store"},
        ) from None

    with contextlib.closing(conn):
        c = conn.cursor()
        return _render_potato_inner(
            c,
            target,
            section,
            active_filters,
            idx_str,
            search_query,
            view,
            sort_key,
            status_filter,
            page_str,
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

    for sec_name, cells_json in _load_cells_cached(c, target):
        if sec_name in sections:
            sections[sec_name]["cells"] = json.loads(cells_json)
    return sections, data


# Potato mode fetches ALL cells for the target (json_group_array over the
# whole cells table) on every page render — each filter toggle or sort
# re-fetches the multi-MB payload.  Memoize per DB fingerprint: a rebuild
# changes the WAL-aware snapshot (mtime_ns/size incl. -wal — raw main-file
# mtime missed WAL-committed rebuilds) so the cache self-invalidates, no
# explicit clear needed.  The JSON string is immutable, so sharing it across
# requests is safe (json.loads per request is cheap relative to the SQL
# aggregation).
_POTATO_CELLS_CACHE: dict[tuple[int, int, str], list[tuple[str, str]]] = {}
_POTATO_CELLS_CACHE_LOCK = threading.Lock()
# Upper bound on retained payloads across rebuilds (multi-MB per entry).
_POTATO_CELLS_CACHE_MAX = 4


def clear_cells_cache() -> None:
    """Clear the memoized potato cells payloads (called on DB rebuild)."""
    with _POTATO_CELLS_CACHE_LOCK:
        _POTATO_CELLS_CACHE.clear()


def _load_cells_cached(c: sqlite3.Cursor, target: str) -> list[tuple[str, str]]:
    """Return [(section_name, cells_json), ...] for *target*, memoized."""
    snap = _snapshot_db_mtime()
    fingerprint: tuple[int, int, str] | None = (*snap, target) if snap is not None else None
    if fingerprint is not None:
        with _POTATO_CELLS_CACHE_LOCK:
            cached = _POTATO_CELLS_CACHE.get(fingerprint)
        if cached is not None:
            return cached

    rows = [(str(row[0]), str(row[1])) for row in _cells_json_rows(c, target)]

    if fingerprint is not None:
        with _POTATO_CELLS_CACHE_LOCK:
            _evict_oldest(_POTATO_CELLS_CACHE, _POTATO_CELLS_CACHE_MAX)
            _POTATO_CELLS_CACHE[fingerprint] = rows
    return rows


def _compute_section_stats(
    c: sqlite3.Cursor,
    target: str,
    sections: dict[str, dict[str, Any]],
    data: dict[str, Any],
) -> dict[str, dict[str, int]]:
    per_section_stats: dict[str, dict[str, int]] = {}
    summary = data.get("summary", {})
    c.execute(
        "SELECT section_name, total_cells, exact_count, reloc_count, "
        "near_match_count, stub_count, padding_count FROM section_cell_stats WHERE target = ?",
        (target,),
    )
    for row in c.fetchall():
        sec_name_r, s_total, s_exact, s_reloc, s_near_match, s_stub, s_padding = row
        sec_summary_entry = summary.get(sec_name_r, summary)
        s_covered_bytes = sec_summary_entry.get("coveredBytes", 0)
        s_sec_size = sections.get(sec_name_r, {}).get("size", 0)
        s_pct = int((s_covered_bytes / s_sec_size) * 100) if s_sec_size > 0 else 0
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


def _search_functions(c: sqlite3.Cursor, target: str, search_query: str) -> set[str]:
    search_matched_fns: set[str] = set()
    if not search_query:
        return search_matched_fns

    like_pat = _escape_like(search_query)
    # ORDER BY makes the 500-row cap deterministic (SQLite scan order is
    # otherwise arbitrary for >500 matches).
    c.execute(
        "SELECT name, vaStart FROM functions WHERE target = ? AND ("
        "name LIKE ? ESCAPE '\\' OR vaStart LIKE ? ESCAPE '\\' "
        "OR symbol LIKE ? ESCAPE '\\') ORDER BY name, vaStart LIMIT 500",
        (target, like_pat, like_pat, like_pat),
    )
    for name, va_start in c.fetchall():
        search_matched_fns.add(name)
        if va_start:
            # Grid .text cells store the function's vaStart string (not the
            # name) in their `functions` field — the dimming test compares
            # cell entries against this set, so VA spellings must be included.
            search_matched_fns.add(va_start)
    c.execute(
        "SELECT name FROM globals WHERE target = ? AND ("
        "name LIKE ? ESCAPE '\\' OR printf('0x%x', va) LIKE ? ESCAPE '\\') LIMIT 500",
        (target, like_pat, like_pat),
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
    sec_size = sec_data.get("size", 0)
    sec_summ = summary.get(section, summary)
    covered_bytes = sec_summ.get("coveredBytes", 0)
    total_fn = sec_summ.get("totalFunctions", 0)
    exact_matches = sec_summ.get("exactMatches", 0)
    reloc_matches = sec_summ.get("relocMatches", 0)
    near_match_matches = sec_summ.get("nearMatchCount", 0)
    stub_matches = sec_summ.get("stubCount", 0)
    matched_fn = exact_matches + reloc_matches  # NEAR_MATCHING/STUB are not matched

    if section == ".text" and total_fn > 0:
        seg_exact = exact_matches / total_fn * 100
        seg_reloc = reloc_matches / total_fn * 100
        seg_near_match = near_match_matches / total_fn * 100
        seg_stub = stub_matches / total_fn * 100
    elif sec_size > 0:
        seg_exact = sec_summ.get("exactBytes", 0) / sec_size * 100
        seg_reloc = sec_summ.get("relocBytes", 0) / sec_size * 100
        seg_near_match = sec_summ.get("nearMatchBytes", 0) / sec_size * 100
        seg_stub = sec_summ.get("stubBytes", 0) / sec_size * 100
    else:
        seg_exact = seg_reloc = seg_near_match = seg_stub = 0

    padding_bytes = sec_summ.get("paddingBytes", 0)
    seg_padding = (padding_bytes / sec_size * 100) if sec_size > 0 else 0
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
    merged_cells: list[dict[str, Any]] = []
    if not cells:
        return merged_cells

    curr_cell: dict[str, Any] = dict(cells[0])
    curr_cell["orig_idx"] = 0
    curr_col: int = int(curr_cell.get("span", 1))

    for i, next_c in enumerate(cells[1:], 1):
        n_span = int(next_c.get("span", 1))
        if (
            curr_cell.get("state") not in ("none", None)
            and next_c.get("state") == curr_cell.get("state")
            and next_c.get("functions") == curr_cell.get("functions")
            and curr_col + n_span <= grid_columns
        ):
            curr_cell["span"] = curr_cell.get("span", 1) + n_span
            curr_cell["end"] = next_c.get("end")
            curr_col += n_span
            continue

        merged_cells.append(curr_cell)
        curr_cell = dict(next_c)
        curr_cell["orig_idx"] = i
        curr_col = n_span if curr_col >= grid_columns else curr_col + n_span

    merged_cells.append(curr_cell)
    return merged_cells


# One page of grid is this many rows × the section's column count (~2k cells at
# 64 columns, ~700 KB of table markup).  Potato Mode exists for clients that
# cannot run the SPA, and those are the last clients that should be handed a
# 7 MB response with 74k DOM nodes.
_GRID_PAGE_ROWS = 32


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
        for pos, cell in enumerate(merged_cells):
            if cell.get("orig_idx") == idx:
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
) -> str:
    """Render the coverage grid as an HTML table.

    grid_columns controls the number of cells per row. A sizing row of
    transparent cells is emitted first so the browser allocates uniform
    column widths regardless of colspan usage in data rows.
    """
    if grid_columns <= 0:
        raise ValueError(f"grid_columns must be positive, got {grid_columns}")
    cell_w = 18
    cell_h = 15
    sizing_tds = "".join(
        f'<td bgcolor="{BG_COLOR}" width="{cell_w}" height="1"></td>' for _ in range(grid_columns)
    )
    grid_html_parts = [
        f'<table id="grid" border="1" frame="void" rules="all" cellpadding="0" cellspacing="0" bordercolor="{BG_COLOR}" bgcolor="{BG_COLOR}">'
        f"<tr>{sizing_tds}</tr><tr>"
    ]

    curr_col = 0
    sec_va = sec_data.get("va", 0)
    for i, cell in enumerate(merged_cells):
        span = cell.get("span", 1)
        orig_idx = cell.get("orig_idx", i)
        if curr_col >= grid_columns:
            grid_html_parts.append("</tr><tr>")
            curr_col = 0

        state = cell.get("state", "none")

        dimmed = (active_filters and state != "none" and state not in active_filters) or (
            search_query and not any(fn in search_matched_fns for fn in cell.get("functions", []))
        )
        bgcolor = BG_COLOR if dimmed else COLORS.get(state, COLORS["none"])
        try:
            selected = int(idx_str) == orig_idx
        except (ValueError, OverflowError):
            selected = False
        link = _build_url(
            target, section, active_filters or None, idx=orig_idx, search=search_query
        )
        funcs = cell.get("functions", [])
        title = (
            f"{hex(sec_va + cell.get('start', 0))}..{hex(sec_va + cell.get('end', 0))} | {state}"
        )
        if funcs:
            title += f" | {funcs[0]}"
        # The alt text IS the link's accessible name here, so it carries the
        # same address range the title does.  With state alone, thousands of
        # links announced as "none" with no way to tell them apart (WCAG 2.4.4).
        alt_text = title
        w = cell_w * span
        img = (
            f'<a href="{link}" title="{_esc(title)}">'
            f'<img src="{TRANSPARENT_GIF}" width="{w}" height="{cell_h}" border="0" alt="{_esc(alt_text)}"></a>'
        )

        if selected:
            sel_img = (
                f'<a href="{link}" title="{_esc(title)}">'
                f'<img src="{TRANSPARENT_GIF}" width="{w - 2}" height="{cell_h - 2}" border="0" alt="{_esc(alt_text)}">'
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

    remaining = int(grid_columns) - curr_col
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

    where = ["target = ?"]
    params: list[Any] = [target]
    if status_filter:
        where.append("status = ?")
        params.append(status_filter)
    if search_query:
        like = _escape_like(search_query)
        where.append(
            "(name LIKE ? ESCAPE '\\' OR symbol LIKE ? ESCAPE '\\' OR printf('0x%x', va) LIKE ? ESCAPE '\\')"
        )
        params.extend([like, like, like])

    where_sql = " AND ".join(where)
    # Cap the rendered list at 500 rows (matching the API's search cap) so a
    # large project's ?view=functions page doesn't build a multi-MB HTML
    # document on every request.  ORDER BY keeps the cap deterministic.
    c.execute(
        "SELECT name, va, vaStart, size, status, module FROM functions "
        f"WHERE {where_sql} ORDER BY {order_by}, va LIMIT 500",
        params,
    )
    rows = c.fetchall()

    base = f"?target={_url_quote(target)}&section={_url_quote(section)}&view=functions"
    if search_query:
        base += f"&search={_url_quote(search_query)}"
    if status_filter:
        base += f"&status={_url_quote(status_filter)}"

    parts = [
        f'<table width="100%" border="1" cellpadding="0" cellspacing="0" bordercolor="{BORDER_COLOR}" bgcolor="{PANEL_COLOR}">',
        f'<tr><td background="{PANEL_HDR_PNG}" cellpadding="8">'
        f'<font color="{MUTED_COLOR}" size="2"><b>Functions</b></font> '
        f'<font size="1" color="{MUTED_COLOR}">({len(rows)} results)</font> '
        f'<a href="{_build_url(target, section, search=search_query)}"><font size="1" color="{ACCENT_COLOR}">[Grid View]</font></a>'
        f"</td></tr>",
        "<tr><td>",
        f'<table width="100%" border="1" cellpadding="6" cellspacing="0" bordercolor="{BORDER_COLOR}">',
        f'<caption align="left"><font size="1" color="{MUTED_COLOR}">Functions for {_esc(section)} ({len(rows)} results)</font></caption>',
        f'<tr bgcolor="{PANEL_COLOR}">'
        f'<th><a href="{base}&sort=name"><font color="{MUTED_COLOR}">Name</font></a></th>'
        f'<th><a href="{base}&sort=va"><font color="{MUTED_COLOR}">VA</font></a></th>'
        f'<th><a href="{base}&sort=size"><font color="{MUTED_COLOR}">Size</font></a></th>'
        f'<th><a href="{base}&sort=status"><font color="{MUTED_COLOR}">Status</font></a></th>'
        f'<th><font color="{MUTED_COLOR}">Origin</font></th></tr>',
    ]

    if not rows:
        parts.append(
            f'<tr><td colspan="5"><font color="{MUTED_COLOR}">No functions found.</font></td></tr>'
        )
    else:
        for name, va, _, size, status, module in rows:
            st = status or "none"
            color = COLORS.get(st.lower(), TEXT_COLOR)
            name_link = f"?target={_url_quote(target)}&section=.text&search={_url_quote(name)}"
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
    per_section_stats: dict[str, dict[str, int]],
    active_filters: set[str] | None,
    search_query: str,
) -> list[tuple[str, str, bool, str, str]]:
    """(name, url, is_active, pct-label, accesskey-index) for the section tabs."""
    return [
        (
            s,
            _build_url(target, s, active_filters or None, search=search_query),
            s == section,
            (
                f" {per_section_stats.get(s, {}).get('pct', 0)}%"
                if per_section_stats.get(s, {}).get("total", 0) > 0
                else ""
            ),
            str(i),
        )
        for i, s in enumerate(sections, 1)
    ]


def _render_potato_inner(
    c: sqlite3.Cursor,
    target: str,
    section: str,
    active_filters: set[str],
    idx_str: str,
    search_query: str,
    view: str = "",
    sort_key: str = "va",
    status_filter: str = "",
    page_str: str = "",
) -> str:
    target_ids, targets = resolve_targets(c)
    if not target and target_ids:
        target = target_ids[0]

    sections, data = _load_section_data(c, target)
    if not data:
        return (
            f'<html><body bgcolor="#0f1216" text="#ffffff">'
            f"No data for target {_esc(target)}</body></html>"
        )

    if section not in sections and sections:
        section = next(iter(sections))

    sec_data: dict[str, Any] = sections.get(section, {})
    cells = sec_data.get("cells", [])

    search_matched_fns = _search_functions(c, target, search_query)
    per_section_stats = _compute_section_stats(c, target, sections, data)
    filter_btn_data = _build_filter_data(target, section, active_filters, search_query)
    progress = _build_progress(section, sec_data, data, sections)
    section_tab_data = _section_tab_data(
        target, section, sections, per_section_stats, active_filters or None, search_query
    )

    # ── Grid (with cell merging) ─────────────────────────────────
    functions_html = ""
    if view == "functions":
        grid_html = ""
        block_count = 0
        panel_html = ""
        sec_stats = {}
        functions_html = _render_function_list(
            c,
            target,
            section,
            search_query,
            sort_key,
            status_filter,
        )
    else:
        grid_columns = sec_data.get("columns", 64)
        if grid_columns <= 0:
            grid_columns = 64
        merged_cells = _merge_cells(cells, grid_columns)
        block_count = len(merged_cells)

        # Paginate: a real .text section is ~25k cells, which is ~7 MB of table
        # markup and ~74k DOM nodes — punishing on exactly the weak clients this
        # mode exists for.  One page is _GRID_PAGE_ROWS rows of the grid.
        page_cells = _GRID_PAGE_ROWS * grid_columns
        page_count = max(1, -(-block_count // page_cells))
        page = _grid_page(page_str, idx_str, merged_cells, page_cells, page_count)
        page_slice = merged_cells[(page - 1) * page_cells : page * page_cells]

        grid_html = _build_grid_html(
            page_slice,
            sec_data,
            grid_columns,
            active_filters,
            search_query,
            search_matched_fns,
            idx_str,
            target,
            section,
        )
        if page_count > 1:
            grid_html += _pager_html(
                target, section, active_filters, search_query, page, page_count
            )
        sec_stats = per_section_stats.get(section, {})
        panel_html = _render_panel(
            c,
            cells,
            idx_str,
            target,
            section,
            data,
            sec_data,
            active_filters,
            search_query,
        )

    clear_search_url = _build_url(target, section, active_filters or None)

    progress_bar_png_uri = ""
    if progress:
        progress_bar_png_uri = _make_progress_svg(progress["segments"], COLORS)

    db_mtime_str = ""
    try:
        mtime = _db_path().stat().st_mtime
        db_mtime_str = datetime.fromtimestamp(mtime, tz=UTC).strftime("%Y-%m-%d %H:%M UTC")
    except OSError:
        pass

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
    empty-cell and function-detail panel paths so both stay in one format)."""
    hex_dump = _format_hex_dump(raw_bytes, file_offset)
    return _code_block_raw(_highlight_hex(wrap_text(hex_dump, 72)))


def _panel_empty_cell_bytes(
    ctx: dict[str, Any],
    cell: dict[str, Any],
    sec_data: dict[str, Any] | None,
    target: str,
) -> None:
    """Fill hex dump + data inspector context for a cell with no functions."""
    cell_file_offset = _cell_file_offset(cell, sec_data)
    cell_size = cell.get("end", 0) - cell.get("start", 0)
    if not cell_file_offset or cell_size <= 0:
        return
    raw_bytes = _get_raw_bytes(cell_file_offset, cell_size, target)
    if not raw_bytes:
        return
    ctx["hex_heading"] = _section_heading("01", "#10b981", "Original Bytes")
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
        c.execute(
            "SELECT verified_at, byte_delta, diff_lines, similarity"
            " FROM verify_results WHERE target=? AND va=?",
            (target, int(fn_va_resolved)),
        )
        vr = c.fetchone()
    except (sqlite3.Error, ValueError, TypeError):
        vr = None
    if not vr:
        return
    fn_data["last_verify_time"] = vr[0]
    if vr[1] is not None:
        fn_data["last_verify_delta"] = f"{vr[1]}B"
    if vr[2] is not None:
        fn_data["last_verify_diff_lines"] = vr[2]
    if vr[3] is not None:
        fn_data["last_verify_similarity"] = f"{vr[3]:.1f}%"


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
    source_root = data.get("paths", {}).get("sourceRoot", f"/src/{target.lower()}")
    base = (Path.cwd().resolve() / source_root.lstrip("/")).resolve()
    c_path = (base / files[0]).resolve()
    if not c_path.is_relative_to(base):
        return None
    try:
        with open(c_path, encoding="utf-8") as f:
            return f.read()
    except OSError:
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
    # /functions/<va> route — parse hex and look up by va; fall back to name
    # for legacy/name-form cells.  Out-of-range ints are treated as
    # non-numeric: SQLite INTEGER tops out at signed 64-bit, and passing a
    # bigger Python int raises OverflowError at execute time.
    try:
        fn_va = int(fn_name, 0)
        is_numeric = 0 <= fn_va <= VA_MAX
    except ValueError:
        is_numeric = False

    fn_sql = "SELECT " + _FN_JSON_SQL + " FROM functions WHERE target=? AND "
    if is_numeric:
        c.execute(fn_sql + "va=?", (target, fn_va))
    else:
        c.execute(fn_sql + "name=?", (target, fn_name))
    fn_row = c.fetchone()
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
            va_link = _build_url(target, ".text")
            return f'<a href="{va_link}"><font color="{ACCENT_COLOR}">{val}</font></a>'
        return val

    ctx["detail_rows_html"] = _detail_rows(fn_data, skip_fields, hex_fields, _fn_val)

    # Source code + annotations
    files = fn_data.get("files", [])
    code_text = _panel_fn_source_text(data, target, fn_data)
    if code_text:
        ctx["annotations"] = _extract_annotations(code_text)
        ctx["c_heading"] = _section_heading("C", "#3b82f6", f"C Source ({_esc(files[0])})")
        ctx["code_html"] = _code_block_raw(_highlight_c(code_text))

    # Assembly (only meaningful for code cells)
    if section == ".text":
        asm_va = fn_data.get("va")
        asm_size = fn_data.get("size")
        asm_file_offset = fn_data.get("fileOffset")
        if HAS_CAPSTONE and asm_va and asm_size and asm_file_offset:
            asm_text = get_disassembly(asm_va, asm_size, asm_file_offset, target)
            if asm_text:
                ctx["asm_heading"] = _section_heading("ASM", "#ef4444", "Assembly")
                ctx["asm_html"] = _code_block_raw(
                    _highlight_asm(wrap_text(asm_text, 55), target=target)
                )

    # Original Bytes (+ data inspector outside .text, where bytes are data)
    fn_file_offset = fn_data.get("fileOffset")
    fn_size = fn_data.get("size")
    if fn_file_offset and fn_size:
        raw_bytes = _get_raw_bytes(fn_file_offset, fn_size, target)
        if raw_bytes:
            ctx["bytes_heading"] = _section_heading("01", "#10b981", "Original Bytes")
            ctx["bytes_html"] = _render_original_bytes(raw_bytes, fn_file_offset)
            if section != ".text":
                inspector = _format_data_inspector(raw_bytes)
                if inspector:
                    ctx["inspector_html"] = inspector
    return True


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
    """Render the right-hand detail panel HTML."""
    ctx = _panel_base_ctx()

    if not idx_str:
        return _PANEL_TPL.render(**ctx)

    try:
        idx = int(idx_str)
    except (ValueError, OverflowError):
        return _PANEL_TPL.render(**ctx)

    if idx < 0 or idx >= len(cells):
        return _PANEL_TPL.render(**ctx)

    # Bounds already validated by the if-guard above
    cell = cells[idx]
    state = cell.get("state", "none")
    funcs = cell.get("functions", [])
    sec_va = (sec_data or {}).get("va", 0)

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
            "prev_url": prev_url,
            "next_url": next_url,
            "target": target,
            "section": section,
        }
    )

    if not funcs:
        # Show hex dump + data inspector for empty cells
        _panel_empty_cell_bytes(ctx, cell, sec_data, target)
        return _PANEL_TPL.render(**ctx)

    fn_name = funcs[0]
    ctx["fn_name"] = fn_name
    if not _panel_function_detail(ctx, c, target, section, data, fn_name):
        # ── Try globals table ────────────────────────────────────────
        c.execute(
            "SELECT " + _GLOBAL_JSON_SQL + " FROM globals WHERE target=? AND name=?",
            (target, fn_name),
        )
        gl_row = c.fetchone()
        if gl_row:
            gl_data = json.loads(gl_row[0])
            ctx["gl_data"] = gl_data
            ctx["gl_detail_rows"] = _detail_rows(gl_data, skip_fields={"files"})
        # else: no function and no global → "Unknown" branch in template

    return _PANEL_TPL.render(**ctx)
