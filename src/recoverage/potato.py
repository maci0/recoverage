from __future__ import annotations

import base64
import json
import sqlite3
import struct
import textwrap
from collections.abc import Callable, Iterable
from html import escape as _html_escape
from pathlib import Path
from typing import Any
from urllib.parse import ParseResult, parse_qs
from urllib.parse import quote as _url_quote

from bottle import SimpleTemplate  # type: ignore

# --- UI Constants ---
COLORS = {
    "exact": "#10b981",
    "reloc": "#0ea5e9",
    "matching": "#f59e0b",
    "matching_reloc": "#f59e0b",
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

TRANSPARENT_GIF = "data:image/gif;base64,R0lGODlhAQABAIAAAAAAAP///yH5BAEAAAAALAAAAAABAAEAAAIBRAA7"

SCANLINE_PNG = (
    "data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAAAEAAAADCAYAAABS3WWC"
    "AAAADElEQVR4nGNgQAYaAAA3AClW0vESAAAAAElFTkSuQmCC"
)


# Topbar gradient
def _make_topbar_png() -> str:
    """Generate a 1x80 vertical gradient SVG for the topbar."""
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


TOPBAR_PNG = _make_topbar_png()

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
    "matching": (
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

# ── Progress bar PNG cache ──────────────────────────────────
_progress_png_cache: dict[tuple[tuple[str, float], ...], str] = {}


def _make_progress_png(
    segments: list[tuple[str, float]],
    colors: dict[str, str],
    width: int = 700,
    height: int = 32,
    radius: int = 10,
) -> str:
    """Generate an SVG with colored segments and rounded corners as a data: URI.
    `segments` is a list of (status_key, pct) pairs. Cached by key."""
    cache_key = tuple(segments)
    if cache_key in _progress_png_cache:
        return _progress_png_cache[cache_key]

    svg = [
        f'<svg xmlns="http://www.w3.org/2000/svg" width="{width}" height="{height}" viewBox="0 0 {width} {height}">'
        f'<defs><clipPath id="rc"><rect width="{width}" height="{height}" rx="{radius}" ry="{radius}"/></clipPath></defs>'
        f'<rect width="{width}" height="{height}" fill="#1f2937" rx="{radius}" ry="{radius}"/>'
        '<g clip-path="url(#rc)">'
    ]

    current_x = 0.0
    for status, pct in segments:
        hex_color = colors.get(status, "#1f2937")
        seg_w = width * pct / 100.0
        if seg_w > 0:
            svg.append(
                f'<rect x="{current_x:.2f}" y="0" width="{seg_w:.2f}" height="{height}" fill="{hex_color}"/>'
            )
        current_x += seg_w

    svg.append("</g></svg>")

    uri = "data:image/svg+xml;base64," + base64.b64encode("".join(svg).encode("utf-8")).decode(
        "utf-8"
    )
    _progress_png_cache[cache_key] = uri
    return uri


def _make_pill_caps(
    height: int, fill_hex: str, border_hex: str | None = None, radius: int | None = None
) -> tuple[str, str, str]:
    """Generate left-cap and right-cap SVG data URIs for a pill shape.
    Returns (left_uri, right_uri, fill_hex) for 3-cell construction."""
    if radius is None:
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

    return _uri(left_svg), _uri(right_svg), fill_hex


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
ACTIVE_L, ACTIVE_R, _ = _make_pill_caps(32, "#1a3a4a", border_hex="#06b6d4")
INACTIVE_L, INACTIVE_R, _ = _make_pill_caps(32, "#182230", border_hex="#2a3a4a")
ACTIVE_MID = _make_pill_mid_tile(32, "#1a3a4a", "#06b6d4")
INACTIVE_MID = _make_pill_mid_tile(32, "#182230", "#2a3a4a")

# Pre-compute filter pill cap images
FILTER_ACT_L, FILTER_ACT_R, _ = _make_pill_caps(32, "#162438", border_hex="#2a6fdb")
FILTER_INACT_L, FILTER_INACT_R, _ = _make_pill_caps(32, "#182230", border_hex="#2a3a4a")
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
    ("matching", "near-miss"),
    ("stub", "stub"),
    ("padding", "padding"),
]


# --- HTML Helpers ---


def _hex_logo_svg(label: str, color: str) -> str:
    """Generate a hex-shaped SVG logo as a data-URI <img> tag."""
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


def _section_heading(label: str, color: str, title: str, extra: str = "") -> str:
    """Render a section heading with a hex logo + title text."""
    logo = _hex_logo_svg(label, color)
    return (
        f'<table border="0" cellpadding="0" cellspacing="4"><tr>'
        f'<td valign="middle">{logo}</td>'
        f'<td valign="middle"><font size="3"><b>{title}</b></font>'
        f"{extra}</td></tr></table><br>"
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
            f'<tr><td bgcolor="{PANEL_COLOR}" width="28%">'
            f'<font size="1" color="{MUTED_COLOR}"><b>{_esc(k)}</b></font></td>'
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


def _pygments_available() -> bool:
    """Check if pygments is available (lazy import)."""
    try:
        import pygments.lexers  # type: ignore # noqa: F401

        return True
    except ImportError:
        return False


def _get_c_colors() -> dict[Any, str]:
    from pygments.token import (  # type: ignore
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


def _get_asm_colors() -> dict[Any, str]:
    from pygments.token import (  # type: ignore
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


def _highlight_c(code: str) -> str:
    """Syntax-highlight C code using Pygments tokens and <font> tags (no CSS)."""
    if not _pygments_available():
        return _html_escape(code)
    from pygments.lexers import CLexer  # type: ignore

    return _highlight_tokens(CLexer().get_tokens(code), _get_c_colors())


def _highlight_asm(text: str) -> str:
    """Syntax-highlight x86 assembly using Pygments tokens and <font> tags (no CSS)."""
    if not _pygments_available():
        return _html_escape(text)
    from pygments.lexers import NasmLexer  # type: ignore

    colors = _get_asm_colors()
    lexer = NasmLexer()
    result_lines: list[str] = []
    for line in text.splitlines():
        if line.startswith("0x") and "  " in line:
            addr_end = line.index("  ")
            addr_part, code_part = line[:addr_end], line[addr_end:]
            hl = _highlight_tokens(lexer.get_tokens(code_part), colors)
            result_lines.append(
                f'<font color="#858585">{_html_escape(addr_part)}</font>' + hl.rstrip("\n")
            )
        else:
            result_lines.append(_html_escape(line))
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


def get_db_path() -> Path:
    return Path.cwd().resolve() / "db" / "coverage.db"


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


def _dll_path(target: str) -> Path:
    """Resolve the DLL path for a target from reccmp-project.yml."""
    project_root = Path.cwd().resolve()
    try:
        import yaml  # type: ignore

        yml_path = project_root / "reccmp-project.yml"
        with open(yml_path, encoding="utf-8") as f:
            doc = yaml.safe_load(f)
        targets_cfg = doc.get("targets", {}) if isinstance(doc, dict) else {}
        target_info = targets_cfg.get(target, targets_cfg.get("SERVER", {}))
        filename = (
            target_info.get("filename", "original/Server/server.dll")
            if isinstance(target_info, dict)
            else "original/Server/server.dll"
        )
        return project_root / filename
    except Exception:
        return project_root / "original" / "Server" / "server.dll"


def _get_raw_bytes(file_offset: int, size: int, target: str) -> bytes | None:
    """Read raw bytes from the target DLL."""
    try:
        with open(_dll_path(target), "rb") as f:
            f.seek(file_offset)
            return f.read(size)
    except OSError:
        return None


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


def _format_data_inspector(
    raw_bytes: bytes | None,
    panel_color: str | None = None,
    border_color: str | None = None,
    muted_color: str | None = None,
) -> str:
    """Format raw bytes as a Data Inspector table (like the main UI)."""
    if not raw_bytes:
        return ""

    pc = panel_color or PANEL_COLOR
    bc = border_color or BORDER_COLOR
    mc = muted_color or MUTED_COLOR

    parts: list[str] = []
    parts.append(
        _section_heading("{}", "#a855f7", "Data Inspector")
        + f'<table width="100%" border="0" cellpadding="3" cellspacing="1"'
        f' bgcolor="{bc}">'
    )

    def _row(label: str, value: object) -> None:
        parts.append(
            f'<tr><td bgcolor="{pc}" width="35%">'
            f'<font size="1" color="{mc}"><b>{_esc(label)}</b></font></td>'
            f'<td bgcolor="{pc}">'
            f'<font face="Courier New, monospace" size="1">{_esc(value)}</font></td></tr>'
        )

    b = raw_bytes
    _INT_FMTS = [
        (1, "int8", "<b"),
        (1, "uint8", "<B"),
        (2, "int16", "<h"),
        (2, "uint16", "<H"),
        (4, "int32", "<i"),
        (4, "uint32", "<I"),
    ]
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
) -> str:
    """Build a potato URL with the given parameters."""
    url = "?target=" + _url_quote(target) + "&section=" + _url_quote(section)
    if filters:
        url += "&filter=" + ",".join(sorted(filters))
    if idx is not None:
        url += "&idx=" + str(idx)
    if search:
        url += "&search=" + _url_quote(search)
    return url


def _get_disassembly(va: int, size: int, file_offset: int, target: str) -> str | None:
    """Try to disassemble using capstone, return text or None."""
    try:
        import capstone  # type: ignore
    except ImportError:
        return None

    try:
        with open(_dll_path(target), "rb") as f:
            f.seek(file_offset)
            code_bytes = f.read(size)
    except OSError:
        return None

    if len(code_bytes) < size:
        return None

    md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_32)
    md.detail = False

    asm_lines: list[str] = []
    for insn in md.disasm(code_bytes, va):
        asm_lines.append(f"0x{insn.address:08x}  {insn.mnemonic:8s} {insn.op_str}")

    return "\n".join(asm_lines) if asm_lines else None


# ── SimpleTemplate: Page Layout ─────────────────────────────────────

_PAGE_SRC = r"""<!DOCTYPE html>
<html lang="en">
<head><meta charset="utf-8"><title>ReCoverage - Potato Mode</title><link rel="icon" href="data:image/svg+xml,%3Csvg%20xmlns%3D%27http%3A%2F%2Fwww.w3.org%2F2000%2Fsvg%27%20viewBox%3D%270%200%20100%20100%27%3E%3Ctext%20y%3D%27.9em%27%20font-size%3D%2790%27%3E%F0%9F%A5%94%3C%2Ftext%3E%3C%2Fsvg%3E"></head>
<body bgcolor="{{BG_COLOR}}" text="{{TEXT_COLOR}}" background="{{SCANLINE_PNG}}" link="{{COLORS['reloc']}}" vlink="{{COLORS['reloc']}}" alink="{{COLORS['exact']}}">
<font face="{{SANS_FONT}}">

<!-- Top Bar -->
<table id="topbar" width="100%" border="0" cellpadding="4" cellspacing="0" background="{{TOPBAR_PNG}}">
  <tr>
    <td valign="middle">
      <table id="logo" border="0" cellpadding="0" cellspacing="0">
        <tr>
          <td><img src="{{R_LOGO_SVG}}" width="48" height="32" border="0" alt="R"></td>
          <td valign="middle"><font face="{{MONO_FONT}}" size="5" color="{{TEXT_COLOR}}">&nbsp;<b>ReCoverage</b></font></td>
        </tr>
      </table>
    </td>
    <td valign="middle">
      <table id="section-tabs" border="0" cellpadding="0" cellspacing="4"><tr>
      % for s_name, s_url, s_active, s_pct_str in section_tab_data:
        <td valign="middle">
        % if s_active:
          <table border="0" cellpadding="0" cellspacing="0"><tr><td><img src="{{ACTIVE_L}}" width="16" height="32" border="0" alt=""></td><td background="{{ACTIVE_MID}}" height="32" nowrap><a href="{{s_url}}"><font face="{{MONO_FONT}}" size="3" color="#ffffff"><b>{{s_name}}</b></font></a></td><td><img src="{{ACTIVE_R}}" width="16" height="32" border="0" alt=""></td></tr></table>
        % else:
          <table border="0" cellpadding="0" cellspacing="0"><tr><td><img src="{{INACTIVE_L}}" width="16" height="32" border="0" alt=""></td><td background="{{INACTIVE_MID}}" height="32" nowrap><a href="{{s_url}}"><font face="{{MONO_FONT}}" size="3" color="{{MUTED_COLOR}}">{{s_name}}</font></a></td><td><img src="{{INACTIVE_R}}" width="16" height="32" border="0" alt=""></td></tr></table>
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
          <input id="search-input" type="text" name="search" size="18" value="{{search_query}}" placeholder="Search VA or name..."> <input type="submit" value="Go"></form>
          % if search_query:
            <br><font size="1" color="{{ACCENT_COLOR}}">Searching: &quot;{{search_query}}&quot; ({{search_match_count}} matches)</font> <a href="{{clear_search_url}}"><font size="1" color="{{MUTED_COLOR}}">[Clear search]</font></a>
          % end
        </td>
        <td valign="middle">
          <table id="filters" border="0" cellpadding="0" cellspacing="4"><tr>
            % for fb_href, fb_label, fb_color, fb_active in filter_btn_data:
              <td valign="middle">
              % if fb_active:
                <table border="0" cellpadding="0" cellspacing="0"><tr><td><img src="{{FILTER_ACT_L}}" width="16" height="32" border="0" alt=""></td><td background="{{FILTER_ACT_MID}}" height="32" nowrap><a href="{{fb_href}}"><font face="{{MONO_FONT}}" size="3" color="{{fb_color}}"><b>{{fb_label}}</b></font></a></td><td><img src="{{FILTER_ACT_R}}" width="16" height="32" border="0" alt=""></td></tr></table>
              % else:
                <table border="0" cellpadding="0" cellspacing="0"><tr><td><img src="{{FILTER_INACT_L}}" width="16" height="32" border="0" alt=""></td><td background="{{FILTER_INACT_MID}}" height="32" nowrap><a href="{{fb_href}}"><font face="{{MONO_FONT}}" size="3" color="{{fb_color}}">{{fb_label}}</font></a></td><td><img src="{{FILTER_INACT_R}}" width="16" height="32" border="0" alt=""></td></tr></table>
              % end
              </td>
            % end
          </tr></table>
        </td>
        <td valign="middle">
          <form id="target-form" action="/potato" method="GET">
            <input type="hidden" name="section" value="{{section}}">
            <select id="target-select" name="target">
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
    <td valign="top" width="75%">
      <table id="map" width="100%" border="1" cellpadding="0" cellspacing="0" bgcolor="{{PANEL_COLOR}}" bordercolor="{{BORDER_COLOR}}">
        <tr><td id="map-header" background="{{PANEL_HDR_PNG}}" cellpadding="8">&nbsp;<font color="{{MUTED_COLOR}}" size="2"><b>Coverage Map - {{section}}</b></font> <font color="{{MUTED_COLOR}}" size="1"> ({{block_count}} blocks)</font>
        % if sec_stats.get('total', 0) > 0:
          <font face="{{MONO_FONT}}" size="1" color="{{MUTED_COLOR}}"><font color="{{COLORS['exact']}}">E:{{sec_stats['exact']}}</font> <font color="{{COLORS['reloc']}}">R:{{sec_stats['reloc']}}</font> <font color="{{COLORS['matching']}}">M:{{sec_stats['matching']}}</font> <font color="{{COLORS['stub']}}">S:{{sec_stats['stub']}}</font> <font color="{{COLORS['padding']}}">P:{{sec_stats.get('padding', 0)}}</font> &#x2502; {{sec_stats['pct']}}% covered</font>
        % end
        </td></tr>
        <tr><td bgcolor="{{PANEL_COLOR}}" cellpadding="8">
          <table id="legend" border="0" cellpadding="0" cellspacing="4"><tr>
          % for leg_key, leg_label in LEGEND_ITEMS:
            <td valign="middle"><img src="{{DOT_PNGS[leg_key]}}" width="12" height="12" border="0" alt=""></td><td valign="middle"><font face="{{MONO_FONT}}" size="1" color="{{MUTED_COLOR}}">{{leg_label}}</font></td>
          % end
          </tr></table>
          <table id="grid-container" border="1" cellpadding="8" cellspacing="0" bordercolor="{{BORDER_COLOR}}" bgcolor="{{BG_COLOR}}" width="100%"><tr><td>
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
  </tr>
</table>
<table width="100%" border="0" cellpadding="8" cellspacing="0"><tr><td><a href="https://validator.w3.org/"><img src="https://upload.wikimedia.org/wikipedia/commons/b/bb/W3C_HTML5_certified.png" width="133" height="47" alt="Valid HTML5" border="0"></a></td></tr></table>
</font></body></html>"""

_PAGE_TPL = SimpleTemplate(source=_PAGE_SRC)


# ── SimpleTemplate: Detail Panel ────────────────────────────────────

_PANEL_SRC = r"""
% if not has_cell:
<table width="100%" border="0" cellpadding="10" cellspacing="1" bgcolor="{{BORDER_COLOR}}"><tr><td bgcolor="{{PANEL_COLOR}}" align="center"><font size="3" color="{{MUTED_COLOR}}"><b>Select a block</b></font><br><br><font color="{{MUTED_COLOR}}">Click any colored block in the grid to view details.</font></td></tr></table>
% else:
&nbsp;<font size="2"><b>Block {{idx}}</b></font><br>
<table width="100%" border="0" cellpadding="3" cellspacing="1" bgcolor="{{BORDER_COLOR}}"><tr><td bgcolor="{{PANEL_COLOR}}"><font size="1" color="{{MUTED_COLOR}}"><b>Range:</b></font></td><td bgcolor="{{PANEL_COLOR}}"><font face="Courier New, monospace" size="1">{{cell_range}}</font></td></tr><tr><td bgcolor="{{PANEL_COLOR}}"><font size="1" color="{{MUTED_COLOR}}"><b>State:</b></font></td><td bgcolor="{{PANEL_COLOR}}"><font face="Courier New, monospace" size="1" color="{{state_color}}"><b>{{state_upper}}</b></font></td></tr>% if cell_label:
<tr><td bgcolor="{{PANEL_COLOR}}"><font size="1" color="{{MUTED_COLOR}}"><b>Label:</b></font></td><td bgcolor="{{PANEL_COLOR}}"><font face="Courier New, monospace" size="1">{{cell_label}}</font></td></tr>% end
% if parent_function:
<tr><td bgcolor="{{PANEL_COLOR}}"><font size="1" color="{{MUTED_COLOR}}"><b>Parent:</b></font></td><td bgcolor="{{PANEL_COLOR}}"><font face="Courier New, monospace" size="1"><a href="?target={{target}}&section={{section}}&search={{parent_function}}"><font color="{{ACCENT_COLOR}}">{{parent_function}}</font></a></font></td></tr>% end
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

    db_path = get_db_path()
    try:
        conn = sqlite3.connect(f"file:{db_path}?mode=ro", uri=True)
    except Exception as e:
        return f"<html><body>Database error: {_esc(str(e))}</body></html>"

    try:
        c = conn.cursor()
        return _render_potato_inner(c, conn, target, section, active_filters, idx_str, search_query)
    finally:
        conn.close()


def _render_potato_inner(
    c: sqlite3.Cursor,
    conn: sqlite3.Connection,
    target: str,
    section: str,
    active_filters: set[str],
    idx_str: str,
    search_query: str,
) -> str:
    # Get targets (resolve display name from reccmp-project.yml)
    c.execute("SELECT DISTINCT target FROM metadata")
    target_ids = [row[0] for row in c.fetchall()]
    if not target and target_ids:
        target = target_ids[0]
    _target_filenames: dict[str, str] = {}
    try:
        import yaml  # type: ignore

        _yml = Path.cwd().resolve() / "reccmp-project.yml"
        if _yml.exists():
            with open(_yml, encoding="utf-8") as _f:
                _doc = yaml.safe_load(_f)
            if isinstance(_doc, dict):
                _tcfg = _doc.get("targets", {})
                if isinstance(_tcfg, dict):
                    for _tid, _tinfo in _tcfg.items():
                        fn = _tinfo.get("filename", "") if isinstance(_tinfo, dict) else ""
                        _target_filenames[_tid] = Path(fn).name if fn else _tid
    except Exception:
        pass

    if not _target_filenames:
        try:
            _toml = Path.cwd().resolve() / "rebrew.toml"
            if _toml.exists():
                import tomllib

                _text = _toml.read_text(encoding="utf-8")
                _doc = tomllib.loads(_text)
                _targets_dict = _doc.get("targets", {})
                for _tid in _targets_dict:
                    _target_filenames[_tid] = _tid
        except Exception:
            pass
    targets = (
        [{"id": tid, "name": _target_filenames.get(tid, tid)} for tid in target_ids]
        if target_ids
        else []
    )

    data: dict[str, Any] = {}
    c.execute("SELECT key, value FROM metadata WHERE target = ?", (target,))
    for key, val in c.fetchall():
        try:
            data[key] = json.loads(val)
        except (json.JSONDecodeError, TypeError):
            data[key] = val

    if not data:
        return (
            f'<html><body bgcolor="#0f1216" text="#ffffff">'
            f"No data for target {_esc(target)}</body></html>"
        )

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

    c.execute(
        "SELECT section_name, json_group_array(json_object("
        "'id', id, 'start', start, 'end', end, 'span', span, "
        "'state', state, 'functions', json(functions), 'label', label, 'parent_function', parent_function"
        ")) FROM cells WHERE target = ? GROUP BY section_name",
        (target,),
    )
    for row in c.fetchall():
        sec_name = row[0]
        if sec_name in sections:
            sections[sec_name]["cells"] = json.loads(row[1])

    if section not in sections and sections:
        section = next(iter(sections))

    sec_data: dict[str, Any] = sections.get(section, {})
    cells = sec_data.get("cells", [])

    # ── Search ───────────────────────────────────────────────────
    search_matched_fns: set[str] = set()
    if search_query:
        like_pat = "%" + search_query.replace("%", "\\%").replace("_", "\\_") + "%"
        c.execute(
            "SELECT name FROM functions WHERE target = ? AND ("
            "name LIKE ? ESCAPE '\\' OR vaStart LIKE ? ESCAPE '\\' "
            "OR symbol LIKE ? ESCAPE '\\')",
            (target, like_pat, like_pat, like_pat),
        )
        search_matched_fns.update(row[0] for row in c.fetchall())
        c.execute(
            "SELECT name FROM globals WHERE target = ? AND ("
            "name LIKE ? ESCAPE '\\' OR printf('0x%x', va) LIKE ? ESCAPE '\\')",
            (target, like_pat, like_pat),
        )
        search_matched_fns.update(row[0] for row in c.fetchall())

    # ── Coverage stats ───────────────────────────────────────────
    total_cells = exact_count = reloc_count = matching_count = stub_count = 0
    per_section_stats: dict[str, dict[str, int]] = {}
    _summary = data.get("summary", {})
    c.execute(
        "SELECT section_name, total_cells, exact_count, reloc_count, "
        "matching_count, stub_count, padding_count, data_count, thunk_count FROM section_cell_stats WHERE target = ?",
        (target,),
    )
    for row in c.fetchall():
        sec_name_r, s_total, s_exact, s_reloc, s_matching, s_stub, s_padding, s_data, s_thunk = row
        total_cells += s_total
        exact_count += s_exact
        reloc_count += s_reloc
        matching_count += s_matching
        stub_count += s_stub
        sec_summary_entry = _summary.get(sec_name_r, _summary)
        s_covered_bytes = sec_summary_entry.get("coveredBytes", 0)
        s_sec_size = sections.get(sec_name_r, {}).get("size", 0)
        s_pct = int((s_covered_bytes / s_sec_size) * 100) if s_sec_size > 0 else 0
        per_section_stats[sec_name_r] = {
            "total": s_total,
            "exact": s_exact,
            "reloc": s_reloc,
            "matching": s_matching,
            "stub": s_stub,
            "padding": s_padding,
            "covered": s_exact + s_reloc,
            "pct": s_pct,
        }

    # ── Filter toggle links ──────────────────────────────────────
    _FILTER_OPTS = [
        ("exact", "E"),
        ("reloc", "R"),
        ("matching", "M"),
        ("stub", "S"),
        ("padding", "P"),
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
        for f, _ in _FILTER_OPTS
    }
    all_link = _build_url(target, section, search=search_query)
    filter_btn_data = [
        (
            all_link,
            "All",
            TEXT_COLOR if not active_filters else MUTED_COLOR,
            not active_filters,
        )
    ] + [(toggle_links[f], n, COLORS[f], f in active_filters) for f, n in _FILTER_OPTS]

    # ── Progress bar data ────────────────────────────────────────
    progress = None
    if total_cells > 0:
        sec_size = sec_data.get("size", 0)
        sec_summ = _summary.get(section, _summary)
        covered_bytes = sec_summ.get("coveredBytes", 0)
        total_fn = sec_summ.get("totalFunctions", 0)
        exact_matches = sec_summ.get("exactMatches", 0)
        reloc_matches = sec_summ.get("relocMatches", 0)
        matching_matches = sec_summ.get("matchingMatches", 0)
        stub_matches = sec_summ.get("stubCount", 0)
        matched_fn = exact_matches + reloc_matches + matching_matches + stub_matches

        # Use function counts for .text, byte counts for other sections
        # (matches normal UI app.js behavior)
        if section == ".text" and total_fn > 0:
            seg_exact = exact_matches / total_fn * 100
            seg_reloc = reloc_matches / total_fn * 100
            seg_matching = matching_matches / total_fn * 100
            seg_stub = stub_matches / total_fn * 100
        elif sec_size > 0:
            seg_exact = sec_summ.get("exactBytes", 0) / sec_size * 100
            seg_reloc = sec_summ.get("relocBytes", 0) / sec_size * 100
            seg_matching = sec_summ.get("matchingBytes", 0) / sec_size * 100
            seg_stub = sec_summ.get("stubBytes", 0) / sec_size * 100
        else:
            seg_exact = seg_reloc = seg_matching = seg_stub = 0

        padding_bytes_val = sec_summ.get("paddingBytes", 0)
        seg_padding = (padding_bytes_val / sec_size * 100) if sec_size > 0 else 0
        seg_none = max(0, 100 - seg_exact - seg_reloc - seg_matching - seg_stub - seg_padding)
        progress = {
            "sec_size": sec_size,
            "coverage_pct": (covered_bytes / sec_size * 100) if sec_size > 0 else 0,
            "total_fn": total_fn,
            "matched_fn": matched_fn,
            "segments": [
                ("exact", seg_exact),
                ("reloc", seg_reloc),
                ("matching", seg_matching),
                ("stub", seg_stub),
                ("padding", seg_padding),
                ("none", seg_none),
            ],
        }

    # ── Section tab data ─────────────────────────────────────────
    section_tab_data = [
        (
            s,
            _build_url(target, s, active_filters or None, search=search_query),
            s == section,
            (
                f" {per_section_stats.get(s, {}).get('pct', 0)}%"
                if per_section_stats.get(s, {}).get("total", 0) > 0
                else ""
            ),
        )
        for s in sections
    ]

    # ── Grid (with cell merging) ─────────────────────────────────
    grid_columns = sec_data.get("columns", 64)
    if grid_columns <= 0:
        grid_columns = 64

    CELL_W = 18
    # NOTE: CELL_H < CELL_W to compensate for the browser baseline gap
    # (~3px) added below inline images.  The <font size="1"> wrapper around
    # the grid (in the template) keeps this gap small and predictable.
    # Removing that wrapper will make cells taller than wide.
    CELL_H = 15

    merged_cells = []
    if cells:
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
            else:
                merged_cells.append(curr_cell)
                curr_cell = dict(next_c)
                curr_cell["orig_idx"] = i
                if curr_col >= grid_columns:
                    curr_col = n_span
                else:
                    curr_col += n_span
        merged_cells.append(curr_cell)
    else:
        merged_cells = cells

    sizing_tds = "".join(
        f'<td bgcolor="{BG_COLOR}" width="{CELL_W}" height="1"></td>' for _ in range(grid_columns)
    )
    grid_html_parts = [
        f'<table id="grid" border="1" frame="void" rules="all" cellpadding="0" cellspacing="0" bordercolor="{BG_COLOR}" bgcolor="{BG_COLOR}">'
        f"<tr>{sizing_tds}</tr><tr>"
    ]
    curr_col = 0
    for i, cell in enumerate(merged_cells):
        span = cell.get("span", 1)
        orig_idx = cell.get("orig_idx", i)
        if curr_col >= grid_columns:
            grid_html_parts.append("</tr><tr>")
            curr_col = 0

        state = cell.get("state", "none")
        if state == "matching_reloc":
            state = "matching"

        dimmed = (active_filters and state != "none" and state not in active_filters) or (
            search_query and not any(fn in search_matched_fns for fn in cell.get("functions", []))
        )
        bgcolor = BG_COLOR if dimmed else COLORS.get(state, COLORS["none"])
        selected = idx_str.isdigit() and int(idx_str) == orig_idx
        link = _build_url(
            target, section, active_filters or None, idx=orig_idx, search=search_query
        )
        sec_va = sec_data.get("va", 0)
        title = (
            f"{hex(sec_va + cell.get('start', 0))}..{hex(sec_va + cell.get('end', 0))} | {state}"
        )
        w = CELL_W * span
        img = f'<a href="{link}" title="{_esc(title)}"><img src="{TRANSPARENT_GIF}" width="{w}" height="{CELL_H}" border="0" alt=""></a>'

        if selected:
            # Accent border for selection highlight via nested table.
            # Shrink image by 2px in each dimension to compensate for border.
            sel_img = (
                f'<a href="{link}" title="{_esc(title)}">'
                f'<img src="{TRANSPARENT_GIF}" width="{w - 2}" height="{CELL_H - 2}" border="0" alt="">'
                f"</a>"
            )
            grid_html_parts.append(
                f'<td bgcolor="{BG_COLOR}" width="{w}" height="{CELL_H}" colspan="{span}">'
                f'<table border="1" cellpadding="0" cellspacing="0" bordercolor="{ACCENT_COLOR}" width="100%">'
                f'<tr><td bgcolor="{bgcolor}">{sel_img}</td></tr></table></td>'
            )
        else:
            grid_html_parts.append(
                f'<td bgcolor="{bgcolor}" width="{w}" height="{CELL_H}" colspan="{span}">{img}</td>'
            )
        curr_col += span

    remaining = int(grid_columns) - curr_col
    if remaining > 0:
        grid_html_parts.append(
            f'<td bgcolor="{BG_COLOR}" width="{CELL_W * remaining}"'
            f' height="{CELL_H}" colspan="{remaining}"></td>'
        )
    grid_html_parts.append("</tr></table>")
    grid_html = "".join(grid_html_parts)

    sec_stats = per_section_stats.get(section, {})

    # ── Detail panel ─────────────────────────────────────────────
    panel_html = _render_panel(c, cells, idx_str, target, section, data, sec_data)

    # ── Render page template ─────────────────────────────────────
    clear_search_url = _build_url(target, section, active_filters or None)

    progress_bar_png_uri = ""
    if progress:
        progress_bar_png_uri = _make_progress_png(progress["segments"], COLORS)

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
        TOPBAR_PNG=TOPBAR_PNG,
        PANEL_HDR_PNG=PANEL_HDR_PNG,
        R_LOGO_SVG=R_LOGO_SVG,
        DOT_PNGS=DOT_PNGS,
        LEGEND_ITEMS=LEGEND_ITEMS,
        # Data
        target=target,
        section=section,
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
        block_count=len(merged_cells),
        grid_html=grid_html,
        panel_html=panel_html,
    )


def _render_panel(
    c: sqlite3.Cursor,
    cells: list[dict[str, Any]],
    idx_str: str,
    target: str,
    section: str,
    data: dict[str, Any],
    sec_data: dict[str, Any] | None = None,
) -> str:
    """Render the right-hand detail panel HTML."""
    # Common context — constants + defaults for all panel states
    _empty = {
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
        "target": "",
        "section": "",
    }
    ctx: dict[str, Any] = {
        **_empty,
        "PANEL_COLOR": PANEL_COLOR,
        "BORDER_COLOR": BORDER_COLOR,
        "MUTED_COLOR": MUTED_COLOR,
        "ACCENT_COLOR": ACCENT_COLOR,
        "COLORS": COLORS,
    }

    if not idx_str.isdigit():
        return _PANEL_TPL.render(**ctx)

    idx = int(idx_str)
    if idx >= len(cells):
        return _PANEL_TPL.render(**ctx)

    cell = cells[idx]
    state = cell.get("state", "none")
    if state == "matching_reloc":
        state = "matching"
    state_color = COLORS.get(state, TEXT_COLOR)

    funcs = cell.get("functions", [])
    cell_label = cell.get("label", "")
    parent_function = cell.get("parent_function", "")
    ctx.update(
        {
            "has_cell": True,
            "idx": idx,
            "cell_range": f"{hex(sec_data.get('va', 0) + cell.get('start', 0))} .. {hex(sec_data.get('va', 0) + cell.get('end', 0))}",
            "state_upper": state.upper(),
            "state_color": state_color,
            "funcs": funcs,
            "cell_label": cell_label,
            "parent_function": parent_function,
            "target": target,
            "section": section,
        }
    )

    if not funcs:
        # Show hex dump + data inspector for empty cells
        cell_file_offset = _cell_file_offset(cell, sec_data)
        cell_size = cell.get("end", 0) - cell.get("start", 0)
        if cell_file_offset and cell_size > 0:
            raw_bytes = _get_raw_bytes(cell_file_offset, cell_size, target)
            if raw_bytes:
                hex_dump = _format_hex_dump(raw_bytes, cell_file_offset)
                ctx["hex_heading"] = _section_heading("01", "#10b981", "Original Bytes")
                ctx["hex_dump_html"] = _code_block_raw(_highlight_hex(wrap_text(hex_dump, 72)))
                inspector = _format_data_inspector(raw_bytes)
                if inspector:
                    ctx["inspector_html"] = inspector
        return _PANEL_TPL.render(**ctx)

    fn_name = funcs[0]
    ctx["fn_name"] = fn_name

    # ── Try functions table ──────────────────────────────────────
    c.execute(
        "SELECT json_object("
        "'va', va, 'name', name, 'vaStart', vaStart, 'size', size, "
        "'fileOffset', fileOffset, 'status', status, 'origin', origin, "
        "'cflags', cflags, 'symbol', symbol, 'markerType', markerType, "
        "'ghidra_name', ghidra_name, 'r2_name', r2_name, "
        "'is_thunk', is_thunk, 'is_export', is_export, "
        "'sha256', sha256, 'files', json(files)"
        ") FROM functions WHERE target=? AND name=?",
        (target, fn_name),
    )
    fn_row = c.fetchone()

    if fn_row:
        fn_data = json.loads(fn_row[0])
        ctx["fn_data"] = fn_data

        HEX_FIELDS = {"va", "fileOffset"}
        SKIP_FIELDS = {"files", "sha256", "is_thunk", "is_export"}

        # Badges
        badges: list[str] = []
        if fn_data.get("is_thunk"):
            badges.append(
                f'<font color="{COLORS.get("matching", "#f59e0b")}"><b>[IAT thunk]</b></font>'
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

        ctx["detail_rows_html"] = _detail_rows(fn_data, SKIP_FIELDS, HEX_FIELDS, _fn_val)

        # Source code + annotations
        files = fn_data.get("files", [])
        code_text = None
        if files:
            source_root = data.get("paths", {}).get("sourceRoot", f"/src/{target.lower()}")
            c_path = Path(__file__).resolve().parent.parent / source_root.lstrip("/") / files[0]
            try:
                with open(c_path, encoding="utf-8") as f:
                    code_text = f.read()
            except OSError:
                pass

        if code_text:
            ctx["annotations"] = _extract_annotations(code_text)
            ctx["c_heading"] = _section_heading("C", "#3b82f6", f"C Source ({_esc(files[0])})")
            ctx["code_html"] = _code_block_raw(_highlight_c(code_text))

        # Assembly
        if section == ".text":
            fn_va = fn_data.get("va")
            fn_size = fn_data.get("size")
            fn_file_offset = fn_data.get("fileOffset")
            if fn_va and fn_size and fn_file_offset:
                asm_text = _get_disassembly(fn_va, fn_size, fn_file_offset, target)
                if asm_text:
                    ctx["asm_heading"] = _section_heading("ASM", "#ef4444", "Assembly")
                    ctx["asm_html"] = _code_block_raw(_highlight_asm(wrap_text(asm_text, 55)))

        # Original Bytes
        fn_file_offset = fn_data.get("fileOffset")
        fn_size = fn_data.get("size")
        if fn_file_offset and fn_size:
            raw_bytes = _get_raw_bytes(fn_file_offset, fn_size, target)
            if raw_bytes:
                hex_dump = _format_hex_dump(raw_bytes, fn_file_offset)
                ctx["bytes_heading"] = _section_heading("01", "#10b981", "Original Bytes")
                ctx["bytes_html"] = _code_block_raw(_highlight_hex(wrap_text(hex_dump, 72)))
                if section != ".text":
                    inspector = _format_data_inspector(raw_bytes)
                    if inspector:
                        ctx["inspector_html"] = inspector

        return _PANEL_TPL.render(**ctx)

    # ── Try globals table ────────────────────────────────────────
    c.execute(
        "SELECT json_object("
        "'va', va, 'name', name, 'decl', decl, "
        "'files', json(files)"
        ") FROM globals WHERE target=? AND name=?",
        (target, fn_name),
    )
    gl_row = c.fetchone()
    if gl_row:
        gl_data = json.loads(gl_row[0])
        ctx["gl_data"] = gl_data
        ctx["gl_detail_rows"] = _detail_rows(gl_data, skip_fields={"files"})
    # else: fn_data and gl_data both None → "Unknown" branch in template

    return _PANEL_TPL.render(**ctx)
