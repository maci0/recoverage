#!/usr/bin/env python3
"""Disassembly of a target's original binary, via the optional capstone extra.

One capability, one module: the availability probe, the thread-local
``Cs`` handle, the per-slice memo, and its invalidation hook.  The routes
that render assembly (``api.py``'s ``/asm`` and ``potato.py``'s panel)
import from here, so the optional dependency and its thread-safety
requirement stay out of the shared transport module.
"""

from __future__ import annotations

import functools
import importlib.util
import logging
import threading
from typing import Any

from recoverage.server import _load_dll

_log = logging.getLogger("recoverage")

#: Whether a capstone distribution is on the path at all.  NOT the capability
#: verdict: a wheel for the wrong architecture, a half-unpacked install or a
#: missing libcapstone shared object is found here and still fails on import,
#: so the callers gate on :func:`disassembly_available` instead.
_CAPSTONE_INSTALLED = importlib.util.find_spec("capstone") is not None

_CAPSTONE_MD_TLS = threading.local()

#: Memoized load verdict + its lock.  The probe imports capstone once per
#: process, so the cost is paid by the first caller (health, /asm, a Potato
#: panel) and every later caller reads the answer.
_probe_lock = threading.Lock()
_probe_reason: str | None = None  # None once probed: either healthy or broken
_probed = False


class CapstoneUnavailableError(RuntimeError):
    """capstone is on the path but cannot be loaded (broken or partial install).

    Raised by :func:`get_capstone_md` and, by contract, unreachable from a
    route: both gate on :func:`disassembly_available` first, so a broken extra
    answers the documented 501 / omitted panel instead of a 500 traceback.
    """


def capstone_unavailable_reason() -> str | None:
    """Why disassembly is unavailable, or ``None`` when it works.

    ``find_spec`` answers "is there a capstone distribution", not "does it
    load": the import itself and the ``Cs`` constructor raise on a wheel built
    for another architecture, on a missing libcapstone, and on a half-installed
    package, while the spec probe stays quiet.  A caller that trusted it got a
    500 with a traceback where the 501 contract promises an answer, and
    /api/health advertised an extra that could not be used.

    The verdict is computed once and remembered, so a broken install costs one
    failed import per process rather than one per request, and a working one
    costs one import total.
    """
    global _probe_reason, _probed
    if not _CAPSTONE_INSTALLED:
        return "capstone is not installed"
    if _probed:
        return _probe_reason
    with _probe_lock:
        if not _probed:
            try:
                import capstone as _capstone  # type: ignore[import-not-found]

                _capstone.Cs(_capstone.CS_ARCH_X86, _capstone.CS_MODE_32)
            except Exception as exc:
                # OSError (missing shared object), ImportError (wrong arch),
                # anything the C extension raises at load: the operator needs
                # the class and message, and the request paths answer with
                # this reason rather than a bare "not installed".
                _probe_reason = f"{type(exc).__name__}: {exc}"
                _log.warning("capstone is installed but unusable — %s", _probe_reason)
            _probed = True
        return _probe_reason


def disassembly_available() -> bool:
    """Whether this process can actually disassemble (see the probe above)."""
    return capstone_unavailable_reason() is None


def get_capstone_md() -> Any:
    """Return a thread-local Capstone disassembler.

    A single shared ``Cs`` instance is NOT safe to disassemble concurrently
    (libcapstone is not thread-safe) — with the threaded WSGI server, request
    threads were racing on it and producing garbage/crashes.

    Raises :class:`CapstoneUnavailableError` when the probe says the extra is
    unusable, so a caller that skipped the gate names the reason instead of
    dying on the import.
    """
    md = getattr(_CAPSTONE_MD_TLS, "md", None)
    if md is None:
        reason = capstone_unavailable_reason()
        if reason is not None:
            raise CapstoneUnavailableError(reason)
        import capstone as _capstone  # type: ignore[import-not-found]

        md = _capstone.Cs(_capstone.CS_ARCH_X86, _capstone.CS_MODE_32)
        md.detail = False
        _CAPSTONE_MD_TLS.md = md
    return md


def get_disassembly(va: int, size: int, file_offset: int, target: str) -> str:
    """Disassemble *size* bytes of *target* at *va*, memoized per slice.

    The DLL-load guard deliberately stays OUTSIDE the memo cache: ``_load_dll``
    leaves transient OS failures uncached so the next request self-heals, and
    memoizing their "" result here would pin that outage until the next
    rebuild broadcast happened to clear the cache.
    """
    if _load_dll(target) is None:
        return ""
    return _disassemble_loaded(va, size, file_offset, target)


#: Memo entries for :func:`_disassemble_loaded`, sized by the memo's own
#: worst-case RETAINED BYTES rather than by a plausible row count: one entry is
#: the rendered text of a ``?size=`` slice, and the SPA asks for a whole cell's
#: worth (app.js sends ``size=cell.size``, up to the endpoint's 4096-byte
#: clamp).  Measured: 4096 bytes of x86 renders to 72 KB of text (~1900
#: lines), so a 2048-entry memo retains up to ~148 MB for a cache whose hits
#: are rare — the ETag answers the browser's repeat clicks with a 304 before
#: the memo is consulted, so only non-browser repeats reach it.  128 entries
#: bounds the worst case near 9 MB and still covers a work session that
#: revisits the same slices.
_DISASSEMBLY_MEMO_MAX = 128


@functools.lru_cache(maxsize=_DISASSEMBLY_MEMO_MAX)
def _disassemble_loaded(va: int, size: int, file_offset: int, target: str) -> str:
    """Cached disassembly; :func:`get_disassembly` verified the DLL loads."""
    target_data = _load_dll(target)
    if target_data is None:
        # Raced a rebuild's DLL_DATA.clear() between the two loads, so this
        # slice is unresolvable rather than empty.  The "" lands in the memo
        # behind the broadcast's clear_disassembly_cache(), so it survives
        # until the next rebuild; the client refetches after the db-updated
        # frame.
        return ""

    code_bytes = target_data[file_offset : file_offset + size]
    if len(code_bytes) < size:
        return ""

    md = get_capstone_md()
    asm_lines = [
        f"0x{insn.address:08x}  {insn.mnemonic:8s} {insn.op_str}"
        for insn in md.disasm(code_bytes, va)
    ]

    return "\n".join(asm_lines) if asm_lines else "  (no instructions)"


def clear_disassembly_cache() -> None:
    """Drop memoized disassembly (called when the original binary changes)."""
    _disassemble_loaded.cache_clear()
