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
                import capstone as _capstone

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
        import capstone as _capstone

        md = _capstone.Cs(_capstone.CS_ARCH_X86, _capstone.CS_MODE_32)
        md.detail = False
        _CAPSTONE_MD_TLS.md = md
    return md


#: Bumped by every :func:`clear_disassembly_cache`.  An lru_cache cannot retract
#: an entry that lands after ``cache_clear()``, so a build that read the binary
#: before a rebuild and stores its result after the clear leaves a stale entry
#: nothing will invalidate again.  The counter is that build's check: a build
#: whose generation changed by the time it returns drops what it just stored.
#: Its lock is what makes the bump one step rather than three: the broadcast
#: runs on the SSE watcher thread and the regen invalidation on the request
#: thread, so two invalidations can land at once, and ``g += 1`` alone loses
#: one of them — a build overlapping the lost update compares two generations
#: that differ only because the counter moved at all, which is the whole of
#: what this counter has to say.
_GENERATION_LOCK = threading.Lock()
_DISASSEMBLY_GENERATION = 0


def _disassembly_generation() -> int:
    """The current generation, read under the lock that moves it.

    :func:`get_disassembly` reads this twice per request and compares; both
    reads take the lock, so the pair it compares is two states of the counter
    rather than a half-applied bump.
    """
    with _GENERATION_LOCK:
        return _DISASSEMBLY_GENERATION


def get_disassembly(va: int, size: int, file_offset: int, target: str) -> str:
    """Disassemble *size* bytes of *target* at *va*, memoized per slice.

    The DLL-load guard deliberately stays OUTSIDE the memo cache: ``_load_dll``
    leaves transient OS failures uncached so the next request self-heals, and
    memoizing their "" result here would pin that outage until the next
    rebuild broadcast happened to clear the cache.
    """
    if _load_dll(target) is None:
        return ""
    generation = _disassembly_generation()
    text = _disassemble_loaded(va, size, file_offset, target)
    if generation == _disassembly_generation():
        return text
    # A rebuild's invalidation overtook this build: the bytes just memoized
    # came from the binary the clear was meant to drop, and lru_cache has no
    # way to retract them. Clear again and rebuild from the current binary, so
    # the answer served is the one the post-rebuild client expects. Every
    # build in flight at the invalidation takes this path, so the window
    # closes for the whole herd rather than per request.
    clear_disassembly_cache()
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
    """Drop memoized disassembly (called when the original binary changes).

    Bumps :data:`_DISASSEMBLY_GENERATION` first: a build already in flight
    cannot be stopped, so it has to learn that what it is about to store is
    stale (see :func:`get_disassembly`).

    The bump is one critical section and the ``cache_clear`` that follows it is
    not: a build that reads the generation while the memo is still being
    emptied sees the new value, decides an invalidation overtook it, and clears
    again itself, which is the path that closes the window anyway. Holding the
    lock across the lru sweep would only make every other build wait for it.
    """
    global _DISASSEMBLY_GENERATION
    with _GENERATION_LOCK:
        _DISASSEMBLY_GENERATION += 1
    _disassemble_loaded.cache_clear()
