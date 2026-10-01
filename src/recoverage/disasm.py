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

from recoverage.server import _load_dll, binary_stamp

_log = logging.getLogger("recoverage")

#: Whether a capstone distribution is on the path at all.  NOT the capability
#: verdict: a wheel for the wrong architecture, a half-unpacked install or a
#: missing libcapstone shared object is found here and still fails on import,
#: so the callers gate on :func:`disassembly_available` instead.
_CAPSTONE_INSTALLED = importlib.util.find_spec("capstone") is not None

_CAPSTONE_MD_TLS = threading.local()

#: The x86 instruction width a binary is decoded at, when its container header
#: does not say.  32 is the historical answer this module always used, and it
#: is also what every 32-bit PE declares explicitly, so a header this reader
#: cannot make sense of keeps today's behaviour rather than losing it.
_DEFAULT_WIDTH_BITS = 32

#: Memoized width per binary stamp: one dict lookup on the request path instead
#: of re-reading the container header per slice, keyed on the SAME stat the
#: disassembly memo is keyed on so a rebuilt binary that changed architecture is
#: decoded at the new one's width rather than the previous one's.
_WIDTH_LOCK = threading.Lock()
_WIDTH_MEMO: dict[tuple[int, int, int], int] = {}
_WIDTH_MEMO_MAX = 64

#: How much of the file the container headers live in.  ELF is trivially
#: inside it (the 16-bit ``e_machine`` is at offset 18), PE is not: the DOS
#: header's ``e_lfanew`` is a FILE offset into the DOS stub, and real images
#: put the PE header anywhere past 0x80, so a 64-byte read — the length of the
#: smallest legal DOS header — names no ``Machine`` field and every PE would
#: read as unknown. 4096 is the window Microsoft's own loader tooling reads a
#: PE header out of, it bounds the read whatever the binary's size, and the
#: buffer is already in memory, so the cost is one short slice.
_CONTAINER_HEADER_BYTES = 4096

#: The container machine fields, read little-endian at these offsets: PE/COFF
#: puts a 16-bit ``Machine`` 4 bytes past its ``PE\0\0`` signature, and ELF puts
#: a 16-bit ``e_machine`` at 0x12 of the file.  Only the 64-bit member of the
#: x86 family is named, because 32 bits is the answer for everything else this
#: can decode: another machine has no x86 decoder, and rebrew's own
#: ``binary_loader`` picks the architecture from the same field, so recoverage
#: follows the producer rather than guessing wider.
_PE_MACHINE_AMD64 = 0x8664
_ELF_MACHINE_X86_64 = 62

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


def binary_width_bits(data: bytes) -> int:
    """The x86 instruction width *data*'s container header declares.

    64 for a 64-bit image, :data:`_DEFAULT_WIDTH_BITS` for a 32-bit one and for
    anything this cannot read: a header that is not PE/ELF at all, a truncated
    one, or a machine that is not the x86 family.  That last case is a
    deliberate floor rather than a guess — recoverage has no decoder for another
    architecture, and rebrew would have chosen one itself, so a 32-bit answer
    keeps the panel rendering what it always rendered instead of raising on a
    route that is contracted to answer.

    Every field is read little-endian, which is what PE/COFF and both x86 ELF
    variants specify; nothing here depends on the HOST's byte order, because
    the offsets and the widths are explicit rather than cast from a struct.
    """
    if len(data) >= 4 and data[:4] == b"\x7fELF":
        if len(data) < 0x14:
            return _DEFAULT_WIDTH_BITS
        machine = int.from_bytes(data[0x12:0x14], "little")
        if machine == _ELF_MACHINE_X86_64:
            return 64
        return _DEFAULT_WIDTH_BITS
    if len(data) >= 0x40 and data[:2] == b"MZ":
        # e_lfanew is a signed 32-bit file offset; a header that points outside
        # the bytes we hold names no Machine field, so it reads as unknown.
        pe_offset = int.from_bytes(data[0x3C:0x40], "little", signed=True)
        start = pe_offset + 4  # the PE signature is four bytes before Machine
        if pe_offset < 0 or start + 2 > len(data):
            return _DEFAULT_WIDTH_BITS
        if data[pe_offset : pe_offset + 4] != b"PE\x00\x00":
            return _DEFAULT_WIDTH_BITS
        machine = int.from_bytes(data[start : start + 2], "little")
        if machine == _PE_MACHINE_AMD64:
            return 64
        return _DEFAULT_WIDTH_BITS
    return _DEFAULT_WIDTH_BITS


def _target_width_bits(target: str, data: bytes) -> int:
    """:func:`binary_width_bits` for *target*, memoized on the binary's stat.

    Only the leading :data:`_CONTAINER_HEADER_BYTES` of *data* is read, which
    covers every field in both headers; the rest is a whole binary already in
    memory and is not this function's business.

    Keyed on the stamp for the reason every other binary-derived memo is: a
    rebuild can replace the file with one of a different architecture, and a
    width remembered from the previous build would decode the new one wrong.
    The bound is a memory bound on a dict keyed by a stat triple, and the
    oldest key goes first — a target whose binary is gone then re-reads its
    header, which is the free path.
    """
    stamp = binary_stamp(target)
    if stamp is None:
        return binary_width_bits(data[:_CONTAINER_HEADER_BYTES])
    with _WIDTH_LOCK:
        cached = _WIDTH_MEMO.get(stamp)
    if cached is not None:
        return cached
    width = binary_width_bits(data[:_CONTAINER_HEADER_BYTES])
    with _WIDTH_LOCK:
        if len(_WIDTH_MEMO) >= _WIDTH_MEMO_MAX:
            for oldest in list(_WIDTH_MEMO)[: len(_WIDTH_MEMO) - _WIDTH_MEMO_MAX + 1]:
                del _WIDTH_MEMO[oldest]
        _WIDTH_MEMO[stamp] = width
    return width


def clear_width_cache() -> None:
    """Forget every memoized width, alongside the disassembly memo."""
    with _WIDTH_LOCK:
        _WIDTH_MEMO.clear()


def _new_cs(bits: int = _DEFAULT_WIDTH_BITS) -> Any:
    """A Capstone handle in the ONE configuration this module asks for.

    Both the probe below and :func:`get_capstone_md` build their ``Cs`` here,
    so the configuration the probe certifies is the one the request path
    runs: they drifted once, and the probe verified a handle with ``detail``
    left at its default while every caller turned it off.

    *bits* is the image width :func:`binary_width_bits` read off the binary.
    Decoding a 64-bit image at 32 bits is not a smaller answer, it is a wrong
    one: a ``REX`` prefix is read as the start of the next instruction, every
    RIP-relative displacement as a ModRM, and the panel renders garbage over
    exactly the bytes the reader selected.  The probe passes the default because
    it certifies that capstone LOADS, and any mode a given handle is built with
    would answer that equally.
    """
    import capstone as _capstone

    mode = _capstone.CS_MODE_64 if bits == 64 else _capstone.CS_MODE_32
    md = _capstone.Cs(_capstone.CS_ARCH_X86, mode)
    md.detail = False
    return md


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
                _new_cs()
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


def get_capstone_md(bits: int = _DEFAULT_WIDTH_BITS) -> Any:
    """Return a thread-local Capstone disassembler for a *bits*-wide image.

    A single shared ``Cs`` instance is NOT safe to disassemble concurrently
    (libcapstone is not thread-safe) — with the threaded WSGI server, request
    threads were racing on it and producing garbage/crashes.

    Raises :class:`CapstoneUnavailableError` when the probe says the extra is
    unusable, so a caller that skipped the gate names the reason instead of
    dying on the import.

    *bits* selects among the handles this thread holds, one per width, because
    the mode is fixed at construction: a 32-bit and a 64-bit handle are two
    objects, and a project with a target of each width would otherwise decode
    whichever it built first.  Caching by width rather than by target is what
    keeps this bounded at two: the widths are what the binary can be, not what
    a caller asked for.
    """
    handle = getattr(_CAPSTONE_MD_TLS, "handles", None)
    if not handle:
        # An EMPTY cache is the same as no cache: the probe has to run before a
        # handle exists, and a test that empties the cache is asking for the
        # verdict, not for a handle built without one.
        reason = capstone_unavailable_reason()
        if reason is not None:
            raise CapstoneUnavailableError(reason)
        handle = _CAPSTONE_MD_TLS.handles = {}
    md = handle.get(bits)
    if md is None:
        md = handle[bits] = _new_cs(bits)
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
    stamp = binary_stamp(target)
    text = _disassemble_loaded(va, size, file_offset, target, stamp)
    if generation == _disassembly_generation():
        return text
    # A rebuild's invalidation overtook this build: the bytes just memoized
    # came from the binary the clear was meant to drop, and lru_cache has no
    # way to retract them. Clear again and rebuild from the current binary, so
    # the answer served is the one the post-rebuild client expects. Every
    # build in flight at the invalidation takes this path, so the window
    # closes for the whole herd rather than per request.
    clear_disassembly_cache()
    return _disassemble_loaded(va, size, file_offset, target, binary_stamp(target))


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
def _disassemble_loaded(
    va: int, size: int, file_offset: int, target: str, stamp: tuple[int, int, int] | None
) -> str:
    """Cached disassembly; :func:`get_disassembly` verified the DLL loads.

    *stamp* is :func:`recoverage.server.binary_stamp`, here only to key the memo
    on the binary the slice was read from: a replaced binary is a different key,
    where the target alone would serve the old binary's text.
    """
    target_data = _load_dll(target)
    if target_data is None:
        # Raced a rebuild's DLL_DATA.clear() between the two loads, so this
        # slice is unresolvable rather than empty.  The "" lands in the memo
        # behind the broadcast's clear_disassembly_cache(), so it survives
        # until the next rebuild; the client refetches after the db-updated
        # frame.
        return ""

    if file_offset < 0 or size < 0 or va < 0:
        # A negative offset or length is a negative-index slice, and a negative
        # index counts back from the END of the buffer: `data[-10:-5]` is five
        # bytes near the tail of the binary, so a hand-edited document carrying
        # a negative `fileOffset` answered with the disassembly of unrelated
        # bytes at the requested VA, in the one shape that passes the length
        # check below. api.py's /asm and /bytes both refuse a negative file
        # offset for this reason; the Potato panel hands this function the
        # document's own value, so the refusal belongs where both paths arrive.
        #
        # A negative VA is the same class of mistake in the ADDRESS rather than
        # in the slice: capstone's `insn.address` is unsigned, so a decode
        # started at -4096 renders every line as `0xfffffffffffff000`, an
        # address the reader never asked for, and the panel shows it beside
        # the byte dump of the very bytes it describes. A VA is a virtual
        # address in the image, so there is no reading of a negative one.
        return ""

    code_bytes = target_data[file_offset : file_offset + size]
    if len(code_bytes) < size:
        return ""

    md = get_capstone_md(_target_width_bits(target, target_data))
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
    # The memoized widths with it: a rebuild is exactly when the binary's
    # architecture can have changed, and the width is read off the SAME file
    # the memoized disassembly was decoded from.  The stamp keying them would
    # retire those entries on its own, so this is belt and braces for the
    # entries a rebuild raced past the stat — and it keeps the two memos from
    # outliving the reason they exist independently.
    clear_width_cache()
    _disassemble_loaded.cache_clear()
