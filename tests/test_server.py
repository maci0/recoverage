"""Tests for recoverage.server — compression, encoding, path helpers, response helpers."""

from __future__ import annotations

import gzip
import itertools
import json
import logging
import queue
import re
import shutil
import subprocess
import tempfile
import threading
import time
from collections.abc import Sequence
from pathlib import Path
from typing import IO, Any, ClassVar

import brotli
import pytest
import zstandard as zstd
from coverage_fixture import TOML_VERSION, cell, coverage_dir, write_coverage
from rebrew.coverage_toml import CoverageSnapshot, CoverageTomlError, load_coverage

from recoverage import clock
from recoverage.server import (
    DLL_DATA,
    DLL_LOCK,
    SUPPORTED_ENCODINGS,
    _best_encoding,
    _db_path,
    _find_dll_path,
    _load_dll,
    _project_dir,
    clear_target_cache,
    compress_payload,
    compress_static_bodies,
    fold_match,
    fold_match_folded,
    fold_needle,
    fold_text,
    globals_by_va,
    lookup_global,
    origin_is_this_dashboard,
    select_static_variant,
    static_variant_key,
    verify_by_va,
)


def _coverage_dir(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    """Point the server at a test-local coverage directory and return it.

    Every test that serves its own documents goes through this, rather than
    setting the variable and hoping the two readers land in the same place.
    """
    directory = coverage_dir(tmp_path)
    monkeypatch.setenv("RECOVERAGE_DB", str(directory))
    return directory


def _snapshot_for(sections: dict[str, dict[str, Any]], **kwargs: Any) -> CoverageSnapshot:
    """One target's snapshot, built by the reader the server actually uses.

    Written to a throwaway directory rather than hand-constructed: ``buckets``,
    ``covered_bytes``, ``coverage_pct`` and ``function_stats`` are all derived,
    and a snapshot assembled in the test would be a second formula to keep in
    step with the reader's.
    """
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        write_coverage(root / "db", "T", sections, **kwargs)
        return load_coverage(root, "T")


def _cell_section(
    states: Sequence[str], *, name: str = ".text", va: int = 0x1000
) -> dict[str, Any]:
    """A section table holding one one-byte cell per state, in order."""
    return {
        "va": va,
        "size": len(states),
        "fileOffset": 0,
        "unitBytes": 1,
        "columns": 1,
        "cells": [cell(i, i + 1, state) for i, state in enumerate(states)],
    }


# ── Advisory-lock probe ────────────────────────────────────────────


def _probe_free_lock(fh: IO[bytes]) -> None:
    """Raise BlockingIOError unless *fh*'s advisory lock is free.

    Mirrors the split the production lock makes (rebrew's
    ``file_handle_lock``: ``fcntl`` on POSIX, ``msvcrt`` elsewhere), so the
    caller probes the same mechanism the server takes on this platform —
    importing fcntl unconditionally would fail the run on the Windows
    CI runner.
    """
    try:
        import fcntl
    except ImportError:  # Windows
        import msvcrt

        fh.seek(0)
        try:
            msvcrt.locking(fh.fileno(), msvcrt.LK_NBLCK, 1)
        except OSError as exc:
            raise BlockingIOError(str(exc)) from exc
        fh.seek(0)
        msvcrt.locking(fh.fileno(), msvcrt.LK_UNLCK, 1)
        return
    fcntl.flock(fh, fcntl.LOCK_EX | fcntl.LOCK_NB)
    fcntl.flock(fh, fcntl.LOCK_UN)


# ── _best_encoding ─────────────────────────────────────────────────


class TestBestEncoding:
    def test_prefers_zstd(self) -> None:
        assert _best_encoding("gzip, br, zstd") == "zstd"

    def test_prefers_br_over_gzip(self) -> None:
        assert _best_encoding("gzip, br") == "br"

    def test_falls_back_to_gzip(self) -> None:
        assert _best_encoding("gzip") == "gzip"

    def test_empty_returns_empty(self) -> None:
        assert _best_encoding("") == ""

    def test_identity_returns_empty(self) -> None:
        assert _best_encoding("identity") == ""

    def test_strips_quality_values(self) -> None:
        assert _best_encoding("gzip;q=0.5, br;q=1.0") == "br"

    def test_case_insensitive(self) -> None:
        assert _best_encoding("GZIP, BR") == "br"

    def test_no_false_substring_match(self) -> None:
        """Encoding token 'not-zstd' should not match 'zstd'."""
        assert _best_encoding("not-zstd") == ""

    def test_whitespace_handling(self) -> None:
        assert _best_encoding("  gzip  ,  br  ") == "br"

    # ── Adversarial Accept-Encoding inputs ─────────────────────────

    def test_null_byte_in_encoding(self) -> None:
        """Null bytes in header must not crash or produce false match."""
        result = _best_encoding("gzip\x00, br")
        # "gzip\x00" is not "gzip" — null byte prevents match; "br" is clean
        assert result == "br"

    def test_very_long_header(self) -> None:
        """Header with many tokens should still work."""
        tokens = ", ".join(f"enc{i}" for i in range(1000)) + ", gzip"
        assert _best_encoding(tokens) == "gzip"

    def test_semicolons_only(self) -> None:
        assert _best_encoding(";;;") == ""

    def test_commas_only(self) -> None:
        assert _best_encoding(",,,") == ""

    def test_duplicate_encodings(self) -> None:
        assert _best_encoding("gzip, gzip, gzip") == "gzip"

    @pytest.mark.parametrize(
        "header,expected",
        [
            ("*", ""),
            ("zstd, br, gzip, deflate, sdch", "zstd"),
            ("br;q=1.0, gzip;q=0.5, zstd;q=0.9", "zstd"),
        ],
    )
    def test_various_real_world_headers(self, header: str, expected: str) -> None:
        assert _best_encoding(header) == expected


# ── compress_payload ───────────────────────────────────────────────


class TestCompressPayload:
    def test_gzip_roundtrip(self) -> None:
        data = b"hello world" * 100
        compressed, encoding = compress_payload(data, "gzip")
        assert encoding == "gzip"
        assert gzip.decompress(compressed) == data

    def test_no_compression(self) -> None:
        data = b"hello"
        result, encoding = compress_payload(data, "identity")
        assert encoding == ""
        assert result == data

    def test_brotli_returns_br(self) -> None:
        data = b"x" * 100
        _, encoding = compress_payload(data, "br")
        assert encoding == "br"

    def test_zstd_returns_zstd(self) -> None:
        data = b"x" * 100
        _, encoding = compress_payload(data, "zstd")
        assert encoding == "zstd"

    # ── Compression roundtrip fuzz ────────────────────────────────

    def test_brotli_roundtrip(self) -> None:
        data = b"decompression test data " * 50
        compressed, encoding = compress_payload(data, "br")
        assert encoding == "br"
        assert brotli.decompress(compressed) == data

    def test_zstd_roundtrip(self) -> None:
        data = b"zstandard roundtrip " * 50
        compressed, encoding = compress_payload(data, "zstd")
        assert encoding == "zstd"
        dctx = zstd.ZstdDecompressor()
        assert dctx.decompress(compressed) == data

    def test_empty_payload(self) -> None:
        compressed, encoding = compress_payload(b"", "gzip")
        assert encoding == "gzip"
        assert gzip.decompress(compressed) == b""

    def test_single_byte_payload(self) -> None:
        compressed, encoding = compress_payload(b"\xff", "br")
        assert encoding == "br"
        assert brotli.decompress(compressed) == b"\xff"

    def test_binary_payload(self) -> None:
        """Full byte range should compress and decompress correctly."""
        data = bytes(range(256)) * 10
        compressed, _encoding = compress_payload(data, "gzip")
        assert gzip.decompress(compressed) == data

    def test_unknown_encoding_passes_through(self) -> None:
        data = b"passthrough"
        result, encoding = compress_payload(data, "deflate")
        assert encoding == ""
        assert result == data

    def test_concurrent_zstd_roundtrip(self) -> None:
        """compress_payload must be safe under concurrent request threads.

        A shared module-level ZstdCompressor is not supported by
        python-zstandard (the C extension releases the GIL during compress,
        so threads shared one ZSTD_CCtx and the process segfaulted).  Each
        thread compresses its own payload; every output must round-trip.
        """
        payloads = [bytes([i % 256]) * 4096 + b"payload-%d" % i for i in range(16)]
        results: list[tuple[bytes, str] | None] = [None] * len(payloads)
        errors: list[BaseException] = []

        def worker(idx: int) -> None:
            try:
                results[idx] = compress_payload(payloads[idx], "zstd")
            except BaseException as exc:
                errors.append(exc)

        threads = [threading.Thread(target=worker, args=(i,)) for i in range(len(payloads))]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        assert not errors
        dctx = zstd.ZstdDecompressor()
        for idx, (data, res) in enumerate(zip(payloads, results, strict=True)):
            assert res is not None
            compressed, encoding = res
            assert encoding == "zstd"
            assert dctx.decompress(compressed) == data, f"thread {idx} payload corrupted"


# ── Precompressed static variants ───────────────────────────────────


class TestStaticVariantSelection:
    """A precompressed body is chosen by SIZE among what the client accepts.

    Handing a client a body in an encoding it did not advertise is the failure
    this exists to prevent, and a fixed preference is what caused it: every
    zstd-capable browser was served 3 KB more than the shell needed.
    """

    #: Shorter wins; the lengths are arbitrary, only their order is the test.
    _CANDIDATES: ClassVar[dict[str, bytes]] = {
        "zstd": b"z" * 10,
        "br": b"b" * 20,
        "gzip": b"g" * 30,
    }

    def test_smallest_accepted_wins(self) -> None:
        body, encoding = select_static_variant(self._CANDIDATES, "gzip, br, zstd", b"identity")
        assert encoding == "zstd"
        assert body == self._CANDIDATES["zstd"]

    def test_a_smaller_body_the_client_did_not_accept_is_never_served(self) -> None:
        """zstd is the smallest candidate; a gzip-only client must not get it."""
        body, encoding = select_static_variant(self._CANDIDATES, "gzip", b"identity")
        assert encoding == "gzip"
        assert body == self._CANDIDATES["gzip"]

    def test_a_tie_goes_to_the_earlier_supported_encoding(self) -> None:
        """Equal lengths are served under one name, so the cache stays keyed."""
        tied = {"zstd": b"z" * 16, "br": b"b" * 16, "gzip": b"g" * 40}
        assert select_static_variant(tied, "br, zstd", b"identity") == (tied["zstd"], "zstd")
        assert select_static_variant(tied, "gzip, br", b"identity") == (tied["br"], "br")

    @pytest.mark.parametrize("header", ["", "identity", "deflate", "*"])
    def test_nothing_accepted_returns_the_identity_body(self, header: str) -> None:
        """An empty encoding name is the caller's signal to set no header."""
        body, encoding = select_static_variant(self._CANDIDATES, header, b"identity")
        assert (body, encoding) == (b"identity", "")

    def test_static_variant_key_names_the_accepted_subset_in_a_fixed_order(self) -> None:
        """The key is itself a valid Accept-Encoding, so a cache can pre-build it."""
        assert static_variant_key("br, gzip") == "br, gzip"
        assert static_variant_key("gzip, br") == "br, gzip"
        assert static_variant_key("deflate") == ""
        assert static_variant_key("") == ""

    def test_static_variant_key_is_bounded_by_the_supported_alphabets(self) -> None:
        """Whatever the client sends, at most 2**3 keys can exist.

        The header is attacker-controlled and the key is what precompressed
        bodies are cached and pre-built under, so an unbounded key space is an
        unbounded cache and an unbounded set of compressions.
        """
        keys = {
            static_variant_key(header)
            for header in itertools.chain(
                ("gzip", "br", "zstd", "gzip, br", "br, zstd", "gzip, zstd"),
                (
                    ", ".join(subset)
                    for subset in itertools.chain.from_iterable(
                        itertools.combinations(SUPPORTED_ENCODINGS, n) for n in range(4)
                    )
                ),
            )
        }
        assert len(keys) == 2 ** len(SUPPORTED_ENCODINGS)
        assert static_variant_key(", ".join(SUPPORTED_ENCODINGS)) in keys

    def test_every_supported_encoding_decompresses_to_the_same_body(self) -> None:
        """The precompressed set is one body in three encodings, not three bodies."""
        body = b"the quick brown fox jumps over the lazy dog " * 64
        bodies = compress_static_bodies(body)
        assert set(bodies) == set(SUPPORTED_ENCODINGS)
        assert zstd.ZstdDecompressor().decompress(bodies["zstd"]) == body
        assert brotli.decompress(bodies["br"]) == body
        assert gzip.decompress(bodies["gzip"]) == body


# ── Path helpers ───────────────────────────────────────────────────


class TestPathHelpers:
    def test_project_dir_is_absolute(self) -> None:
        assert _project_dir().is_absolute()

    def test_db_path_is_the_coverage_directory(self) -> None:
        """The storage layer names a DIRECTORY now: one document per target.

        ``RECOVERAGE_DB`` used to name ``coverage.db`` itself; the name is kept
        and names the directory that file used to live in, so every consumer
        that wants "where does the coverage live" still has one answer.
        """
        assert _db_path().name == "db"
        assert _db_path().parent == Path.cwd()

    def test_find_dll_path_none_for_unconfigured_target(self) -> None:
        """A target with no [targets.<tid>].binary must return None, not a
        silently-served fallback (SERVER's DLL) — the caller then reports a
        target-specific error instead of plausible-but-wrong disassembly."""
        clear_target_cache()
        assert _find_dll_path("NONEXISTENT") is None

    def test_find_dll_path_resolves_configured_binary(self, monkeypatch: Any) -> None:
        from unittest.mock import patch

        from recoverage import server as srv

        with (
            patch.object(srv, "_project_dir", return_value=Path("/proj")),
            patch.object(
                srv, "_get_targets_config", return_value={"GAME": {"filename": "bin/game.dll"}}
            ),
        ):
            assert _find_dll_path("GAME") == Path("/proj/bin/game.dll")


# ── DB-freshness ETags ─────────────────────────────────────────────


class TestDbEtag:
    """DB-freshness ETags must key on the WHOLE coverage directory.

    A rebuild writes one ``coverage-<target>.toml`` per target, so a target
    added, rewritten or removed anywhere in the directory has to move the change
    token behind every ETag.  A token derived from one file (the raw ``st_mtime``
    the WAL-aware ``coverage.db`` snapshot replaced) would keep answering 304
    while another target's ``/data``, ``/asm``, ``/bytes`` and ``/potato``
    responses were stale.
    """

    @staticmethod
    def _doc(directory: Path, target: str) -> Path:
        return write_coverage(directory, target, {".text": _cell_section(["exact"])})

    def test_snapshot_tracks_a_rewritten_document(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        import recoverage.server as srv

        directory = _coverage_dir(tmp_path, monkeypatch)
        first = self._doc(directory, "FAKEDLL")
        self._doc(directory, "OTHER")
        before = srv._snapshot_db_mtime()
        assert before is not None

        # Appending moves BOTH halves of the stat the token folds, so the test
        # does not depend on the filesystem's mtime granularity.
        first.write_text(first.read_text(encoding="utf-8") + "# rebuilt\n", encoding="utf-8")
        after = srv._snapshot_db_mtime()
        assert after is not None
        assert after != before

    def test_snapshot_tracks_a_document_that_disappears(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """A target deleted by a scoped rebuild must invalidate the token too."""
        import recoverage.server as srv

        directory = _coverage_dir(tmp_path, monkeypatch)
        self._doc(directory, "FAKEDLL")
        gone = self._doc(directory, "OTHER")
        before = srv._snapshot_db_mtime()

        gone.unlink()
        assert srv._snapshot_db_mtime() != before

    def test_etag_changes_on_a_document_rewrite(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """The /asm//bytes/potato ETag input must move when a document does."""
        import recoverage.server as srv

        directory = _coverage_dir(tmp_path, monkeypatch)
        first = self._doc(directory, "FAKEDLL")
        before = srv._etag_or_304(srv._snapshot_db_mtime(), "FAKEDLL", ".text", 16)
        assert before is not None

        first.write_text(first.read_text(encoding="utf-8") + "# rebuilt\n", encoding="utf-8")
        after = srv._etag_or_304(srv._snapshot_db_mtime(), "FAKEDLL", ".text", 16)
        assert after is not None
        assert after != before

    def test_etag_none_when_the_directory_is_empty(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """No document is the old missing-file answer: no token, so no ETag."""
        import recoverage.server as srv

        _coverage_dir(tmp_path, monkeypatch)
        assert srv._snapshot_db_mtime() is None
        assert srv._etag_or_304(srv._snapshot_db_mtime(), "T") is None

    def test_matching_if_none_match_raises_304(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        import recoverage.server as srv

        directory = _coverage_dir(tmp_path, monkeypatch)
        self._doc(directory, "T")
        etag = srv._etag_or_304(srv._snapshot_db_mtime(), "T")

        class _Req:
            headers: ClassVar[dict[str, str]] = {"If-None-Match": etag}

        monkeypatch.setattr(srv, "request", _Req())
        with pytest.raises(srv.HTTPResponse) as excinfo:
            srv._etag_or_304(srv._snapshot_db_mtime(), "T")
        assert excinfo.value.status_code == 304


# ── clear_target_cache ─────────────────────────────────────────────


class TestClearTargetCache:
    def test_clear_is_safe_when_empty(self) -> None:
        """Clearing an already-empty cache is a no-op, not a KeyError.

        Asserting the resulting state rather than "did not raise" also pins
        the part that is easy to get wrong: a second clear must leave every
        global None, not a half-reset pair.
        """
        import recoverage.server as srv

        clear_target_cache()
        srv._TOML_CONFIG_CACHE = {"a": 1}
        srv._TOML_CACHE_MTIME = (1, 2)
        srv._RESOLVED_TARGETS_CACHE = ["T"]

        clear_target_cache()
        assert srv._TOML_CONFIG_CACHE is None
        assert srv._TOML_CACHE_MTIME is None
        assert srv._RESOLVED_TARGETS_CACHE is None

        # Idempotent: a second clear over the emptied state changes nothing.
        clear_target_cache()
        assert srv._TOML_CONFIG_CACHE is None
        assert srv._RESOLVED_TARGETS_CACHE is None

    def test_thread_safety(self) -> None:
        errors: list[Exception] = []

        def _clear() -> None:
            try:
                for _ in range(100):
                    clear_target_cache()
            except Exception as e:
                errors.append(e)

        threads = [threading.Thread(target=_clear) for _ in range(4)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        assert not errors


# ── Search folding ─────────────────────────────────────────────────


class TestSearchFolding:
    """A search term is TEXT, matched caselessly, never a pattern.

    This is the guarantee the SQLite-era LIKE escaping protected, restated over
    the in-memory folding that replaced it.  The escaping existed because the
    term was interpolated into a LIKE pattern; the documents are read into
    Python now, so there is no pattern to escape — and the property that has to
    survive the move is the same one: `%`, `_` and `\\` are ordinary characters
    a user may search for, `ß` matches `ss`, and the NFD spelling of a name
    matches its NFC twin.
    """

    def test_match_is_case_insensitive(self) -> None:
        assert fold_match("_func_a", "FUNC")

    def test_percent_is_a_literal(self) -> None:
        assert fold_match("100%", "%")
        assert not fold_match("1000", "%")

    def test_underscore_is_a_literal(self) -> None:
        assert fold_match("foo_bar", "_")
        assert not fold_match("fooxbar", "_")

    def test_backslash_is_a_literal(self) -> None:
        assert fold_match("c:\\path", "\\")
        assert not fold_match("c:path", "\\")

    def test_a_run_of_wildcards_is_matched_whole(self) -> None:
        assert fold_match("%%%", "%%%")
        assert not fold_match("---", "%%%")

    def test_empty_term_matches_anything(self) -> None:
        assert fold_match("alloc", "")
        assert fold_match(None, "")

    def test_absent_column_matches_no_nonempty_term(self) -> None:
        """NULL folded as the empty string, which is what COALESCE gave it."""
        assert not fold_match(None, "x")

    def test_unicode_term_is_matched_literally(self) -> None:
        assert fold_match("日本語", "日本語")
        assert not fold_match("日本語", "語日")

    def test_sql_injection_spelling_is_ordinary_text(self) -> None:
        """Nothing is interpolated into SQL now; the spelling that used to need
        escaping must still be searchable, and must not match anything else."""
        injection = "' OR 1=1; DROP TABLE--"
        assert fold_match(injection, injection)
        assert not fold_match("harmless", injection)

    def test_casefold_expansion_matches_both_spellings(self) -> None:
        """ß casefolds to ss, so either spelling finds the one row."""
        assert fold_match("straße", "STRASSE")
        assert fold_match("STRASSE", "straße")

    def test_nfd_spelling_matches_its_nfc_twin(self) -> None:
        """A name written by a macOS-side tool is NFD; the stored one is NFC."""
        import unicodedata

        nfd = unicodedata.normalize("NFD", "café")
        assert nfd != "café"
        assert fold_match("café", nfd)
        assert fold_match(nfd, "café")

    def test_fold_text_passes_an_absent_column_through(self) -> None:
        assert fold_text(None) is None
        assert fold_text("_Func_A") == "_func_a"

    def test_the_prefolded_needle_answers_as_the_whole_needle_does(self) -> None:
        """A collection scan folds the term once; the answers must not move."""
        for haystack, needle in (
            ("_func_a", "FUNC"),
            ("straße", "STRASSE"),
            ("100%", "%"),
            ("日本語", "日本語"),
            (None, "x"),
            (None, ""),
        ):
            assert fold_match_folded(haystack, fold_needle(needle)) == fold_match(haystack, needle)


class TestSnapshotVaIndices:
    """The by-VA indices a snapshot does not carry answer as the scan did.

    rebrew's snapshot has ``functions_by_va`` and nothing for ``globals`` or
    ``verify_results``, so the batch endpoint and the detail panel built their
    own index per request or walked the array outright.  These pin the two
    answers that must not move: the FIRST global for a repeated VA, and a
    verify row whose ``va`` is not an int being unmatchable.
    """

    def test_globals_resolve_by_va(self) -> None:
        snap = _snapshot_for(
            {},
            globals_=[
                {"va": 0x2000, "name": "g_first"},
                {"va": 0x2004, "name": "g_second"},
            ],
        )
        index = globals_by_va(snap)
        assert index[0x2000].name == "g_first"
        assert index[0x2004].name == "g_second"
        assert lookup_global(snap, "0x2004").name == "g_second"
        assert 0x2008 not in index

    def test_a_repeated_global_va_keeps_the_first_row(self) -> None:
        """The linear scan this index replaced returned the first match."""
        snap = _snapshot_for(
            {},
            globals_=[
                {"va": 0x2000, "name": "g_first"},
                {"va": 0x2000, "name": "g_second"},
            ],
        )
        assert globals_by_va(snap)[0x2000].name == "g_first"
        assert lookup_global(snap, "0x2000").name == "g_first"

    def test_verify_rows_index_by_va_and_repeat_calls_reuse_the_memo(self) -> None:
        snap = _snapshot_for(
            {},
            functions=[{"va": 0x1000, "name": "f"}],
            verify_results=[{"va": 0x1000, "byte_delta": 3}, {"va": "0x1004", "byte_delta": 9}],
        )
        index = verify_by_va(snap)
        assert index[0x1000]["byte_delta"] == 3
        assert "0x1004" not in index
        assert verify_by_va(snap) is index
        assert globals_by_va(snap) is globals_by_va(snap)

    def test_two_snapshots_do_not_share_one_index(self) -> None:
        first = _snapshot_for({}, globals_=[{"va": 0x2000, "name": "g_first"}])
        second = _snapshot_for({}, globals_=[{"va": 0x2000, "name": "g_other"}])
        assert globals_by_va(first)[0x2000].name == "g_first"
        assert globals_by_va(second)[0x2000].name == "g_other"


class TestCoverageDocumentShapeGuard:
    """A document that is not shaped like this schema must not serve.

    The SQLite reader stamped a schema version into a ``metadata`` row and
    probed the objects that version implied (``PRAGMA table_info``, the
    ``section_cell_stats`` view, the v6 optional columns), reporting
    ``<incomplete>`` so the endpoints answered the 503 contract instead of
    failing at query time.  A document carries its own ``version`` and its
    shape is checked as it is parsed: a foreign version, a non-table
    ``sections`` and a ``cells`` value that is not an array of tables are all
    the same answer — this target is not readable, and the caller gets
    ``db_unavailable``.
    """

    def test_well_formed_document_reports_its_version(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        import recoverage.server as srv

        directory = _coverage_dir(tmp_path, monkeypatch)
        write_coverage(directory, "GAME", {".text": _cell_section(["exact"])})
        snap = srv.coverage_snapshots()["GAME"]
        assert srv.coverage_version(snap) == str(TOML_VERSION)
        assert srv.known_schema_versions() == [str(TOML_VERSION)]

    @pytest.mark.parametrize(
        ("label", "body"),
        [
            # A version this reader does not implement: reading it the way the
            # vocabulary happens to line up is how a foreign layout is guessed at.
            ("foreign_version", 'version = 42\ntarget = "GAME"\n'),
            # `sections` written as a scalar: the table the whole payload hangs
            # off is not a table.
            ("sections_not_a_table", "sections = 4\n"),
            # A cells row that is not a table: the row shape is not this
            # schema's, so no field can be trusted.
            (
                "cells_row_not_a_table",
                'version = 1\ntarget = "GAME"\n[sections.".text"]\nva = 0\ncells = [1, 2]\n',
            ),
            # `functions` as a table instead of the array of tables the writer
            # emits.
            ("functions_not_an_array", "functions = { va = 1 }\n"),
        ],
    )
    def test_a_shape_violation_is_unreadable(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, label: str, body: str
    ) -> None:
        import recoverage.server as srv

        directory = _coverage_dir(tmp_path, monkeypatch)
        directory.mkdir(parents=True, exist_ok=True)
        (directory / f"coverage-{label}.toml").write_text(body, encoding="utf-8")

        with pytest.raises(CoverageTomlError):
            srv.coverage_snapshots()


class TestCoverageVersionGate:
    """The version this server writes and reads is the one it advertises."""

    def test_fixture_version_is_what_the_reader_accepts(self) -> None:
        """The fixture's TOML_VERSION is the format both sides are written to.

        ``known_schema`` is served to the SPA so it can tell "no section rows
        yet" from "this build does not understand the file"; a version in that
        list that no reader accepts would make that message wrong.
        """
        import rebrew.coverage_toml as cov

        assert cov._TOML_VERSION == TOML_VERSION

    def test_known_schema_names_only_readable_versions(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """A version the reader refuses never reaches the served list.

        The SQLite reader accepted a RANGE of stamps and reported which one it
        found; a document carries exactly one version and either parses or does
        not, so the list has to be read off the snapshots that were built rather
        than off a constant.  Naming a version nothing serves is what makes the
        SPA's "this build does not understand the file" message lie.
        """
        import recoverage.server as srv

        directory = _coverage_dir(tmp_path, monkeypatch)
        write_coverage(directory, "GAME", {".text": _cell_section(["exact"])})
        (directory / "coverage-FOREIGN.toml").write_text(
            'version = 42\ntarget = "FOREIGN"\n', encoding="utf-8"
        )

        assert srv.known_schema_versions() == [str(TOML_VERSION)]
        assert srv.db_target_ids() == ["GAME"]

    def test_the_served_cell_payload_has_no_surrogate_id(self) -> None:
        """The stored cell is served as the file holds it and nothing more.

        ``build_db``'s ``cells`` table had a surrogate ``id`` (dropped again in
        the current producer); a client never saw it and must not start.  The
        keys are the whole contract — the document's own columns, minus the two
        optional ones the payload omits when empty.
        """
        import recoverage.server as srv

        snap = _snapshot_for(
            {".text": _cell_section(["exact"])},
            functions=[{"va": 0x1000, "name": "f", "status": "EXACT", "size": 1}],
        )
        stored = json.loads(srv.cells_json(snap.sections[".text"].cells))
        assert stored == [{"start": 0, "end": 1, "span": 1, "state": "exact"}]
        assert "id" not in stored[0]
        assert srv._bucket_row(snap.sections[".text"])["exact"] == 1


class TestCoverageReadsAreSideEffectFree:
    """Reading coverage must not write to the directory the operator owns.

    ``_open_db`` opened ``coverage.db`` read-only (``immutable=1``) and took a
    shared advisory lock, so a running dashboard could not corrupt the file a
    build was replacing and left a stray ``.lock`` behind.  The documents need
    neither — the reader only stats and reads them — and that is the property
    worth pinning on this side: a full read path leaves the directory
    byte-identical, so the dashboard can run beside the builder that owns it.
    """

    def test_a_read_leaves_the_directory_untouched(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        import recoverage.server as srv

        directory = _coverage_dir(tmp_path, monkeypatch)
        write_coverage(directory, "GAME", {".text": _cell_section(["exact"])})

        def listing() -> dict[str, tuple[int, bytes]]:
            return {
                p.name: (p.stat().st_mtime_ns, p.read_bytes()) for p in sorted(directory.iterdir())
            }

        before = listing()
        srv.coverage_snapshots()
        srv.resolve_targets()
        srv._bucket_row(srv.coverage_for("GAME").sections[".text"])
        assert listing() == before

    def test_the_lock_sidecar_is_not_part_of_the_format(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """A ``coverage.db.lock`` left over from the SQLite era is ignored.

        The reader globs ``coverage-*.toml``, so a stale sidecar is neither read
        nor mistaken for a target, and nothing recreates one.
        """
        import recoverage.server as srv

        directory = _coverage_dir(tmp_path, monkeypatch)
        write_coverage(directory, "GAME", {".text": _cell_section(["exact"])})
        (directory / "coverage.db.lock").write_bytes(b"")

        assert srv.db_target_ids() == ["GAME"]
        assert not (directory / "coverage-GAME.toml.lock").exists()


class TestSnapshotIsTheReadPin:
    """A multi-statement read must see ONE build.

    Python's sqlite3 opened a deferred transaction per statement, so a rebuild
    committing between two reads of the same table answered the second from the
    new build; ``read_snapshot`` pinned the version for the whole block instead.
    A snapshot is frozen and memoized on the directory's own stat, so the same
    consistency is held by the type and the reader: two reads inside one
    response get THE SAME snapshot, and a rebuild that lands between them
    cannot be observed by the first one.
    """

    @staticmethod
    def _write(directory: Path, size: int) -> None:
        write_coverage(
            directory,
            "GAME",
            {
                ".text": {
                    "va": 0x1000,
                    "size": size,
                    "fileOffset": 0x200,
                    "unitBytes": 16,
                    "columns": 8,
                    "cells": [cell(0, 16, "exact")],
                }
            },
        )

    def test_a_rebuild_mid_read_is_invisible(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        import recoverage.server as srv

        directory = _coverage_dir(tmp_path, monkeypatch)
        self._write(directory, 16)
        pinned = srv.coverage_snapshots()["GAME"]
        before = pinned.sections[".text"].size

        # The rebuild lands between the two reads.
        self._write(directory, 99)
        during = pinned.sections[".text"].size
        # Outside the pin the next read sees the committed rebuild.
        after = srv.coverage_snapshots()["GAME"].sections[".text"].size

        assert before == during == 16
        assert after == 99

    def test_an_unchanged_directory_returns_the_same_snapshot(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """The identity is the change token every DB-derived memo keys on."""
        import recoverage.server as srv

        directory = _coverage_dir(tmp_path, monkeypatch)
        self._write(directory, 16)
        assert srv.coverage_snapshots()["GAME"] is srv.coverage_snapshots()["GAME"]

    def test_a_snapshot_cannot_be_mutated(self) -> None:
        """The freeze is what replaces the read transaction: a caller cannot
        publish half of one build alongside half of the next."""
        snap = _snapshot_for({".text": _cell_section(["exact"])})
        with pytest.raises(AttributeError):
            snap.target = "OTHER"  # type: ignore[misc]
        with pytest.raises(TypeError):
            snap.sections[".text"] = None  # type: ignore[index]


class TestSpaFilterControls:
    """The status filters match what the two renderers share.

    A filter name no button offers dims every painted cell and lights none, and
    a pill with no key in the state table isolates nothing: the toolbar, the
    deep link, the dimming pass and Potato Mode all read the same vocabulary.
    """

    def test_filter_url_names_are_allowlisted(self) -> None:
        from recoverage.potato import FILTER_STATES

        pack = _web("grid/pack.ts")
        raw = re.search(r"export const FILTER_KEY = \[(.*?)\];", pack).group(1)
        keys = set(re.findall(r'"([a-z_]*)"', raw))
        assert keys - {""} == set(FILTER_STATES)

    def test_every_filter_key_has_a_button(self) -> None:
        from recoverage.potato import FILTER_STATES

        app = _web("App.tsx")
        buttons = set(re.findall(r'key: "([a-z_]+)"', app))
        assert buttons - {"all"} == set(FILTER_STATES)

    def test_every_packed_state_survives_a_filter(self) -> None:
        """A "" in FILTER_KEY means the cell is dimmed by every pill and lit by
        none, which is the state the two missing buttons were for."""
        pack = _web("grid/pack.ts")
        raw = re.search(r"export const FILTER_KEY = \[(.*?)\];", pack, re.DOTALL).group(1)
        keys = [value.strip().strip('"') for value in raw.split(",") if value.strip()]
        assert keys[:6] == ["", "exact", "reloc", "near_match", "stub", "padding"]
        assert keys[6:] == ["proven", "problem"]


# ── Token auth & security headers ──────────────────────────────────


class TestAuthTokenMatches:
    """_auth_token_matches must accept the right token only, in constant time."""

    def test_correct_token_accepted(self, monkeypatch: Any) -> None:
        import recoverage.server as srv

        monkeypatch.setattr(srv, "_AUTH_TOKEN", "hunter2")
        assert srv._auth_token_matches("hunter2") is True

    def test_wrong_token_rejected(self, monkeypatch: Any) -> None:
        import recoverage.server as srv

        monkeypatch.setattr(srv, "_AUTH_TOKEN", "hunter2")
        assert srv._auth_token_matches("hunter3") is False

    def test_empty_config_token_never_matches(self, monkeypatch: Any) -> None:
        """No --token configured means the helper must not authenticate."""
        import recoverage.server as srv

        monkeypatch.setattr(srv, "_AUTH_TOKEN", "")
        assert srv._auth_token_matches("") is False


class TestTokenAuthEndpoint:
    """WSGI-level behavior of the --token gate, incl. guess throttling."""

    @pytest.fixture(autouse=True)
    def _token(self, monkeypatch: Any) -> None:
        import recoverage.server as srv

        monkeypatch.setattr(srv, "_AUTH_TOKEN", "unit-test-token")
        yield
        srv._clear_auth_failures()

    def test_missing_token_is_401(self) -> None:
        from conftest import wsgi_get

        status, _, _ = wsgi_get("/api/health")
        assert status.startswith("401")

    def test_failed_auth_is_audit_logged(self, caplog: pytest.LogCaptureFixture) -> None:
        """A rejected token attempt must leave an audit trail (brute-force
        visibility) without ever logging the attempted token value."""
        from conftest import wsgi_get

        with caplog.at_level(logging.WARNING, logger="recoverage"):
            wsgi_get("/api/health", headers={"Authorization": "Bearer wrong-guess-123"})
        warnings = [r for r in caplog.records if r.levelno == logging.WARNING]
        assert any("invalid auth token" in r.getMessage() for r in warnings)
        assert all("wrong-guess-123" not in r.getMessage() for r in caplog.records)

    def test_bearer_token_accepted(self) -> None:
        from conftest import wsgi_get

        status, _, _ = wsgi_get("/api/health", headers={"Authorization": "Bearer unit-test-token"})
        assert status.startswith("200")

    def test_rate_limit_after_max_failures(self) -> None:
        from conftest import wsgi_get

        from recoverage.server import _AUTH_FAIL_MAX

        codes = []
        for _ in range(_AUTH_FAIL_MAX + 2):
            status, _, _ = wsgi_get("/api/health")
            codes.append(status.split()[0])
        assert codes[:_AUTH_FAIL_MAX] == ["401"] * _AUTH_FAIL_MAX
        assert all(c == "429" for c in codes[_AUTH_FAIL_MAX:])

    def test_query_param_token_accepted(self) -> None:
        """The documented share-link flow: /?token=<token> authenticates."""
        from conftest import wsgi_get

        status, _, _ = wsgi_get("/api/health?token=unit-test-token")
        assert status.startswith("200")

    def test_cookie_token_accepted(self) -> None:
        """After the SPA cookie is set, plain navigation authenticates."""
        from conftest import wsgi_get

        status, _, _ = wsgi_get(
            "/api/health", headers={"Cookie": "recoverage_token=unit-test-token"}
        )
        assert status.startswith("200")

    def test_ui_route_gets_html_401_page(self) -> None:
        """A browser asking for a page gets the human-readable 401 page,
        not a raw JSON blob with no instructions."""
        from conftest import wsgi_get

        status, headers, body = wsgi_get("/", headers={"Accept": "text/html"})
        assert status.startswith("401")
        assert "text/html" in headers.get("Content-Type", "")
        assert headers.get("Cache-Control") == "no-store"
        assert b"Access token required" in body

    def test_api_route_stays_json_401_despite_html_accept(self) -> None:
        """API consumers keep the JSON error contract even when they send
        Accept: text/html — only UI routes get the page."""
        from conftest import wsgi_get

        status, headers, body = wsgi_get(
            "/api/health",
            headers={"Accept": "text/html,application/xhtml+xml"},
        )
        assert status.startswith("401")
        assert headers.get("Content-Type", "").startswith("application/json")
        data = json.loads(body)
        assert data["code"] == "unauthorized"

    def test_valid_token_on_index_sets_httponly_cookie(self) -> None:
        """Opening / as /?token=<token> must set the SPA's HttpOnly cookie."""
        from conftest import wsgi_get

        status, headers, _ = wsgi_get("/?token=unit-test-token")
        assert status.startswith("200")
        cookie = headers.get("Set-Cookie", "")
        assert "recoverage_token=" in cookie
        assert "HttpOnly" in cookie

    def test_valid_token_on_potato_sets_httponly_cookie(self) -> None:
        """Potato Mode links are relative, so the share-link token has to
        survive the first click — the page itself must set the same cookie the
        SPA shell does.  Without it /potato?token=... rendered once and every
        link on it answered the 401 page."""
        from conftest import wsgi_get

        status, headers, _ = wsgi_get("/potato?target=FAKEDLL&token=unit-test-token")
        assert status.startswith("200")
        cookie = headers.get("Set-Cookie", "")
        assert "recoverage_token=" in cookie
        assert "HttpOnly" in cookie

    def test_potato_without_a_token_sets_no_cookie(self) -> None:
        """Cookie-setting is a no-op on an unauthenticated request, so a
        browser that visits /potato with no --token in play never gets one."""
        from conftest import wsgi_get

        import recoverage.server as srv

        original = srv._AUTH_TOKEN
        srv._AUTH_TOKEN = ""
        try:
            status, headers, _ = wsgi_get("/potato?target=FAKEDLL&token=anything")
            assert status.startswith("200")
            assert "Set-Cookie" not in headers
        finally:
            srv._AUTH_TOKEN = original


def _concrete_path(rule: str) -> str:
    """A path a Bottle ``rule`` actually matches, for a structural route sweep.

    Every ``<placeholder>`` becomes a single ``sample`` segment; a
    ``<name:re:...>`` placeholder takes the first alternative of its own
    filter, because a value the regex does not match would 404 the route out
    of the sweep and hide the assertion it is there to make.
    """

    def substitute(match: re.Match[str]) -> str:
        token = match.group(0)
        if ":re:" not in token:
            return "sample"
        return re.split(r"\|", token.split(":re:", 1)[1])[0].replace("\\", "")

    return re.sub(r"<[^>]+>", substitute, rule)


class TestEveryRouteIsBehindTheTokenGate:
    """The deny side of the matrix, pinned over the whole route table.

    ``_require_auth`` is a ``before_request`` hook on the one shared Bottle
    app, so every route it serves is behind the gate by construction.  The
    per-route tests sample that (a page, the API, Potato), which cannot
    notice an endpoint added later off the hook chain: the route is mounted,
    nothing refuses it, and the suite stays green.  This enumerates
    ``app.routes`` instead, so a new route has to earn its 401 like the rest.
    """

    @pytest.fixture(autouse=True)
    def _token(self, monkeypatch: Any) -> None:
        import recoverage.server as srv

        monkeypatch.setattr(srv, "_AUTH_TOKEN", "unit-test-token")
        yield
        srv._clear_auth_failures()

    def test_no_route_serves_an_unauthenticated_request(self) -> None:
        from conftest import wsgi_request

        from recoverage.server import app

        served: list[str] = []
        for route in app.routes:
            path = _concrete_path(route.rule)
            for method in route.method:
                # No Origin and no Access-Control-Request-Method, so the
                # CORS preflight exemption cannot answer for any of these:
                # the exemption is for the handshake, not the route behind it.
                status, _, _ = wsgi_request(method, path)
                served.append(f"{method} {path}")
                # 429 once the sweep outruns the failed-token window, which is
                # the gate answering as designed, not a served route.
                assert status.startswith(("401", "429")), (
                    f"{method} {path} answered {status} with no token; "
                    "every route must be behind _require_auth"
                )
        # A rule table that emptied (a rename, a mis-scoped import) would
        # satisfy the loop above without testing anything.
        assert len(served) >= 20, f"route sweep covered only {sorted(served)}"

    def test_the_same_routes_answer_200_with_the_token(self) -> None:
        """The sweep above is only evidence because each route also works.

        Without it, a table of rules the router never dispatches would pass
        the 401 assertion by 404ing everything.
        """
        from conftest import wsgi_request

        from recoverage.server import app

        auth = {"Authorization": "Bearer unit-test-token"}
        for route in app.routes:
            path = _concrete_path(route.rule)
            method = next(iter(route.method))
            status, _, _ = wsgi_request(method, path, headers=auth)
            assert not status.startswith(("401", "403", "404")), (
                f"{method} {path} is unroutable ({status}) but registered"
            )


class TestCorsPreflightBypassesTheTokenGate:
    """A CORS preflight carries no credentials, so the gate must not apply.

    A browser sends ``Origin`` and ``Access-Control-Request-Method`` on the
    preflight and withholds every credential, so a token-gated server that
    answered 401 killed the ``--cors`` + ``--token`` combination the API
    documents: the browser aborted at the handshake and never sent the
    request.  Only the handshake is exempt; the request it precedes is
    authenticated by the same gate, which is what these tests pin.
    """

    @pytest.fixture(autouse=True)
    def _cors(self, monkeypatch: Any) -> None:
        import recoverage.server as srv

        monkeypatch.setattr(srv, "_AUTH_TOKEN", "unit-test-token")
        monkeypatch.setattr(srv, "CORS_ENABLED", True)
        monkeypatch.setattr(srv, "CORS_ALLOWED_ORIGINS", ["http://localhost:5173"])
        yield
        srv._clear_auth_failures()

    def test_preflight_without_credentials_is_answered(self) -> None:
        from conftest import wsgi_request

        status, headers, _ = wsgi_request(
            "OPTIONS",
            "/api/health",
            headers={
                "Origin": "http://localhost:5173",
                "Access-Control-Request-Method": "GET",
            },
        )
        assert status.startswith("200")
        assert headers.get("Access-Control-Allow-Origin") == "http://localhost:5173"

    def test_the_request_the_preflight_precedes_is_still_gated(self) -> None:
        """The exemption covers the handshake, not the work it authorises."""
        from conftest import wsgi_get

        status, _, _ = wsgi_get("/api/health", headers={"Origin": "http://localhost:5173"})
        assert status.startswith("401")

    def test_bare_options_is_not_a_preflight_and_stays_gated(self) -> None:
        """Without the Origin/A-C-R-M pair this is a plain OPTIONS request.

        A client that can name both headers gets the empty preflight body; it
        must not thereby read anything, so the gate holds for a request that
        merely shares the verb.
        """
        from conftest import wsgi_request

        status, _, _ = wsgi_request("OPTIONS", "/api/health")
        assert status.startswith("401")

    def test_the_exemption_does_not_leak_a_privileged_route(self) -> None:
        """A preflight for the one state-changing route reveals nothing.

        ``/api/regen`` answers a preflight from the same catch-all that
        answers every path, so the verb a cross-origin page asks about is not
        a capability it can then exercise.
        """
        from conftest import wsgi_request

        status, _headers, body = wsgi_request(
            "OPTIONS",
            "/api/regen",
            headers={
                "Origin": "http://localhost:5173",
                "Access-Control-Request-Method": "POST",
            },
        )
        assert status.startswith("200")
        assert body == b""
        assert "regen" not in body.decode("utf-8", "replace")

    def test_exempt_preflight_does_not_clear_the_failure_window(self) -> None:
        """An unauthenticated preflight must not count as a good credential.

        ``_clear_auth_failures`` runs only on a verified token; if the
        exemption reached it, any client could reset the brute-force window
        with a header pair it controls.
        """
        from conftest import wsgi_request

        import recoverage.server as srv

        wsgi_request(
            "OPTIONS",
            "/api/health",
            headers={
                "Origin": "http://localhost:5173",
                "Access-Control-Request-Method": "GET",
            },
        )
        assert len(srv._auth_failures) == 0
        # A real bad credential still records, so the window still fills.
        status, _, _ = wsgi_request("GET", "/api/health")
        assert status.startswith("401")
        assert len(srv._auth_failures) == 1


class TestAuthFailureLimiter:
    """Unit behavior of the failure window."""

    # Far above what the in-process burst below needs, low enough that a wedged
    # worker fails the test instead of stalling the run.
    _WORKER_TIMEOUT_SECONDS = 30.0

    def test_success_clears_failures(self, monkeypatch: Any) -> None:
        """A request carrying the right token empties a FULL window.  Only
        _require_auth calls _clear_auth_failures, so the assertion is made
        after a real WSGI request: calling the helper here instead would stay
        green with the production call deleted."""
        from conftest import wsgi_get

        import recoverage.server as srv

        monkeypatch.setattr(srv, "_AUTH_TOKEN", "tok")
        try:
            for _ in range(srv._AUTH_FAIL_MAX):
                srv._auth_throttle(time.monotonic(), reserve_slot=True)
            # The window is full, so the next failure is a 429 ...
            assert srv._auth_throttle(time.monotonic(), reserve_slot=False)
            status, _, _ = wsgi_get("/api/health?token=tok")
            assert status.startswith("200")
            # ... and the verified request wiped the slate.
            assert not srv._auth_throttle(time.monotonic(), reserve_slot=False)
        finally:
            srv._clear_auth_failures()

    def test_old_entries_expire_from_window(self, monkeypatch: Any) -> None:
        import recoverage.server as srv

        try:
            old = time.monotonic() - srv._AUTH_FAIL_WINDOW_SECONDS * 2
            for _ in range(srv._AUTH_FAIL_MAX):
                srv._auth_throttle(old, reserve_slot=True)
            assert not srv._auth_throttle(time.monotonic(), reserve_slot=False)
        finally:
            srv._clear_auth_failures()

    def test_concurrent_reserves_never_exceed_cap(self, monkeypatch: Any) -> None:
        """A burst of simultaneous bad-token requests must not slip past the
        cap: the cap check and the slot append share one critical section
        (_auth_throttle), so exactly _AUTH_FAIL_MAX reservations succeed no
        matter how many threads race the window.

        A wedged worker must FAIL the test, never hang the run: the barrier
        bounds how long the workers wait for one another and the join bounds
        how long this test waits for them.  Each worker flags its own Event
        after recording, so a worker that died without recording is caught
        too (Thread.ident cannot detect that: start() sets it permanently).
        """
        import recoverage.server as srv

        workers = srv._AUTH_FAIL_MAX * 6
        barrier = threading.Barrier(workers)
        reserved: list[bool] = []
        lock = threading.Lock()
        done = [threading.Event() for _ in range(workers)]

        def worker(finished: threading.Event) -> None:
            barrier.wait(timeout=self._WORKER_TIMEOUT_SECONDS)
            got = srv._auth_throttle(time.monotonic(), reserve_slot=True)
            with lock:
                reserved.append(got)
            finished.set()

        threads = [threading.Thread(target=worker, args=(ev,)) for ev in done]
        try:
            for t in threads:
                t.start()
            for t in threads:
                t.join(timeout=self._WORKER_TIMEOUT_SECONDS)
        finally:
            srv._clear_auth_failures()

        assert [t for t in threads if t.is_alive()] == [], "worker thread wedged"
        assert all(ev.is_set() for ev in done)
        assert len(reserved) == workers
        assert reserved.count(False) == srv._AUTH_FAIL_MAX
        assert reserved.count(True) == workers - srv._AUTH_FAIL_MAX


class TestEvictOldest:
    """Bounded-cache arithmetic shared by the /data memo and Potato cells
    memo: callers invoke it BEFORE inserting, so at-capacity caches shed
    exactly one entry."""

    def test_under_cap_is_noop(self) -> None:
        from recoverage.server import _evict_oldest

        cache = dict.fromkeys(range(5))
        _evict_oldest(cache, 8)
        assert len(cache) == 5

    def test_empty_cache_is_noop(self) -> None:
        from recoverage.server import _evict_oldest

        cache: dict[int, int] = {}
        _evict_oldest(cache, 8)
        assert cache == {}

    def test_at_cap_evicts_single_oldest(self) -> None:
        from recoverage.server import _evict_oldest

        cache = dict.fromkeys(range(8))
        _evict_oldest(cache, 8)
        assert len(cache) == 7
        assert 0 not in cache  # insertion-order oldest dropped first

    def test_far_over_cap_drops_down_below_cap(self) -> None:
        from recoverage.server import _evict_oldest

        cache = dict.fromkeys(range(20))
        _evict_oldest(cache, 8)
        assert len(cache) < 8
        assert set(cache) == set(range(13, 20))  # newest kept, oldest gone


class TestStaticAssetRevalidation:
    """Static assets answer If-None-Match with a 304 and no body.

    Cache-Control is no-cache, so the browser revalidates on every load; with
    no validator the only answer was the full body again (45 KB of hljs.min.js
    per visit). The ETag must be stable
    across requests, distinct per encoding, and must reject a stale tag.

    wsgiref title-cases header names on the way out, so the tag arrives as
    "Etag"; HTTP field names are case-insensitive either way.
    """

    def test_asset_carries_an_etag(self) -> None:
        from conftest import wsgi_get

        status, headers, body = wsgi_get("/app.js", headers={"Accept-Encoding": "gzip"})
        assert status == "200 OK"
        assert headers["Etag"]
        assert body

    def test_matching_if_none_match_returns_empty_304(self) -> None:
        from conftest import wsgi_get

        _, headers, _ = wsgi_get("/app.js", headers={"Accept-Encoding": "gzip"})
        etag = headers["Etag"]
        status, headers_304, body = wsgi_get(
            "/app.js",
            headers={"Accept-Encoding": "gzip", "If-None-Match": etag},
        )
        assert status == "304 Not Modified"
        assert body == b""
        assert headers_304["Etag"] == etag
        assert headers_304["Vary"] == "Accept-Encoding"

    def test_weak_validator_still_matches(self) -> None:
        from conftest import wsgi_get

        _, headers, _ = wsgi_get("/app.js", headers={"Accept-Encoding": "gzip"})
        weak = f"W/{headers['Etag']}"
        status, _, _ = wsgi_get(
            "/app.js", headers={"Accept-Encoding": "gzip", "If-None-Match": weak}
        )
        assert status == "304 Not Modified"

    def test_stale_etag_gets_the_full_body(self) -> None:
        """A validator that does not match re-sends the asset, and the fresh
        response carries the CURRENT tag, not the stale one the client sent.
        `assert body` alone is satisfied by a 200 that echoed the stale tag."""
        from conftest import decode_body, wsgi_get

        _, current_headers, _ = wsgi_get("/app.js", headers={"Accept-Encoding": "gzip"})
        status, headers, body = wsgi_get(
            "/app.js",
            headers={"Accept-Encoding": "gzip", "If-None-Match": '"not-the-tag"'},
        )
        assert status == "200 OK"
        assert headers["Etag"] == current_headers["Etag"]
        assert decode_body(body, headers)

    def test_etag_differs_per_encoding(self) -> None:
        """br and zstd are different representations of the same file: a
        strong validator must not match across them."""
        from conftest import wsgi_get

        _, br_headers, _ = wsgi_get("/app.js", headers={"Accept-Encoding": "br"})
        _, zstd_headers, _ = wsgi_get("/app.js", headers={"Accept-Encoding": "zstd"})
        assert br_headers["Etag"] != zstd_headers["Etag"]

    def test_index_revalidates_instead_of_resending(self) -> None:
        """The shell is static, so a repeat visit must answer 304.

        It used to be the one response served no-store with no validator, so
        every reload re-downloaded the whole document while every subordinate
        asset answered 304.
        """
        from conftest import wsgi_get

        status, headers, _ = wsgi_get("/", headers={"Accept-Encoding": "gzip"})
        assert status == "200 OK"
        assert headers["Cache-Control"] == "no-cache, must-revalidate"
        etag = headers["Etag"]

        status_304, headers_304, body_304 = wsgi_get(
            "/", headers={"Accept-Encoding": "gzip", "If-None-Match": etag}
        )
        assert status_304 == "304 Not Modified"
        assert body_304 == b""
        assert headers_304["Etag"] == etag
        assert headers_304["Vary"] == "Accept-Encoding"

    def test_index_etag_differs_per_encoding(self) -> None:
        """Same rule as the static assets: a strong validator must not match
        across representations."""
        from conftest import wsgi_get

        _, br_headers, _ = wsgi_get("/", headers={"Accept-Encoding": "br"})
        _, zstd_headers, _ = wsgi_get("/", headers={"Accept-Encoding": "zstd"})
        assert br_headers["Etag"] != zstd_headers["Etag"]

    def test_index_inlines_the_bundle_and_the_stylesheet(self) -> None:
        """The shell carries both, so the first paint takes no render-blocking
        subresource request: one script, one style, and no link to either."""
        from conftest import decode_body, wsgi_get

        _, headers, body = wsgi_get("/", headers={"Accept-Encoding": "gzip"})
        html = decode_body(body, headers).decode("utf-8")
        assert "<script>" in html
        assert "<style>" in html
        assert 'href="/app.js"' not in html
        assert 'href="/style.css"' not in html
        assert '<div id="root">' in html

    def test_index_preloads_the_target_list(self) -> None:
        """The target list is on the first-paint path and cannot be discovered
        until app.js runs, so the shell advertises it as a fetch preload; the
        plain same-origin fetch() in app.js then reuses it rather than
        issuing a second request."""
        from conftest import decode_body, wsgi_get

        _, headers, body = wsgi_get("/", headers={"Accept-Encoding": "gzip"})
        html = decode_body(body, headers).decode("utf-8")
        assert '<link rel="preload" href="/api/targets" as="fetch">' in html
        # Preload reuse needs the same mode and credentials the fetch uses:
        # a crossorigin attribute here would put the two in different caches
        # and the browser would download the list twice.
        assert '<link rel="preload" href="/api/targets" as="fetch" crossorigin' not in html


class TestHostnameOf:
    """_hostname_of is the parser behind BOTH the DNS-rebinding Host
    allowlist and the regen Origin check — values that browsers never emit
    (userinfo, escapes, control bytes) must parse as "" so they can never
    match an allowlist entry."""

    def test_bare_host_with_port(self) -> None:
        from recoverage.server import _hostname_of

        assert _hostname_of("localhost:8001") == "localhost"

    def test_origin_url(self) -> None:
        from recoverage.server import _hostname_of

        assert _hostname_of("http://localhost:5173") == "localhost"

    def test_uppercase_lowered(self) -> None:
        from recoverage.server import _hostname_of

        assert _hostname_of("HTTP://LOCALHOST:8001") == "localhost"

    @pytest.mark.parametrize(
        "origin",
        [
            "http://evil@localhost",  # userinfo spoofing
            "http://local\\\\host",  # backslash confusion
            "http://loc%61lhost",  # percent-encoding
            "http://loc\x01alhost",  # control byte
            "http://[::1",  # unparsable IPv6
            "",
        ],
    )
    def test_non_plain_values_parse_empty(self, origin: str) -> None:
        from recoverage.server import _hostname_of

        assert _hostname_of(origin) == ""

    def test_junk_host_never_matches_allowlist(self) -> None:
        """Garbage without scheme separators parses as a literal hostname;
        the contract that matters is that it can never equal an allowlisted
        loopback name."""
        from recoverage.server import LOOPBACK_HOSTS, _hostname_of

        junk = _hostname_of("not a url at all")
        assert junk not in LOOPBACK_HOSTS

    def test_ipv6_literal_kept(self) -> None:
        from recoverage.server import _hostname_of

        assert _hostname_of("http://[::1]:8001") == "::1"


class TestSecurityHeaders:
    """Every response carries the hardening header set."""

    EXPECTED: ClassVar[dict[str, str]] = {
        "X-Content-Type-Options": "nosniff",
        "X-Frame-Options": "DENY",
        "Referrer-Policy": "no-referrer",
    }

    @pytest.mark.parametrize(("header", "value"), sorted(EXPECTED.items()))
    def test_headers_on_api_response(self, header: str, value: str) -> None:
        from conftest import wsgi_get

        _, headers, _ = wsgi_get("/api/health")
        assert headers.get(header) == value

    def test_csp_on_api_response(self) -> None:
        from conftest import wsgi_get

        _, headers, _ = wsgi_get("/api/health")
        csp = headers.get("Content-Security-Policy", "")
        assert "default-src 'self'" in csp
        assert "object-src 'none'" in csp
        assert "base-uri 'none'" in csp
        # The SPA inlines its built bundle; the policy must allow that.
        assert "script-src 'self' 'unsafe-inline'" in csp

    def test_csp_allows_spa_inline_script_and_self_connect(self) -> None:
        from conftest import wsgi_get

        _, headers, _ = wsgi_get("/")
        csp = headers.get("Content-Security-Policy", "")
        assert "'unsafe-inline'" in csp
        assert "connect-src 'self'" in csp

    def test_potato_page_forces_revalidation(self) -> None:
        """Potato Mode is the one DB-derived response that used to carry no
        cache directive at all, leaving heuristic freshness to the browser and
        storage-plus-replay to any shared cache in front of the dashboard."""
        from conftest import wsgi_get

        _, headers, _ = wsgi_get("/potato")
        assert headers.get("Cache-Control") == "no-cache, must-revalidate"
        # bottle normalizes header names to Title-Case ("Etag").
        assert headers.get("Etag")


class TestUndecodableRequestHeader:
    """A header the app cannot read as text reads as absent, on every path.

    ``_header`` runs in the before_request hook, ahead of the auth gate, so a
    header value that raised there was a 500 with a traceback on every request
    rather than on the one request that carried it.  Bottle re-encodes the
    environ value to latin-1 before decoding it as UTF-8, so the failure is
    UnicodeEncodeError as well as UnicodeDecodeError; the guard covers both.
    """

    @pytest.mark.parametrize(
        "value",
        [
            "\U0001f600",  # above U+00FF: bottle's latin-1 encode raises
            "中文",
            "�",  # not valid UTF-8 once bottle re-decodes
        ],
    )
    @pytest.mark.parametrize("path", ["/api/health", "/api/targets", "/", "/potato"])
    def test_request_still_served(self, path: str, value: str) -> None:
        from conftest import wsgi_get

        status, _, _ = wsgi_get(path, {"X-Request-ID": value})
        assert not status.startswith("5")

    def test_header_reads_as_absent_not_as_the_value(self) -> None:
        """The value is dropped, not passed through: an unreadable one cannot
        become the request id, and a well-formed one still can."""
        from conftest import wsgi_get

        _, headers, _ = wsgi_get("/api/health", {"X-Request-ID": "\U0001f600"})
        # A minted id is hex; the undecodable value never reaches the header.
        assert set(headers["X-Request-Id"]) <= set("0123456789abcdef")


class TestLogInjection:
    """Request-derived log fields cannot forge multi-line entries: the path
    is percent-decoded by the time it reaches the app, so %0A arrives as a
    raw newline unless escaped before logging."""

    def test_log_safe_escapes_control_characters(self) -> None:
        from recoverage.server import _log_safe

        assert _log_safe("normal/path?q=1") == "normal/path?q=1"
        assert _log_safe("a\nb\rc\x00d\x7f") == "a\\x0ab\\x0dc\\x00d\\x7f"

    def test_log_safe_escapes_every_line_terminator(self) -> None:
        """C1 controls and U+2028/U+2029 break a log line the same way \\n does.

        A header value is not percent-encoded on the wire, so %C2%85 (NEL)
        and %E2%80%A8 (LINE SEPARATOR) reach _log_safe as themselves; every
        consumer that splits a log on \\n splits on these too.  chr(), not a
        literal: the separators are invisible in a diff.
        """
        from recoverage.server import _log_safe

        value = "a" + chr(0x85) + "b" + chr(0x2028) + "c" + chr(0x2029) + "d" + chr(0x9F)
        assert _log_safe(value) == "a\\x85b\\x2028c\\x2029d\\x9f"

    def test_log_safe_keeps_ordinary_non_ascii(self) -> None:
        """Escaping is for line breaks, not for text: a CJK target id or an
        accented symbol name must stay readable in the log."""
        from recoverage.server import _log_safe

        line = "/api/targets/日本語/functions/café"
        assert _log_safe(line) == line

    def test_request_id_cannot_carry_a_line_separator(self, monkeypatch: Any) -> None:
        """The echoed X-Request-ID is the request's identity in the log."""
        import recoverage.server as srv

        class _Req:
            headers: ClassVar[dict[str, str]] = {"X-Request-ID": "abc" + chr(0x2028) + "forged"}

        monkeypatch.setattr(srv, "request", _Req())
        assert srv._new_request_id() == "abc\\x2028forged"

    def test_newline_in_path_stays_one_log_line(self, caplog: pytest.LogCaptureFixture) -> None:
        from conftest import wsgi_get

        with caplog.at_level(logging.DEBUG, logger="recoverage"):
            wsgi_get("/api/health\nX-Forged: yes")
        msgs = [r.getMessage() for r in caplog.records if r.name == "recoverage"]
        assert any("X-Forged" in m for m in msgs), "request was not logged at all"
        assert all("\n" not in m and "\r" not in m for m in msgs)

    def test_target_id_cannot_forge_a_dll_log_line(self, caplog: pytest.LogCaptureFixture) -> None:
        """Target ids are routable request data and originate in analyzed
        binary names, so the DLL loader's warnings carry them through
        _log_safe like every other request-derived log field does."""
        with caplog.at_level(logging.WARNING, logger="recoverage"):
            with DLL_LOCK:
                DLL_DATA.clear()
            assert _load_dll("evil\nX-Forged: yes") is None
        msgs = [r.getMessage() for r in caplog.records if r.name == "recoverage"]
        assert any("X-Forged" in m for m in msgs), "failure was not logged at all"
        assert all("\n" not in m and "\r" not in m for m in msgs)
        with DLL_LOCK:
            DLL_DATA.clear()


class TestLoadDllTransientFailure:
    """A transient DLL read failure must NOT be negative-cached: caching
    ``DLL_DATA[target] = None`` would keep the target's /asm and /bytes
    endpoints failing until the next rebuild broadcast clears the cache,
    even after the file comes back."""

    def test_os_failure_not_cached_and_self_heals(self, tmp_path: Path, monkeypatch: Any) -> None:
        import recoverage.server as srv

        key = "__transient_test_target__"
        holder: dict[str, Path] = {"p": tmp_path / "missing.dll"}
        monkeypatch.setattr(srv, "_find_dll_path", lambda target: holder["p"])
        try:
            # stat() on the absent path raises FileNotFoundError inside
            # _load_dll's OSError handler: logged, returned as None, NOT stored.
            assert srv._load_dll(key) is None
            assert key not in srv.DLL_DATA

            # The file comes back (build finished, lock released): retrying on
            # the next request self-heals with no cache invalidation in between.
            real = tmp_path / "real.dll"
            real.write_bytes(b"MZ-fake-binary")
            holder["p"] = real
            assert srv._load_dll(key) == b"MZ-fake-binary"
            assert srv.DLL_DATA[key] == b"MZ-fake-binary"

            # A later transient failure cannot poison the cached success.
            holder["p"] = tmp_path / "gone-again.dll"
            assert srv._load_dll(key) == b"MZ-fake-binary"
        finally:
            with srv.DLL_LOCK:
                srv.DLL_DATA.pop(key, None)


class TestGetDisassemblyNoNegativeCache:
    """get_disassembly must not memoize the "" result of a DLL-load failure.

    The memo sits BELOW the load guard: caching "" under (va, size,
    file_offset, target) would pin a transient read failure past recovery
    (the exact scenario _load_dll's no-negative-cache contract exists for),
    replaying empty disassembly until the next rebuild broadcast.
    """

    def test_load_failure_bypasses_memo_and_self_heals(
        self, tmp_path: Path, monkeypatch: Any
    ) -> None:
        import recoverage.disasm as disasm
        import recoverage.server as srv

        key = "__disasm_transient_target__"
        holder: dict[str, Path] = {"p": tmp_path / "missing.dll"}
        monkeypatch.setattr(srv, "_find_dll_path", lambda target: holder["p"])

        calls: list[tuple[int, int, int, str]] = []

        def fake_impl(va: int, size: int, file_offset: int, target: str) -> str:
            calls.append((va, size, file_offset, target))
            return f"disasm:{va:#x}"

        monkeypatch.setattr(disasm, "_disassemble_loaded", fake_impl)
        try:
            # Load fails: the caller sees "" and the memo was never consulted.
            assert disasm.get_disassembly(0x1000, 4, 0, key) == ""
            assert calls == []

            # The binary comes back: the same slice disassembles for real
            # instead of replaying the pinned "".
            real = tmp_path / "real.dll"
            real.write_bytes(b"MZ-fake-binary")
            holder["p"] = real
            assert disasm.get_disassembly(0x1000, 4, 0, key) == "disasm:0x1000"
            assert calls == [(0x1000, 4, 0, key)]
        finally:
            with srv.DLL_LOCK:
                srv.DLL_DATA.pop(key, None)

    def test_invalidation_during_a_build_leaves_no_stale_memo_entry(
        self, tmp_path: Path, monkeypatch: Any
    ) -> None:
        """A rebuild broadcast that lands mid-build must not be outlived by it.

        lru_cache stores the result on return, so a clear that runs while the
        build is still disassembling cannot retract it: the entry lands after
        the invalidation and nothing clears it again until the NEXT rebuild.
        The generation counter in get_disassembly is what catches that, and it
        has to catch it for the whole in-flight herd, not one request.
        """
        import recoverage.disasm as disasm
        import recoverage.server as srv

        key = "__disasm_midbuild_target__"
        dll = tmp_path / "real.dll"
        dll.write_bytes(b"MZ-fake-binary")
        monkeypatch.setattr(srv, "_find_dll_path", lambda target: dll)

        built: list[str] = []

        @disasm.functools.lru_cache(maxsize=16)
        def fake_impl(va: int, size: int, file_offset: int, target: str) -> str:
            built.append(f"{va:#x}")
            if len(built) == 1:
                # The rebuild's invalidation lands while this build runs: the
                # bytes behind the answer are the ones it is meant to drop.
                disasm.clear_disassembly_cache()
            return f"disasm-build-{len(built)}"

        monkeypatch.setattr(disasm, "_disassemble_loaded", fake_impl)
        try:
            # Served answer is the post-rebuild one, not the raced build.
            assert disasm.get_disassembly(0x3000, 1, 0, key) == "disasm-build-2"
            assert len(built) == 2
            # And the raced build left nothing behind: the repeat is a memo
            # hit on the fresh entry, still without a third build.
            assert disasm.get_disassembly(0x3000, 1, 0, key) == "disasm-build-2"
            assert len(built) == 2
        finally:
            with srv.DLL_LOCK:
                srv.DLL_DATA.pop(key, None)
            fake_impl.cache_clear()

    def test_clear_derived_caches_clears_disassembly_memo(
        self, tmp_path: Path, monkeypatch: Any
    ) -> None:
        """Rebuilds must evict memoized disassembly through the shared
        invalidation entry point (wiring guard for the split cache)."""
        import recoverage.api
        import recoverage.disasm as disasm
        import recoverage.server as srv

        key = "__disasm_invalidation_target__"
        holder: dict[str, Path] = {"p": tmp_path / "missing.dll"}
        monkeypatch.setattr(srv, "_find_dll_path", lambda target: holder["p"])
        real = tmp_path / "real.dll"

        @disasm.functools.lru_cache(maxsize=16)
        def _prime(va: int, size: int, file_offset: int, target: str) -> str:
            return "cached"

        monkeypatch.setattr(disasm, "_disassemble_loaded", _prime)
        try:
            holder["p"] = real
            real.write_bytes(b"MZ-fake-binary")
            assert disasm.get_disassembly(0x2000, 1, 0, key) == "cached"
            assert _prime.cache_info().currsize == 1
            recoverage.api._clear_derived_caches()
            assert _prime.cache_info().currsize == 0
        finally:
            with srv.DLL_LOCK:
                srv.DLL_DATA.pop(key, None)
        _prime.cache_clear()

    def test_invalidation_bumps_the_generation_under_its_lock(self) -> None:
        """The generation is a read-modify-write, so it needs a lock.

        ``clear_disassembly_cache`` is reached from the SSE watcher thread (the
        db-updated broadcast) and from the regen request thread (both ends of
        ``_do_regen``), so two threads bump this counter at once and ``g += 1``
        is not atomic under the GIL.  A lost update moves the counter once
        where two invalidations happened, and the counter is the only thing
        that retracts a memo entry a build stored after an invalidation: the
        build compares the generation it read with the one it sees on return,
        and a build that overlaps a lost update is told the wrong thing.

        Pinned by holding the lock and asserting the bump cannot land through
        it, which is the property a lost update breaks and which a thread
        barrier cannot demonstrate deterministically.
        """
        import threading

        import recoverage.disasm as disasm

        before = disasm._DISASSEMBLY_GENERATION
        bumped = threading.Event()

        def bump() -> None:
            disasm.clear_disassembly_cache()
            bumped.set()

        with disasm._GENERATION_LOCK:
            thread = threading.Thread(target=bump)
            thread.start()
            assert not bumped.wait(0.2)
            assert before == disasm._DISASSEMBLY_GENERATION
        thread.join(timeout=5)
        assert bumped.is_set()
        assert before + 1 == disasm._DISASSEMBLY_GENERATION


class TestBucketReconciliation:
    """total_cells must equal the sum of the counted buckets.

    rebrew's build_db wrote an `other_count` catch-all into
    section_cell_stats for exactly this reason: without it the residual states
    (compile_error, extract_error, invalid_va, missing_file, missing_size,
    skip, unknown, and the data drift/unchecked verdicts) vanished and the
    buckets silently undercounted.  The document format stores facts, not
    counts, so the catch-all is now the `else` arm of the one fold that turns a
    section's cells into buckets — and that fold is what every reader goes
    through.
    """

    # Every short key _bucket_row emits except total_cells, which is the sum
    # they must reconcile with.
    BUCKET_KEYS = (
        "exact",
        "reloc",
        "near_match",
        "stub",
        "padding",
        "data",
        "thunk",
        "none",
        "proven",
        "size_mismatch",
        "other",
    )

    # One cell per named bucket, plus three the buckets leave to `other`.
    CELL_STATES = (
        "exact",
        "reloc",
        "near_match",
        "stub",
        "padding",
        "data",
        "thunk",
        "none",
        "proven",
        "size_mismatch",
        "compile_error",
        "skip",
        "unknown",
    )

    @staticmethod
    def _reconciles(sec: dict[str, Any]) -> None:
        assert sum(sec[k] for k in TestBucketReconciliation.BUCKET_KEYS) == sec["total_cells"]

    @classmethod
    def _snap(cls, states: Sequence[str] | None = None) -> CoverageSnapshot:
        return _snapshot_for({".text": _cell_section(states or cls.CELL_STATES)})

    def test_residual_states_land_in_other(self) -> None:
        import recoverage.server as srv

        # 'near_matching' is the other spelling of 'near_match'; 'verified'
        # folds into exact.  Neither may reach `other`.
        snap = self._snap((*self.CELL_STATES, "near_matching", "verified", "drift"))
        section = srv._section_stats(snap)["sections"][".text"]
        assert section["other"] == 4
        assert section["near_match"] == 2
        assert section["exact"] == 2
        self._reconciles(section)

    def test_the_bucket_row_always_emits_other(self) -> None:
        """A section with nothing residual keeps the key, at 0.

        The served shape is fixed: a client reading ``other`` off a payload must
        not have to guess whether the producer omitted it.
        """
        import recoverage.server as srv

        snap = self._snap(("exact", "none"))
        assert srv._bucket_row(snap.sections[".text"])["other"] == 0

    def test_section_stats_reuses_the_bucket_row(self) -> None:
        """One fold: the section entry is the bucket row plus byte sums."""
        import recoverage.server as srv

        snap = self._snap()
        section = snap.sections[".text"]
        buckets = srv._bucket_row(section)
        served = srv._section_stats(snap)["sections"][".text"]
        assert {k: served[k] for k in (*self.BUCKET_KEYS, "total_cells")} == buckets
        self._reconciles(served)

    def test_verified_cells_count_as_exact(self) -> None:
        """'verified' is a match, and every surface must agree on that.

        build_db folded VERIFIED into exact_count, the grid palette paints it in
        the exact slot, and covered_bytes already counts its bytes.  A
        cells-side 'exact'-only count would drop every VERIFIED cell from every
        bucket: the served total would no longer reconcile with the bucket sum,
        /stats would disagree with /data and Potato Mode over the same
        documents, and the header would understate coverage.
        """
        import recoverage.server as srv

        snap = self._snap(("exact", "verified", "verified", "none", "skip"))
        section = srv._section_stats(snap)["sections"][".text"]
        assert section["exact"] == 3
        assert section["other"] == 1
        self._reconciles(section)
        # A VERIFIED byte is covered, so it is a match: matched counts it too.
        assert section["matched"] == 3
        assert section["coverage_pct"] == 80.0


class TestCoveragePercentIsFloored:
    """A coverage percentage must never round UP into "complete".

    ``round(covered / total * 100, 2)`` puts 999_997 of 1_000_000 covered
    bytes at ``100.0``: the dashboard, the Potato header and `check --json`
    then all report a project with three bytes still unmatched as fully
    covered.  rebrew floors this figure everywhere else (``rebrew.utils.
    floor_pct``), and ``summary.coveragePercent`` did too, so the per-section
    number was the one surface that disagreed with its own response.
    """

    #: 999_997 exact bytes then 3 uncovered, a section one part in 333_333
    #: short of complete — well inside the range of rounding to 100.0.
    NEARLY_COMPLETE: ClassVar[dict[str, Any]] = {
        "va": 0x1000,
        "size": 1_000_000,
        "fileOffset": 0,
        "unitBytes": 1,
        "columns": 1,
        "cells": [cell(0, 999_997, "exact"), cell(999_997, 1_000_000, "none")],
    }

    def test_section_row_does_not_read_complete(self) -> None:
        import recoverage.server as srv

        snap = _snapshot_for({".text": self.NEARLY_COMPLETE})
        stats = srv._section_stats(snap)
        assert stats["sections"][".text"]["coverage_pct"] == 99.99
        # The summary field over the same bytes already floored; the two are
        # the same quantity, so they must be the same number.
        assert stats["summary"]["coveragePercent"] == stats["sections"][".text"]["coverage_pct"]

    def test_potato_header_reads_the_same_number(self) -> None:
        import recoverage.potato as pot
        import recoverage.server as srv

        snap = _snapshot_for({".text": self.NEARLY_COMPLETE})
        summary = srv._summary(snap)
        sections = {".text": {"size": 1_000_000}}
        assert pot._section_pct(summary, sections, ".text") == 99.99

    def test_a_section_with_no_bytes_is_zero_not_an_error(self) -> None:
        import recoverage.server as srv

        assert srv.coverage_pct(0, 0) == 0.0
        # Rounds down, never up: 99.9999 is 99.99 at 2dp, and a value that is
        # already at 2dp is untouched (no float drift on the way through).
        assert srv.coverage_pct(999_999, 1_000_000) == 99.99
        assert srv.coverage_pct(875, 1_000) == 87.5


class TestEveryDeclaredSectionIsServed:
    """A section the directory declares must never be dropped from the response.

    rebrew's `section_cell_stats` and `section_cells_json` were materialized
    caches over `cells`, read in preference to a live aggregation; a cache that
    covered only SOME of a target's sections dropped the rest — no stats at all,
    and an empty grid that reads as a whole section of `none` bytes, which is a
    wrong answer rather than a slow one.  The document format carries no cache,
    so that particular failure cannot be produced any more; what is left to pin
    is the property the gap fills protected, which is stronger here: every
    section of the file is served, and each one's numbers come from ITS OWN
    cells and nobody else's.
    """

    SECTIONS = (".text", ".data")
    #: .text gets two exact cells, .data one exact and one none, so the two
    #: sections' numbers differ and a dropped section cannot pass unnoticed.
    CELL_STATES: ClassVar[dict[str, tuple[str, ...]]] = {
        ".text": ("exact", "exact"),
        ".data": ("exact", "none"),
    }

    @classmethod
    def _snap(cls) -> CoverageSnapshot:
        return _snapshot_for(
            {
                name: _cell_section(states, va=0x1000 + 0x1000 * idx)
                for idx, (name, states) in enumerate(cls.CELL_STATES.items())
            }
        )

    def test_every_declared_section_reports_its_own_cells(self) -> None:
        import recoverage.server as srv

        stats = srv._section_stats(self._snap())["sections"]
        assert set(stats) == set(self.SECTIONS)
        # .data reports what its own two cells say: one covered byte of two,
        # both cells bucketed.
        assert stats[".data"]["total_cells"] == 2
        assert stats[".data"]["exact"] == 1
        assert stats[".data"]["none"] == 1
        assert stats[".data"]["covered_bytes"] == 1
        assert stats[".data"]["total_bytes"] == 2
        assert stats[".data"]["coverage_pct"] == 50.0

    def test_one_section_cannot_borrow_another_s_cells(self) -> None:
        """The two sections' numbers differ, so a spliced payload shows up."""
        import recoverage.server as srv

        stats = srv._section_stats(self._snap())["sections"]
        assert stats[".text"]["total_cells"] == 2
        assert stats[".text"]["none"] == 0

    def test_the_cell_payload_keeps_every_stored_cell(self) -> None:
        """The grid is built from the section's own cells, in spatial order."""
        import recoverage.server as srv

        snap = self._snap()
        payload = json.loads(srv.cells_json(snap.sections[".data"].cells))
        assert [entry["state"] for entry in payload] == ["exact", "none"]
        assert [entry["start"] for entry in payload] == [0, 1]

    def test_a_section_with_no_cells_serves_an_empty_grid(self) -> None:
        """A declared section with no cells is not a section of `none` bytes.

        The old ``GROUP BY section_name`` produced no row for it, and the cell
        payload is empty rather than absent, so the grid renders nothing instead
        of inventing a section-wide miss.
        """
        import recoverage.server as srv

        snap = _snapshot_for(
            {
                ".text": _cell_section(["exact"]),
                ".empty": {
                    "va": 0x2000,
                    "size": 0x100,
                    "fileOffset": 0,
                    "unitBytes": 0,
                    "columns": 0,
                    "cells": [],
                },
            }
        )
        assert ".empty" in snap.sections
        assert ".empty" not in srv._section_stats(snap)["sections"]
        assert srv.cells_json(snap.sections[".empty"].cells) == "[]"


class TestBucketVocabularyIsShared:
    """The bucket keys and their fold are ONE definition for every reader.

    ``section_bucket_rows`` carried the cache-first policy for /stats, /data and
    the Potato map header, so a rule that changed reached all three.  The
    documents carry no cache and the policy is gone with it; what remains is the
    reason it was centralized — a reader that restates the fold drifts from the
    others — and these are the three rules that survive: every section serves
    the same key set, the keys reconcile with ``total_cells``, and the summary's
    per-section counts are the same numbers the section entry reports.
    """

    SECTIONS = (".text", ".data")

    def _snap(self) -> CoverageSnapshot:
        return _snapshot_for(
            {
                ".text": _cell_section(["exact", "verified", "reloc", "stub", "padding"]),
                ".data": _cell_section(["exact", "none", "skip"], va=0x2000),
            }
        )

    def test_every_section_serves_the_same_key_set(self) -> None:
        import recoverage.server as srv

        stats = srv._section_stats(self._snap())["sections"]
        expected = {"total_cells", *TestBucketReconciliation.BUCKET_KEYS}
        for name in self.SECTIONS:
            assert expected <= set(stats[name]), f"{name} is missing bucket keys"

    def test_a_state_outside_the_fold_keeps_the_sum_reconciling(self) -> None:
        import recoverage.server as srv

        stats = srv._section_stats(self._snap())["sections"][".data"]
        assert stats["other"] == 1
        assert sum(stats[k] for k in TestBucketReconciliation.BUCKET_KEYS) == stats["total_cells"]

    def test_the_summary_reports_the_section_s_buckets(self) -> None:
        """``_summary``'s per-section entries are the same counts /stats serves.

        The summary is what the SPA renders a section's header from and the
        section entry is what its own map reports, so a second fold there would
        let a rebuild's header disagree with its own grid.
        """
        import recoverage.server as srv

        snap = self._snap()
        stats = srv._section_stats(snap)
        # `_summary` carries one entry per section OTHER than .text: the grid
        # summary at the top level IS the .text one.
        entry = stats["sections"][".data"]
        summary = stats["summary"][".data"]
        assert summary["exactMatches"] == entry["exact"]
        assert summary["relocMatches"] == entry["reloc"]
        assert summary["stubCount"] == entry["stub"]
        assert summary["paddingCount"] == entry["padding"]
        assert summary["nearMatchCount"] == entry["near_match"]
        # And the top-level entry is the .text grid the SPA falls back to, read
        # off the section's own cells rather than a second count of them.
        text = snap.sections[".text"]
        assert stats["summary"]["textSize"] == text.size
        assert stats["summary"]["coveredBytes"] == text.covered_bytes


class TestUnreadableDocumentIsNotAnEmptyTarget:
    """A document that cannot be read must surface, never degrade to empty.

    The SQLite-era fallbacks caught every ``sqlite3.Error`` so a pre-v7 database
    kept serving from ``cells``; a locked or truncated ``coverage.db`` took the
    same branch and produced a correct-looking cells-derived payload with
    nothing in the log and nothing in the response to say the database could not
    be read.  A document cannot be partially read: one that does not parse is
    NOT a target with no sections, and every reader has to say so with the 503
    ``db_unavailable`` contract.  The one legible degradation left is the one
    the reader owns — a broken document beside a good one is skipped, so the
    good target still serves.
    """

    BROKEN = "version = = 1\n"

    def test_a_malformed_document_is_not_an_empty_directory(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        import recoverage.server as srv

        directory = _coverage_dir(tmp_path, monkeypatch)
        directory.mkdir(parents=True, exist_ok=True)
        (directory / "coverage-BROKEN.toml").write_text(self.BROKEN, encoding="utf-8")

        with pytest.raises(CoverageTomlError):
            srv.coverage_snapshots()
        with pytest.raises(CoverageTomlError):
            srv.resolve_targets()

    def test_a_missing_document_is_a_503(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        import recoverage.server as srv

        _coverage_dir(tmp_path, monkeypatch)
        assert srv.db_target_ids() == []
        with pytest.raises(CoverageTomlError):
            srv.coverage_snapshots()

    def test_the_error_names_the_command_that_writes_the_documents(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """`rebrew build-db` runs the catalog analysis in process.

        An advice string naming a separate `rebrew catalog` step sends the
        operator after a command they do not have to run.
        """
        import recoverage.server as srv

        _coverage_dir(tmp_path, monkeypatch)
        with pytest.raises(CoverageTomlError) as excinfo:
            srv.coverage_snapshots()
        message = str(excinfo.value)
        assert "rebrew build-db" in message
        assert "rebrew catalog" not in message

    def test_the_endpoint_answers_the_db_unavailable_contract(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """The failure reaches the client as JSON 503, not as a 500 or an empty
        target that never built."""
        from conftest import wsgi_get

        directory = _coverage_dir(tmp_path, monkeypatch)
        directory.mkdir(parents=True, exist_ok=True)
        (directory / "coverage-BROKEN.toml").write_text(self.BROKEN, encoding="utf-8")

        status, headers, body = wsgi_get("/api/targets/BROKEN/stats")
        assert status.startswith("503"), status
        assert headers.get("Content-Type", "").startswith("application/json")
        payload = json.loads(body)
        assert payload["code"] == "db_unavailable"
        assert "CoverageTomlError" in payload["detail"]

    def test_one_broken_document_beside_a_good_one_still_serves(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """The degradation the reader owns: two of three targets beat a 500."""
        from conftest import wsgi_get

        import recoverage.server as srv

        directory = _coverage_dir(tmp_path, monkeypatch)
        write_coverage(directory, "GOOD", {".text": _cell_section(["exact"])})
        (directory / "coverage-BROKEN.toml").write_text(self.BROKEN, encoding="utf-8")

        assert srv.db_target_ids() == ["GOOD"]
        status, _, body = wsgi_get("/api/targets/GOOD/stats")
        assert status.startswith("200"), status
        assert json.loads(body)["sections"][".text"]["exact"] == 1

    def test_a_foreign_version_is_refused_not_guessed(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        import recoverage.server as srv

        directory = _coverage_dir(tmp_path, monkeypatch)
        directory.mkdir(parents=True, exist_ok=True)
        (directory / "coverage-FUTURE.toml").write_text(
            'version = 99\ntarget = "FUTURE"\n', encoding="utf-8"
        )
        with pytest.raises(CoverageTomlError):
            srv.coverage_snapshots()


REPO_ROOT = Path(__file__).resolve().parents[1]
WEB_APP = REPO_ROOT / "web" / "app"


def _web(relative: str) -> str:
    """One frontend source file, as written.

    The dashboard ships as a built bundle (`src/recoverage/assets/app.js`), so
    the contracts below are pinned against the sources the bundle is built from
    rather than against minified output.  Behaviour a browser can observe has
    moved to `tests/test_playwright.py`, which drives the served page.
    """
    return (WEB_APP / relative).read_text(encoding="utf-8")


def _packed_slots() -> dict[str, int]:
    """`STATE_SLOTS` from `grid/pack.ts`, as state -> palette slot."""
    pack_ts = _web("grid/pack.ts")
    block = re.search(
        r"const STATE_SLOTS = new Map<string, number>\(\[(.*?)\]\);", pack_ts, re.DOTALL
    )
    assert block is not None, "pack.ts no longer defines STATE_SLOTS"
    return {name: int(slot) for name, slot in re.findall(r'\["(\w+)",\s*(\d+)\]', block.group(1))}


def _array_items(source: str, name: str) -> list[str]:
    """The string items of one exported array literal in *source*."""
    match = re.search(rf"export const {name} = \[(.*?)\];", source, re.DOTALL)
    assert match is not None, f"{name} is no longer an array literal"
    return [item for item in re.findall(r'"([^"]+)"', match.group(1)) if item != ""]


def _filter_keys() -> list[str]:
    """`FILTER_KEY` from `grid/pack.ts`, empty first slot included.

    The empty string is load-bearing: it is the key every cell in palette slot
    0 carries, and the SPA never puts it in a filter set, so a slot-0 cell is
    dimmed by any active filter unless a filter exempts it by hand.
    """
    pack_ts = _web("grid/pack.ts")
    block = re.search(r"export const FILTER_KEY = \[(.*?)\];", pack_ts, re.DOTALL)
    assert block is not None, "pack.ts no longer defines FILTER_KEY"
    return re.findall(r'"([^"]*)"', block.group(1))


def _spa_ground_state() -> str:
    """The cell state `packSection` marks as the ground a status filter never dims.

    Read from the source rather than restated here, so the pin below is a
    statement about what the map does and not a second copy of it.
    """
    match = re.search(r'ground\[i\] = cell\.state === "(\w+)" \? 1 : 0;', _web("grid/pack.ts"))
    assert match is not None, "pack.ts no longer marks a ground cell in the pack"
    assert "ground === 1" in _web("grid/pack.ts"), (
        "survivesFilter no longer exempts the ground, so a status filter dims it again"
    )
    return match.group(1)


def _spa_survives_filter(state: str, active: set[str]) -> bool:
    """The map's status-filter rule, as `grid/pack.ts` states it."""
    if not active or state == _spa_ground_state():
        return True
    return _filter_keys()[_packed_slots().get(state, 7)] in active


class TestSpaStateVocabulary:
    """The map's state table must cover every state rebrew can write.

    An unmapped state falls to slot 7 (the tooling-failure catch-all) rather
    than to 0, because slot 0 is an undocumented gap and `verified` counts as an
    exact match in /stats: painting one as the other contradicts the number
    beside it. PALETTE_VARS and FILTER_KEY are indexed by the same slots, so all
    three tables have to be the same length.
    """

    def test_state_slots_cover_every_known_cell_state(self) -> None:
        from rebrew.build_db import _KNOWN_CELL_STATES

        missing = sorted(_KNOWN_CELL_STATES - set(_packed_slots()))
        assert missing == [], f"cell states the map paints as undocumented: {missing}"

    def test_verified_is_not_packed_as_none(self) -> None:
        slots = _packed_slots()
        assert slots["verified"] == 1
        assert slots["none"] == 0

    def test_palette_filter_and_label_tables_match_the_state_count(self) -> None:
        """Slot 7 is the highest; every lookup table must be eight long.

        A short table makes `palette[slot]` undefined (silently `--none`) and
        `FILTER_KEY[slot]` undefined (a filter mismatch on every such cell),
        while a short `STATE_LABEL` prints "undefined" in the hover title.
        """
        pack = _web("grid/pack.ts")
        assert len(_array_items(pack, "PALETTE_VARS")) == 8
        raw_filters = re.search(r"export const FILTER_KEY = \[(.*?)\];", pack).group(1)
        assert len(re.findall(r'"([a-z_]*)"', raw_filters)) == 8
        assert len(_array_items(pack, "STATE_LABEL")) == 8
        assert max(_packed_slots().values()) == 7

    def test_other_bg_token_is_defined(self) -> None:
        css = _web("index.css")
        assert "--other-bg:" in css
        assert "--color-other: var(--other-bg);" in css

    def test_legend_names_every_painted_slot(self) -> None:
        """Every slot the map can paint needs a legend row.

        LEGEND is derived from STATE_LABEL, so the rows are its indices: a
        state the map paints into a slot the label table does not reach has no
        word to show in the legend or the hover title.
        """
        pack = _web("grid/pack.ts")
        assert "STATE_LABEL.map(" in pack.split("export const LEGEND", 1)[1]
        labels = len(_array_items(pack, "STATE_LABEL"))
        assert set(_packed_slots().values()) <= set(range(labels))

    def test_the_status_filter_agrees_with_potato_mode_cell_for_cell(self) -> None:
        """One filter rule in both renderers, not two that happened to match once.

        The vocabulary was already pinned state by state, and the SURVIVAL rule
        was not, which is how the undocumented ground came to be the one cell
        the two renderers disagreed about: `potato._state_survives_filter`
        exempts it by raw state, and the map used to read the exemption off the
        paint slot, where it is indistinguishable from the data and thunk
        states that a filter does dim. Same cell, same `?filter=`, two answers.
        """
        from recoverage.potato import FILTER_STATES, _state_survives_filter

        mismatched = [
            (state, key)
            for state in sorted(_packed_slots())
            for key in sorted(FILTER_STATES)
            if _spa_survives_filter(state, {key}) != _state_survives_filter(state, {key})
        ]
        assert mismatched == [], f"the map and Potato Mode filter these apart: {mismatched}"

    def test_the_undocumented_ground_survives_every_status_filter(self) -> None:
        """The one exemption, asserted on both sides.

        The ground is the background the statuses are read against. Dimming it
        turns a filtered map into one where the undocumented regions have
        vanished rather than receded, which reads as absence of data.
        """
        from recoverage.potato import FILTER_STATES, _state_survives_filter

        ground = _spa_ground_state()
        assert _spa_survives_filter(ground, set()) and all(
            _spa_survives_filter(ground, {key}) for key in FILTER_STATES
        )
        assert all(_state_survives_filter(ground, {key}) for key in FILTER_STATES)

    def test_data_and_thunk_are_not_the_ground(self) -> None:
        """They share palette slot 0 with the ground and are not exempt.

        The pack carries the exemption per cell for exactly this reason: read
        off the slot, these two would inherit the ground's exemption and stop
        dimming, and no cell in either renderer could isolate them any more.
        """
        from recoverage.potato import FILTER_STATES, _state_survives_filter

        for state in ("data", "thunk"):
            assert _packed_slots()[state] == 0
            assert state != _spa_ground_state()
            for key in FILTER_STATES:
                assert not _spa_survives_filter(state, {key}), (state, key)
                assert not _state_survives_filter(state, {key}), (state, key)

    def test_legend_swatches_read_the_palette_variables(self) -> None:
        """A legend row draws its swatch from PALETTE_VARS, so a row cannot name
        a colour the map paints from somewhere else."""
        app = _web("App.tsx")
        assert "PALETTE_VARS[slot]" in app
        assert "swatch swatch-" in app

    def test_cell_tooltip_names_the_state_and_function(self) -> None:
        """The hover title says what the cell is, not a 0/1 flag."""
        map_source = _web("components/CoverageMap.tsx")
        assert "Block ${index}" in map_source
        assert "STATE_LABEL[pack.states[index]" in map_source
        assert "no function" in map_source


class TestSpaLayoutAndFeedback:
    """Structural contracts of the ported map and shell.

    These pin the wiring Python cannot observe: the layout memo's key, the
    roving-focus scroll, the ResizeObserver teardown, the per-section cell
    failure, and the timed notice. Browser-observable behaviour lives in
    `tests/test_playwright.py`.
    """

    def test_layout_memo_keys_on_the_packed_cells_and_the_width(self) -> None:
        """A rebuild re-spans cells without necessarily changing how many there
        are, so a (columns, cell-count) key would match while the spans differ
        and hand a click the wrong block."""
        map_source = _web("components/CoverageMap.tsx")
        assert "state.pack === pack" in map_source
        assert "state.layWidth === width" in map_source

    def test_selection_scrolls_the_block_into_view(self) -> None:
        map_source = _web("components/CoverageMap.tsx")
        assert "scrollCell" in map_source
        assert "window.scrollTo" in map_source
        assert "wrap.scrollTo" in map_source

    def test_resize_observer_is_disconnected(self) -> None:
        """A ResizeObserver holds every observed target strongly, so dropping a
        wrapper without disconnecting pins its canvas and typed arrays for the
        rest of the session."""
        map_source = _web("components/CoverageMap.tsx")
        assert "observer.disconnect()" in map_source

    def test_section_cell_failure_is_reported_with_a_retry(self) -> None:
        coverage = _web("hooks/useCoverage.ts")
        assert "setCellError({" in coverage
        app = _web("App.tsx")
        assert "Could not load the" in app
        assert "ensureCells(active.name)" in app

    def test_a_jump_to_an_uncovered_address_says_so(self) -> None:
        app = _web("App.tsx")
        assert "jumpToAddress" in app
        assert "MSG.JUMP_NO_BLOCK" in app
        assert 'role="status"' in app

    def test_deep_links_carry_target_section_query_and_filter(self) -> None:
        app = _web("App.tsx")
        for marker in (
            'searchParams.set("target"',
            'searchParams.set("section"',
            'searchParams.set("q"',
            'searchParams.append("filter"',
            "history.replaceState",
        ):
            assert marker in app, f"deep-link marker missing: {marker}"

    def test_the_same_origin_guard_wraps_both_db_supplied_paths(self) -> None:
        app = _web("App.tsx")
        binary = _web("hooks/useOriginalBinary.ts")
        assert "sameOriginPath(" in app and "coverage.paths.sourceRoot" in app
        assert "sameOriginPath(" in binary and "documentPath" in binary


class TestSpaJumpAndSearch:
    """The search set and the jump must agree on what a cell stores.

    `.text` cells hold the function's name (or a VA spelling); the search index
    is keyed by name and carries the VA. The dimming pass compares against both,
    and Enter jumps to the first matched name.
    """

    def test_matched_set_carries_names_and_va_spellings(self) -> None:
        app = _web("App.tsx")
        assert "new Set<string | number>(matchedNames)" in app
        assert "coverage.searchIndex[name]?.va" in app

    def test_enter_jumps_to_the_first_matched_name(self) -> None:
        app = _web("App.tsx")
        assert "const [first] = matchedNames;" in app
        assert "entry.functions?.[0] === first" in app
        assert "jumpToAddress(toVa(entry.va))" in app


class TestClockSeam:
    """Every window in the request path reads ``recoverage.clock``.

    The regen cooldown, the idempotency-key retention window, the
    failed-token throttle, the ``db-updated`` stamp and the per-request
    duration window are the only clock reads the request path makes, and all
    five go through one module (the duration window in ``test_metrics.py``,
    which drives it the same way).  One patched clock therefore drives all of
    them: each window is minutes wide, so a test that slept through one would
    be a test nobody runs, and a test that backdated each module global by
    hand would stay green with the production read of the clock deleted.
    """

    def test_windows_expire_on_the_patched_clock(self, monkeypatch: Any) -> None:
        from conftest import wsgi_request

        import recoverage.api as api
        import recoverage.server as srv

        now = [1_000.0]
        monkeypatch.setattr(clock, "monotonic", lambda: now[0])
        monkeypatch.setattr(api, "_regen_last_attempt", None)
        monkeypatch.setattr(api, "_do_regen", lambda remote: api._json_ok({"ok": True}))
        monkeypatch.setattr(srv, "_AUTH_TOKEN", "tok")
        api._REGEN_COMPLETED_KEYS.clear()

        def post(**extra: str) -> tuple[str, dict[str, str], bytes]:
            headers = {"Authorization": "Bearer tok", **extra}
            return wsgi_request("POST", "/api/regen", headers=headers, remote_addr="127.0.0.1")

        try:
            status, _, _ = post(**{"Idempotency-Key": "k1"})
            assert status.startswith("200"), status
            # A fresh key at the same instant is inside the cooldown window.
            status, _, _ = post(**{"Idempotency-Key": "k2"})
            assert status.startswith("429"), status
            # The retry of k1 is answered from the ledger instead of re-run.
            status, headers, _ = post(**{"Idempotency-Key": "k1"})
            assert status.startswith("200"), status
            assert headers.get("Idempotent-Replay") == "true"

            # Past the retention window the ledger has forgotten k1 ...
            now[0] += api._REGEN_KEY_TTL_SECONDS + 1
            status, headers, _ = post(**{"Idempotency-Key": "k1"})
            assert status.startswith("200"), status
            assert "Idempotent-Replay" not in headers
            # ... and past the cooldown k2 runs again, both read off the clock.
            now[0] += api._REGEN_COOLDOWN_SECONDS + 1
            status, _, _ = post(**{"Idempotency-Key": "k2"})
            assert status.startswith("200"), status

            # The failed-token window runs off the same clock: 401 while it
            # has room, 429 once full, 401 again after it expires.
            bad = {"Authorization": "Bearer wrong"}

            def attempt() -> str:
                return wsgi_request("GET", "/api/health", headers=bad)[0]

            for _ in range(srv._AUTH_FAIL_MAX):
                assert attempt().startswith("401")
            assert attempt().startswith("429")
            now[0] += srv._AUTH_FAIL_WINDOW_SECONDS + 1
            assert attempt().startswith("401")
        finally:
            srv._clear_auth_failures()
            api._REGEN_COMPLETED_KEYS.clear()

    def test_db_updated_stamp_reads_the_clock(self, monkeypatch: Any) -> None:
        import recoverage.api as api

        monkeypatch.setattr(clock, "wall_time", lambda: 1_234.5)
        client: queue.Queue[bytes] = queue.Queue()
        api._SSE_CLIENTS[client] = "test-peer"
        try:
            api._broadcast_db_updated(None)
            frame = client.get_nowait().decode()
        finally:
            api._SSE_CLIENTS.pop(client, None)
        payload = json.loads(frame.split("data: ", 1)[1])
        assert payload["timestamp"] == 1_234.5

    def test_heartbeat_follows_the_patched_clock(self, monkeypatch: Any) -> None:
        """A stream pings when the CLOCK says the heartbeat interval elapsed.

        The queue is never fed and the heartbeat interval is a second, while
        the patched clock jumps a hundred seconds per read: the ping arrives
        after milliseconds of real time, so it can only have come from the
        clock.  ``_SSE_QUEUE_POLL_SECONDS`` is named, so the empty-queue wait
        the ping is reached through is shortened to milliseconds too.
        """
        import recoverage.api as api

        reads = [0]

        def fake() -> float:
            reads[0] += 1
            return 100.0 * reads[0]

        monkeypatch.setattr(clock, "monotonic", fake)
        monkeypatch.setattr(api, "_SSE_HEARTBEAT_SECONDS", 1.0)
        monkeypatch.setattr(api, "_SSE_QUEUE_POLL_SECONDS", 0.01)
        client: queue.Queue[bytes] = queue.Queue()
        api._SSE_CLIENTS[client] = "test-peer"
        stream = api._SSEStream(client)
        frames = stream._frames()
        try:
            assert next(frames) == b": connected\n\n"
            assert next(frames) == b": ping\n\n"
        finally:
            frames.close()
        assert client not in api._SSE_CLIENTS

    def test_request_duration_reads_the_patched_clock(self, monkeypatch: Any) -> None:
        """The timing window is a clock read too, so a request is slow when
        the CLOCK says so and not when it happened to take that long."""
        from conftest import wsgi_request

        import recoverage.metrics as metrics

        reads = [0]

        def fake() -> float:
            # before_request opens the window; every later read is a second
            # past SLOW_REQUEST_MS, so a real request body never waits.
            reads[0] += 1
            return 0.0 if reads[0] == 1 else metrics.SLOW_REQUEST_MS / 1000.0 + 1.0

        monkeypatch.setattr(clock, "monotonic", fake)
        before = metrics.REQUESTS.snapshot()
        status, _, _ = wsgi_request("GET", "/api/health")
        assert status.startswith("200"), status
        assert metrics.REQUESTS.snapshot()["slow"] == before["slow"] + 1


class TestOriginIsThisDashboard:
    """The privileged-regen origin gate is a same-origin test, not a
    hostname-is-loopback one.

    Every other loopback port is a different origin with its own operator, and
    a page there passes the loopback membership check while the browser refuses
    to hand it the reply, so the rebuild it starts is one the operator neither
    asked for nor sees.
    """

    @pytest.mark.parametrize(
        ("origin", "host"),
        [
            ("http://localhost:8001", "localhost:8001"),
            ("http://LOCALHOST:8001", "localhost:8001"),
            ("http://box:8001", "box:8001"),
            ("https://box:8443", "box:8443"),
            ("http://box", "box:80"),
        ],
    )
    def test_same_authority_accepted(self, origin: str, host: str) -> None:
        assert origin_is_this_dashboard(origin, host)

    @pytest.mark.parametrize(
        ("origin", "host"),
        [
            ("http://localhost:3000", "localhost:8001"),
            ("http://127.0.0.1:8001", "localhost:8001"),
            ("http://box:8001", "localhost:8001"),
            ("http://localhost:8001@evil.com", "localhost:8001"),
            ("http://127.0.0.1.evil.com:8001", "localhost:8001"),
            ("", "localhost:8001"),
        ],
    )
    def test_other_authority_rejected(self, origin: str, host: str) -> None:
        assert not origin_is_this_dashboard(origin, host)

    def test_loopback_fallback_without_a_host_header(self) -> None:
        """No Host header (HTTP/1.0, WSGI harness): fall back to loopback.

        A browser always sends Host, so the fallback only ever admits a
        non-browser client, which cannot have been driven by another page.
        """
        assert origin_is_this_dashboard("http://localhost:8001", "")
        assert not origin_is_this_dashboard("http://evil.com:8001", "")


class TestConfigDerivedMemosFollowTheConfigStat:
    """Editing rebrew-project.toml reaches no server code, so the stat of that
    file is the only invalidation signal its memos get.

    _get_targets_config has always keyed on that stat.  The resolved target
    list and the DLL byte cache did not, and both are invalidated only by the
    rebuild broadcast, which watches coverage.db — a config edit produces no DB
    change.  So a target added to the file, or a binary re-pointed in it,
    while the server ran kept the pre-edit answer until the next build-db.
    """

    @pytest.fixture
    def project(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Any:
        import recoverage.server as srv

        monkeypatch.setattr(srv, "_project_dir", lambda: tmp_path)
        clear_target_cache()
        with srv.DLL_LOCK:
            srv.DLL_DATA.clear()
            monkeypatch.setattr(srv, "_DLL_CONFIG_MTIME", None)
        yield tmp_path
        clear_target_cache()
        with srv.DLL_LOCK:
            srv.DLL_DATA.clear()

    def test_resolved_targets_pick_up_a_config_only_target(
        self, project: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        import recoverage.server as srv

        # The built half of the merge is the coverage directory now, so the
        # target has to exist as a document for the memo to have two inputs.
        write_coverage(project / "db", "FROMDB", {".text": _cell_section(["exact"])})
        monkeypatch.setenv("RECOVERAGE_DB", str(project / "db"))

        assert [t["id"] for t in srv.resolve_targets()] == ["FROMDB"]

        (project / "rebrew-project.toml").write_text(
            '[targets.NEWONE]\nbinary = "bin/new.dll"\n', encoding="utf-8"
        )
        ids = [t["id"] for t in srv.resolve_targets()]
        assert "NEWONE" in ids, (
            "a target declared in rebrew-project.toml after the server "
            "started stayed out of the dropdown, /api/targets and Potato "
            "Mode until the next rebuild"
        )

    def test_dll_bytes_follow_a_re_pointed_binary(self, project: Path) -> None:
        import recoverage.server as srv

        target = "REPOINT"
        # No config yet: the negative verdict is cached, and the edit below is
        # what has to undo it.
        assert srv._load_dll(target) is None

        (project / "first.bin").write_bytes(b"FIRST-BINARY")
        (project / "rebrew-project.toml").write_text(
            f'[targets.{target}]\nbinary = "first.bin"\n', encoding="utf-8"
        )
        assert srv._load_dll(target) == b"FIRST-BINARY"

        # A DIFFERENT-SIZED path, so the config's stat fingerprint moves even
        # on a filesystem whose mtime granularity is a whole second.
        (project / "second-and-longer.bin").write_bytes(b"SECOND-BINARY")
        (project / "rebrew-project.toml").write_text(
            f'[targets.{target}]\nbinary = "second-and-longer.bin"\n', encoding="utf-8"
        )
        assert srv._load_dll(target) == b"SECOND-BINARY", (
            "/asm and /bytes kept serving the binary the config edit replaced"
        )


class TestSpaDbSuppliedPathsStaySameOrigin:
    """``paths.sourceRoot`` / ``paths.originalDll`` must not steer the browser off-origin.

    Both are values the coverage documents hand the dashboard, and a document
    built from a hostile binary — or imported wholesale from elsewhere — can
    hold any string in them.  Spliced into an href or a fetch, ``//evil.example``
    is a protocol-relative URL and ``/\\evil.example`` is the same once a
    browser normalizes the backslash, so either one turns the analyst's browser
    into a beacon and the Source link into a navigation somewhere the dashboard
    does not own.

    The helper is executed rather than pattern-matched: bun runs the shipped
    TypeScript module, so this pins the behaviour a browser sees and fails if
    the guard is ever edited into something weaker.  Skipped when bun is absent;
    CI installs it (see package.json packageManager).
    """

    FALLBACK = "/fallback"

    # (document value, expected result). Accepted values come back unchanged;
    # every other entry must come back as FALLBACK.
    CASES: ClassVar[list[tuple[Any, str]]] = [
        # Accepted: same-origin, absolute or relative.
        ("/src/foo", "/src/foo"),
        ("/original/target.dll", "/original/target.dll"),
        ("src/foo", "src/foo"),
        ("/", "/"),
        # A colon AFTER the first slash is an ordinary path character.
        ("/src/a:b.c", "/src/a:b.c"),
        # Rejected: off-origin, scheme-bearing, or otherwise unparseable.
        ("//evil.example", FALLBACK),
        ("///evil.example", FALLBACK),
        ("/\\evil.example", FALLBACK),
        ("\\\\evil.example", FALLBACK),
        ("https://evil.example", FALLBACK),
        ("http:evil", FALLBACK),
        ("javascript:alert(1)", FALLBACK),
        ("data:text/html,x", FALLBACK),
        ("", FALLBACK),
        (None, FALLBACK),
        (123, FALLBACK),
        ({"a": 1}, FALLBACK),
        ("/src/ev\nil", FALLBACK),
        ("/src/ev\til", FALLBACK),
        ("/src/ev\x00il", FALLBACK),
    ]

    @staticmethod
    def _module_path() -> Path:
        return WEB_APP / "lib" / "format.ts"

    def test_guard_rejects_off_origin_and_scheme_paths(self) -> None:
        bun = shutil.which("bun")
        if bun is None:
            pytest.skip("bun not on PATH")

        driver = (
            "import { sameOriginPath } from "
            + json.dumps(str(self._module_path()))
            + ";\n"
            + "const cases = JSON.parse(await Bun.file(process.argv[2]).text());\n"
            + "console.log(JSON.stringify(cases.map(([v, f]) => sameOriginPath(v, f))));\n"
        )
        with tempfile.TemporaryDirectory() as tmp:
            script = Path(tmp) / "guard.ts"
            script.write_text(driver, encoding="utf-8")
            cases = Path(tmp) / "cases.json"
            cases.write_text(json.dumps(self.CASES), encoding="utf-8")
            proc = subprocess.run(
                [bun, "run", str(script), str(cases)],
                capture_output=True,
                text=True,
                timeout=60,
                check=False,
            )
        assert proc.returncode == 0, f"guard harness failed to run: {proc.stderr}"
        actual = json.loads(proc.stdout)
        expected = [want for _value, want in self.CASES]
        assert actual == expected, "sameOriginPath accepted an off-origin or scheme-bearing path"

    def test_both_db_path_consumers_go_through_the_guard(self) -> None:
        """Wiring: neither consumer may read a document path without the guard.

        The binary path reaches fetch() completely unencoded, and the source root
        feeds both the C-source fetch and the Source href, so a bypass on either
        is the vulnerability the guard exists for.
        """
        binary = _web("hooks/useOriginalBinary.ts")
        assert "sameOriginPath(" in binary
        assert "documentPath" in binary
        app = _web("App.tsx")
        assert "sameOriginPath(" in app
        assert "coverage.paths.sourceRoot" in app


class TestHljsThemeFollowsAppTokens:
    """The highlight theme must read the app's palette, not restate it.

    A colour restated as a hex literal is a value that survives a palette change
    as an orphan: the code pane keeps the old hue and nothing fails. A var()
    reference follows. A lightened step of a status hue is legitimate and stays
    a literal, because it is a different value on purpose.
    """

    @staticmethod
    def _css() -> str:
        return _web("index.css")

    @staticmethod
    def _declarations(css: str, selector: str) -> dict[str, str]:
        body = css.split(f"{selector} {{", 1)[1].split("\n}", 1)[0]
        return dict(re.findall(r"(--[a-z0-9-]+):\s*([^;]+);", body))

    def test_every_referenced_token_is_declared(self) -> None:
        style_css = self._css()
        declared = set(self._declarations(style_css, ":root"))
        declared |= set(self._declarations(style_css, ".light-mode"))
        theme = style_css.split("@layer components {", 1)[1]
        for name in sorted(set(re.findall(r"var\((--[a-z0-9-]+)\)", theme))):
            if name.startswith("--hljs-"):
                continue
            assert name in declared, (
                f"the highlight theme reads {name}, which the token layer never declares"
            )

    @pytest.mark.parametrize(("selector", "css_index"), [(":root", 0), (".light-mode", 1)])
    def test_no_app_token_is_restated_as_a_literal(self, selector: str, css_index: int) -> None:
        del css_index
        style_css = self._css()
        app_values = {
            value.strip()
            for value in self._declarations(style_css, selector).values()
            if value.strip().startswith("#")
        }
        theme = style_css.split("@layer components {", 1)[1]
        hljs_block = theme.split(f"{selector} {{", 1)[1].split("\n}", 1)[0]
        literals = {m.group(0).lower() for m in re.finditer(r"#[0-9a-fA-F]{3,8}\b", hljs_block)}
        assert not (literals & app_values), (
            f"the highlight theme {selector} spells {sorted(literals & app_values)} by hand; "
            "reference the token so the code pane follows a palette change"
        )
