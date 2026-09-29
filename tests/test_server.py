"""Tests for recoverage.server — compression, encoding, path helpers, response helpers."""

from __future__ import annotations

import gzip
import itertools
import json
import logging
import math
import os
import queue
import re
import shutil
import subprocess
import tempfile
import threading
import time
from collections.abc import Sequence
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import IO, Any, ClassVar

import brotli
import pytest
import zstandard as zstd
from conftest import WSGI_PEER, path_the_filesystem_holds
from coverage_fixture import TOML_VERSION, cell, coverage_dir, write_coverage
from rebrew.coverage_toml import CoverageSnapshot, CoverageTomlError, load_coverage

from recoverage import clock
from recoverage.server import (
    _BUCKET_FOLD,
    DLL_DATA,
    DLL_LOCK,
    HSTS_MAX_AGE_SECONDS,
    MIN_COMPRESS_BYTES,
    SUPPORTED_ENCODINGS,
    _best_encoding,
    _db_path,
    _find_dll_path,
    _load_dll,
    _project_dir,
    clear_target_cache,
    compress_payload,
    compress_static_bodies,
    fold_can_match_decimal,
    fold_can_match_hex,
    fold_match,
    fold_match_folded,
    fold_needle,
    fold_text,
    functions_by_name,
    globals_by_name,
    globals_by_va,
    lookup_function,
    lookup_global,
    mtime_ns_to_utc,
    origin_is_this_dashboard,
    select_static_variant,
    static_variant_key,
    verify_by_va,
)
from recoverage.server import (
    strip_ascii_whitespace as srv_strip,
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
        data = b"x" * (MIN_COMPRESS_BYTES + 100)
        _, encoding = compress_payload(data, "br")
        assert encoding == "br"

    def test_zstd_returns_zstd(self) -> None:
        data = b"x" * (MIN_COMPRESS_BYTES + 100)
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
        assert encoding == ""
        assert compressed == b""

    def test_a_body_under_the_floor_is_served_whole(self) -> None:
        """Below the floor the frame costs more than the squeeze saves."""
        data = b"hello world" * 4
        assert len(data) < MIN_COMPRESS_BYTES
        for accept in ("gzip", "br", "zstd"):
            result, encoding = compress_payload(data, accept)
            assert encoding == "", accept
            assert result == data, accept

    def test_single_byte_payload(self) -> None:
        data = b"\xff" * (MIN_COMPRESS_BYTES + 1)
        compressed, encoding = compress_payload(data, "br")
        assert encoding == "br"
        assert brotli.decompress(compressed) == data

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

    def test_find_dll_path_refuses_a_binary_outside_the_tree(self, monkeypatch: Any) -> None:
        """A configured binary naming a file outside the project is refused.

        rebrew-project.toml arrives in the checkout, and `_load_dll` READS the
        path it names and `/asm` and `/bytes` serve the bytes, so a parent hop
        or an anchor is a read of any file the process can open.  Each value
        below is one of the shapes that gets out of the tree, and the answer is
        the refusal the /src and /original routes give a path that escapes
        theirs.
        """
        from unittest.mock import patch

        from recoverage import server as srv

        escaping = (
            "/etc/hostname",
            "../../outside.dll",
            "..",
            "bin/../../outside.dll",
            "./../outside.dll",
        )
        for filename in escaping:
            with (
                patch.object(srv, "_project_dir", return_value=Path("/proj")),
                patch.object(
                    srv, "_get_targets_config", return_value={"GAME": {"filename": filename}}
                ),
            ):
                assert _find_dll_path("GAME") is None, f"{filename!r} was served from outside /proj"

    def test_find_dll_path_refuses_a_symlink_out_of_the_tree(self, tmp_path: Path) -> None:
        """Containment is decided on the RESOLVED path, so a link out of the
        tree is refused too: ``bin/game.dll`` inside the project is plain and
        relative, and the file it names is not."""
        from unittest.mock import patch

        from recoverage import server as srv

        root = tmp_path.resolve()
        outside = root.parent / f"outside-{root.name}.dll"
        outside.write_bytes(b"MZ")
        (root / "bin").mkdir(parents=True, exist_ok=True)
        (root / "bin" / "game.dll").symlink_to(outside)
        try:
            with (
                patch.object(srv, "_project_dir", return_value=root),
                patch.object(
                    srv,
                    "_get_targets_config",
                    return_value={"GAME": {"filename": str(root / "bin" / "game.dll")}},
                ),
            ):
                assert _find_dll_path("GAME") is None
        finally:
            outside.unlink()


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

    def test_a_part_carrying_the_separator_does_not_collide(self) -> None:
        """A validator must name exactly one response, not a family of them.

        The parts are a flat list, so a separator alone lets a value that
        CONTAINS it read as several parts.  Two function-list requests with
        free-text ``?search=`` and ``?sort=`` shift their own boundaries that
        way and shape two different pages, which then shared one strong
        validator: a client holding the first page's body revalidating the
        second was answered 304 and kept rendering the first page's rows.
        """
        import recoverage.server as srv

        by_search = srv._safe_etag(1, "T", "functions", "exact", "a|va:asc|5|3", "va", 5, 3)
        by_sort = srv._safe_etag(1, "T", "functions", "exact", "a", "va:asc|5|3|va", 5, 3)
        assert by_search != by_sort

    def test_a_shifted_part_list_does_not_collide(self) -> None:
        """The part COUNT is part of the key, not just the joined text."""
        import recoverage.server as srv

        assert srv._safe_etag(1, "T", "a|b") != srv._safe_etag(1, "T", "a", "b")
        assert srv._safe_etag(1, "T", "a") != srv._safe_etag(1, "T", "a", None)

    def test_a_filename_outside_utf8_still_yields_a_token(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """A legal Linux filename must not 500 every endpoint that keys on it.

        ``coverage-ca\\xff.toml`` is a name ext4 holds and a checkout, an
        archive or a copy from a Windows tool produces.  Python reads it as
        U+DCFF (os.fsdecode is surrogateescape), and the strict ``encode`` the
        token was built with raised, so one such file turned /potato and every
        other snapshot-keyed route into a 500 with a traceback.
        """
        import recoverage.server as srv

        directory = _coverage_dir(tmp_path, monkeypatch)
        self._doc(directory, "FAKEDLL")
        body = (directory / "coverage-FAKEDLL.toml").read_bytes()
        raw = path_the_filesystem_holds(directory, b"coverage-ca\xffx.toml")
        if raw is None:
            pytest.skip("the filesystem cannot name a file with a byte outside UTF-8")
        raw.write_bytes(body)

        token = srv._snapshot_db_mtime()
        assert token is not None
        # Still a fingerprint of the DIRECTORY: removing the odd file moves it.
        raw.unlink()
        assert srv._snapshot_db_mtime() != token

    def test_two_filenames_differing_only_in_an_undecodable_byte_differ(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """The escape is lossless, so surrogateescape keeps the two apart."""
        import recoverage.server as srv

        assert srv.fs_text_bytes("a\udcffb") != srv.fs_text_bytes("a\udcfe b")

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

    @pytest.mark.parametrize("space", ["\u00a0", "\u2009", "\u3000", "\ufeff"])
    def test_a_unicode_space_is_part_of_the_term(self, space: str) -> None:
        """``str.strip`` is not the trim, and a term is not whitespace.

        Stripping every code point Unicode calls whitespace turned a search for
        a non-breaking space into an EMPTY search, which answers with every row
        instead of the one whose name carries the space.  Only the ASCII run
        comes off.
        """
        assert srv_strip(space) == space
        assert srv_strip(f"{space}func_a{space}") == f"{space}func_a{space}"
        assert fold_match(f"sub{space}name", space)
        assert srv_strip("  func_a\t") == "func_a"

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


class TestSearchColumnGuards:
    """A skipped address column must be one the term could not have matched.

    The address arms build and fold a string per row per keystroke, so a term
    no address can hold skips them.  The guard is necessary, not sufficient:
    a term inside the alphabet can still match nothing, and then the columns
    are built and miss.  A term OUTSIDE it cannot match one, so skipping has
    to be the same answer the comparison gave.
    """

    @pytest.mark.parametrize("query", ["0x00401000", "0X401000", "401000", "0x", "deadbeef"])
    def test_a_hex_address_term_is_not_skipped(self, query: str) -> None:
        assert fold_can_match_hex(fold_needle(query))

    @pytest.mark.parametrize("query", ["sub_401000", "Sym_1", "100%", "café", "a b"])
    def test_a_name_term_skips_the_hex_columns(self, query: str) -> None:
        assert not fold_can_match_hex(fold_needle(query))

    @pytest.mark.parametrize("query", ["1000", "4194304"])
    def test_a_decimal_term_is_not_skipped(self, query: str) -> None:
        assert fold_can_match_decimal(fold_needle(query))

    @pytest.mark.parametrize("query", ["fn_1", "0x1000", "100%", ""])
    def test_a_non_decimal_term_skips_the_va_column(self, query: str) -> None:
        assert not fold_can_match_decimal(fold_needle(query))

    @pytest.mark.parametrize("query", ["0x00401000", "0x401000", "deadbeef", "1000"])
    def test_a_skipped_column_never_matched_in_the_first_place(self, query: str) -> None:
        """The guard is only sound because the column could not have matched.

        A term the guard rejects must find no address anywhere, so a caller
        that skipped the arm and one that built it answer the same.
        """
        needle = fold_needle(query)
        spellings = (f"0x{0x401000:08x}", f"0x{0x401000:x}", str(0x401000))
        for spelling in spellings:
            matched = fold_match_folded(spelling, needle)
            guarded = fold_can_match_hex(needle) or fold_can_match_decimal(needle)
            assert not (matched and not guarded), f"{query!r} matched {spelling!r} but was skipped"


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

    def test_a_name_resolves_by_exact_spelling_then_by_folded_match(self) -> None:
        """Both name arms are index hits, in the order the SQL lookup used.

        The exact spelling wins outright, and a case that differs only in case
        still resolves, which is the fold the scan used to apply per row.
        """
        snap = _snapshot_for(
            {},
            functions=[{"va": 0x1000, "name": "Straße"}, {"va": 0x1004, "name": "other"}],
        )
        index = functions_by_name(snap)
        assert index.exact["Straße"].va == 0x1000
        assert lookup_function(snap, "Straße").va == 0x1000
        assert lookup_function(snap, "STRASSE").va == 0x1000
        assert lookup_function(snap, "nope") is None

    def test_the_folded_arm_matches_the_composed_form_of_a_decomposed_name(self) -> None:
        """A decomposed name is found by either spelling, as the scan found it."""
        snap = _snapshot_for(
            {},
            functions=[{"va": 0x1000, "name": "café"}, {"va": 0x1004, "name": "x"}],
        )
        assert lookup_function(snap, "café").va == 0x1000
        assert lookup_function(snap, "café").va == 0x1000

    def test_a_repeated_name_keeps_the_first_row_on_both_arms(self) -> None:
        """First-row-wins is the semantics the linear scan this index replaced had."""
        snap = _snapshot_for(
            {},
            functions=[
                {"va": 0x1000, "name": "dup"},
                {"va": 0x1004, "name": "dup"},
            ],
        )
        assert functions_by_name(snap).exact["dup"].va == 0x1000
        assert lookup_function(snap, "dup").va == 0x1000
        assert lookup_function(snap, "DUP").va == 0x1000

    def test_a_repeated_global_name_keeps_the_first_row(self) -> None:
        snap = _snapshot_for(
            {},
            globals_=[
                {"va": 0x2000, "name": "dup"},
                {"va": 0x2004, "name": "dup"},
            ],
        )
        assert globals_by_name(snap).exact["dup"].va == 0x2000
        assert lookup_global(snap, "dup").va == 0x2000

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
        # Compared against a held reference, not against a second call:
        # `f() is f()` is satisfied by any deterministic function, so it
        # would hold for a memo that rebuilt the index on every read.
        globals_index = globals_by_va(snap)
        assert globals_by_va(snap) is globals_index

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

        # The rebuild lands between the two reads.  Its size field is longer,
        # so the document's byte count moves even when the rewrite lands in
        # the same mtime tick (NTFS's clock is that coarse).
        self._write(directory, 4096)
        during = pinned.sections[".text"].size
        # Outside the pin the next read sees the committed rebuild.
        after = srv.coverage_snapshots()["GAME"].sections[".text"].size

        assert before == during == 16
        assert after == 4096

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

        states = _web("states.ts")
        raw = re.search(r"export const FILTER_KEY = \[(.*?)\];", states).group(1)
        keys = set(re.findall(r'"([a-z_]*)"', raw))
        assert keys - {""} == set(FILTER_STATES)

    def test_every_filter_key_has_a_button(self) -> None:
        """The pills come from the shared STATE_FILTERS table, so the check
        reads the table the shell spreads rather than a copy of the keys that
        used to sit in App.tsx. A pill the table drops would leave a filter
        unreachable exactly as before."""
        from recoverage.potato import FILTER_STATES

        states = _web("states.ts")
        raw = re.search(
            r"export const STATE_FILTERS = \[(.*?)\] as const;", states, re.DOTALL
        ).group(1)
        buttons = set(re.findall(r'key: "([a-z_]+)"', raw))
        assert buttons == set(FILTER_STATES)
        strip = _web("components/StatsStrip.tsx")
        assert "STATE_FILTERS.map(" in strip

    def test_each_pill_says_the_legends_word(self) -> None:
        """A pill prints its state's word, the one `STATE_LABEL` gives the same
        slot below the map and in the map's tooltip. It used to print one
        letter with a key line spelling the letters out, which was legible on
        hover, to a screen reader and to nobody reading the toolbar."""
        states = _web("states.ts")
        filters = states.split("export const STATE_FILTERS = [", 1)[1].split("] as const;", 1)[0]
        labels = re.findall(r'label: "([^"]+)"', filters)
        assert len(labels) == 7, "a state the map paints has no pill"
        label_block = states.split("export const STATE_LABEL = [", 1)[1].split("];", 1)[0]
        legend = re.findall(r'"([^"]+)"', label_block)
        assert labels == legend[1:], "a pill spells a state in words the legend does not use"
        strip = _web("components/StatsStrip.tsx")
        assert "{entry.label}" in strip

    def test_every_packed_state_survives_a_filter(self) -> None:
        """A "" in FILTER_KEY means the cell is dimmed by every pill and lit by
        none, which is the state the two missing buttons were for."""
        states = _web("states.ts")
        raw = re.search(r"export const FILTER_KEY = \[(.*?)\];", states, re.DOTALL).group(1)
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
        srv._clear_auth_failures(WSGI_PEER)

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

    @pytest.mark.parametrize("path", ["/archivo.woff2", "/jetbrains-mono.woff2"])
    def test_the_brand_fonts_answer_without_a_token(self, path: str) -> None:
        """The 401 page draws in these, and a peer reading it has no token."""
        from conftest import wsgi_get

        import recoverage.server as srv

        failures = srv.metrics.AUTH.snapshot()["failures"]
        status, headers, body = wsgi_get(path, headers={"Accept": "*/*"})
        assert status.startswith("200"), status
        assert headers.get("Content-Type") == "font/woff2"
        assert body[:4] == b"wOF2"
        # A font fetch is not a guess at the token: it charges no failure.
        assert not srv._auth_failures.get(WSGI_PEER)
        assert srv.metrics.AUTH.snapshot()["failures"] == failures

    @pytest.mark.parametrize("path", ["/style.css", "/app.js", "/favicon.svg", "/potato"])
    def test_every_other_asset_stays_gated(self, path: str) -> None:
        from conftest import wsgi_get

        status, _, _ = wsgi_get(path)
        assert status.startswith("401"), (path, status)

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
        srv._clear_auth_failures(WSGI_PEER)

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
        the 401 assertion by 404ing everything. The status is pinned to 2xx
        rather than merely "not refused": a route that raised on every
        request answers 500, and a gate that turned into a blanket refusal
        answers 401, and both say nothing about the route behind it. 405
        counts as dispatchable for the same reason: the router matched the
        rule and declined the method, which a 404 does not do.
        """
        from conftest import wsgi_request

        from recoverage.server import app

        auth = {"Authorization": "Bearer unit-test-token"}
        served: list[str] = []
        for route in app.routes:
            path = _concrete_path(route.rule)
            method = next(iter(route.method))
            status, _, _ = wsgi_request(method, path, headers=auth)
            served.append(f"{method} {path}")
            assert status.startswith(("2", "405")), (
                f"{method} {path} is unroutable or broken ({status}) but registered"
            )
        assert len(served) >= 20, f"route sweep covered only {sorted(served)}"


class TestUnauthorizedPageMatchesTheTokenLayer:
    """The 401 page is painted from the SPA's tokens, not a private palette.

    It is a page of this product, served before anyone has authenticated, and
    it is written as a byte string because it has to answer with no stylesheet
    and no bundle. A colour hand-typed into it is therefore a colour nothing
    else in the project can find, which is how a lockout page ends up a
    different brand from the dashboard that serves it. Each colour has to be a
    `light-dark()` pair the token layer already publishes, so the page follows
    the OS theme the way the dashboard does, and it prints the faces the rest
    of the product uses.
    """

    @staticmethod
    def _page() -> str:
        from recoverage.server import _UNAUTHORIZED_HTML

        return _UNAUTHORIZED_HTML.decode("utf-8")

    def test_every_colour_on_the_page_is_a_token_pair(self) -> None:
        published = set(_token_pairs().values())
        used = {
            (light.lower(), dark.lower())
            for light, dark in re.findall(
                r"light-dark\((#[0-9a-fA-F]{6}),(#[0-9a-fA-F]{6})\)", self._page()
            )
        }
        assert used, "the 401 page painted no colour at all"
        assert used <= published, (
            f"401 page colours not in the token layer: {sorted(used - published)}"
        )
        bare = re.sub(r"light-dark\([^)]*\)", "", self._page())
        assert re.findall(r"#[0-9a-fA-F]{3,8}\b", bare) == [], "a colour outside light-dark()"

    def test_the_page_follows_the_os_theme(self) -> None:
        page = self._page()
        assert '<meta name="color-scheme" content="light dark">' in page
        assert "color-scheme:light dark" in page

    def test_the_page_prints_the_product_faces(self) -> None:
        from recoverage.potato import MONO_FONT, SANS_FONT

        page = self._page()
        assert f"font:1rem/1.55 {SANS_FONT.replace(', ', ',')}" in page
        assert f"font-family:{MONO_FONT.replace(', ', ',')}" in page
        assert "system-ui" not in page

    def test_the_page_loads_the_faces_it_names_from_ungated_paths(self) -> None:
        from recoverage.server import _UNGATED_ASSETS

        loaded = set(re.findall(r'@font-face\{[^}]*src:url\("([^"]+)"\)', self._page()))
        assert loaded == {"/archivo.woff2", "/jetbrains-mono.woff2"}
        assert loaded <= _UNGATED_ASSETS, "a face the 401 page loads sits behind the gate"

    def test_the_page_uses_no_obsolete_markup(self) -> None:
        page = self._page().lower()
        for tag in ("<font", "<tt", "<table", "bgcolor=", "align="):
            assert tag not in page, tag

    def test_the_page_still_explains_the_share_link(self) -> None:
        page = self._page()
        assert "Access token required" in page
        assert "?token=YOUR_TOKEN" in page


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
        srv._clear_auth_failures(WSGI_PEER)

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
                srv._auth_throttle(WSGI_PEER, time.monotonic(), reserve_slot=True)
            # The window is full, so the next failure is a 429 ...
            assert srv._auth_throttle(WSGI_PEER, time.monotonic(), reserve_slot=False)
            status, _, _ = wsgi_get("/api/health?token=tok")
            assert status.startswith("200")
            # ... and the verified request wiped the slate.
            assert not srv._auth_throttle(WSGI_PEER, time.monotonic(), reserve_slot=False)
        finally:
            srv._clear_auth_failures(WSGI_PEER)

    def test_old_entries_expire_from_window(self, monkeypatch: Any) -> None:
        import recoverage.server as srv

        try:
            old = time.monotonic() - srv._AUTH_FAIL_WINDOW_SECONDS * 2
            for _ in range(srv._AUTH_FAIL_MAX):
                srv._auth_throttle(WSGI_PEER, old, reserve_slot=True)
            assert not srv._auth_throttle(WSGI_PEER, time.monotonic(), reserve_slot=False)
        finally:
            srv._clear_auth_failures(WSGI_PEER)

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
            got = srv._auth_throttle(WSGI_PEER, time.monotonic(), reserve_slot=True)
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
            srv._clear_auth_failures(WSGI_PEER)

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

    def test_identity_encoding_carries_the_same_contract(self) -> None:
        """The `no-cache` + strong ETag contract is the asset's, not the
        negotiated encoding's: a client that names no shared encoding gets
        bottle's static_file, and it sends no validator at all."""
        from conftest import wsgi_get

        status, headers, body = wsgi_get("/app.js", headers={"Accept-Encoding": "identity"})
        assert status == "200 OK"
        assert body
        etag = headers["Etag"]
        assert etag
        assert "no-cache" in headers["Cache-Control"]
        status_304, headers_304, body_304 = wsgi_get(
            "/app.js", headers={"Accept-Encoding": "identity", "If-None-Match": etag}
        )
        assert status_304 == "304 Not Modified"
        assert body_304 == b""
        assert headers_304["Etag"] == etag

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

    def test_index_paints_before_the_bundle_runs(self) -> None:
        """The shell is not blank while the dashboard loads.

        Nothing is visible until the inline bundle has been parsed and run, and
        the dashboard it draws is serialized behind `/api/targets` and `/data`,
        so an empty `#root` holds a blank screen for the whole of that. The
        boot block is in the HTML for that reason, and its status line is a
        status region so it is announced rather than merely shown."""
        from conftest import decode_body, wsgi_get

        _, headers, body = wsgi_get("/", headers={"Accept-Encoding": "gzip"})
        html = decode_body(body, headers).decode("utf-8")
        assert '<div id="boot">' in html
        assert 'role="status">Loading coverage' in html
        # The bundle clears the host before mounting (preact/hooks#render
        # appends rather than replaces), so the boot line cannot survive
        # above a live dashboard.
        bundle = html.split("<script>", 1)[1]
        assert "replaceChildren" in bundle

    def test_the_boot_block_wears_the_product(self) -> None:
        """The first paint is the dashboard's own face, not a system default.

        The boot block is what a reader sees between the shell landing and the
        bundle mounting, and it used to be a centred line in a hand-typed
        `system-ui` stack at a hardcoded size: a typeface swap on the way into
        the interface. It draws the relumea mark and the wordmark and reads the
        type scale, the ink and the brand face from the token layer, with
        literal fallbacks for the paint that happens before the stylesheet
        loads."""
        from conftest import decode_body, wsgi_get

        _, headers, body = wsgi_get("/", headers={"Accept-Encoding": "gzip"})
        html = decode_body(body, headers).decode("utf-8")
        boot = html.split('<div id="boot">', 1)[1].split("</div>", 1)[0]
        assert "recoverage" in boot
        assert 'class="boot-mark" aria-hidden="true"' in boot
        # The mark is nine cells, one of them lit.
        assert boot.count("<rect") == 9
        assert boot.count('class="lit"') == 1
        # The shell's own rules, which is where a hand-typed stack would live.
        rules = html.split("<style>", 1)[1].split("</style>", 1)[0]
        assert "system-ui" not in rules
        for token in ("--font-sans", "--text-intro", "--color-text", "--color-accent"):
            assert token in rules, f"the boot block hardcodes {token} instead of reading it"

    def test_index_preloads_the_target_list(self) -> None:
        """The target list is on the first-paint path and cannot be discovered
        until app.js runs, so the shell advertises it as a fetch preload; the
        plain same-origin fetch() in app.js then reuses it rather than
        issuing a second request.

        Reuse needs the preload's mode and credentials to match the fetch's.
        fetch() is a cors-mode request with same-origin credentials, which is
        what `crossorigin` (anonymous) gives the preload; without it the
        preload is no-cors, Chrome logs "credentials mode does not match" and
        downloads the list twice (checked in Chromium 2026-09-29)."""
        from conftest import decode_body, wsgi_get

        _, headers, body = wsgi_get("/", headers={"Accept-Encoding": "gzip"})
        html = decode_body(body, headers).decode("utf-8")
        assert '<link rel="preload" href="/api/targets" as="fetch" crossorigin>' in html
        assert "credentials:" not in _web("api.ts")


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

    @pytest.mark.parametrize("path", ["/src/foo.c", "/original/target.dll"])
    def test_project_files_are_answered_inert(self, path: str) -> None:
        """A file out of the project tree must not be a same-origin document.

        ``/src`` and ``/original`` are served with the content type guessed from
        the file's own suffix, so an ``.html`` or ``.svg`` there is a document
        the browser renders at the dashboard's origin, under a policy that allows
        inline script.  The hook answers those two prefixes with a policy that
        scripts nothing and denies every subresource, so a file the project tree
        happens to carry cannot run with the dashboard's authority (or ride the
        auth cookie onto /api/*).  The path is enough here: the answer is the
        same for the 200 a real file gets and the 404 a missing one gets, so the
        wiring is pinned without depending on a fixture file existing.
        """
        from conftest import wsgi_get

        from recoverage.server import _CSP

        _, headers, _ = wsgi_get(path)
        csp = headers.get("Content-Security-Policy", "")
        assert csp != _CSP
        assert "default-src 'none'" in csp
        assert "sandbox" in csp
        assert "script-src" not in csp
        # The rest of the hardening set is unchanged: this is a stricter
        # policy on one path, not a different header set.
        assert headers.get("X-Frame-Options") == "DENY"
        assert headers.get("X-Content-Type-Options") == "nosniff"

    def test_the_dashboard_documents_keep_the_owning_policy(self) -> None:
        """The narrower policy is scoped to the two file routes: the SPA shell,
        Potato Mode and the API are the documents the dashboard's own scripts run
        in, so a change that reached them would break the app rather than harden
        it."""
        from recoverage.server import csp_for_path

        for path in ("/", "/index.html", "/potato", "/api/health", "/app.js"):
            assert "connect-src 'self'" in csp_for_path(path), path

    def test_potato_page_forces_revalidation(self) -> None:
        """Potato Mode is the one DB-derived response that used to carry no
        cache directive at all, leaving heuristic freshness to the browser and
        storage-plus-replay to any shared cache in front of the dashboard."""
        from conftest import wsgi_get

        _, headers, _ = wsgi_get("/potato")
        assert headers.get("Cache-Control") == "no-cache, must-revalidate"
        # bottle normalizes header names to Title-Case ("Etag").
        assert headers.get("Etag")


class TestTransportSecurityFollowsTheConnection:
    """Secure and HSTS are properties of how the request arrived, not constants.

    The bundled listener speaks no TLS, so a fixed `Secure` on the auth cookie
    would stop it being stored on the loopback install it serves; a fixed
    absence of it would hand the token to whoever was on the wire the moment a
    reader followed an http:// link to a host that also answers https://.  Both
    are answered off the request, so each is driven here from the two sources
    ``server.request_is_https`` reads.
    """

    @pytest.fixture(autouse=True)
    def _token(self, monkeypatch: Any) -> None:
        import recoverage.server as srv

        monkeypatch.setattr(srv, "_AUTH_TOKEN", "unit-test-token")
        yield
        srv._clear_auth_failures(WSGI_PEER)

    def test_no_transport_headers_over_plaintext(self) -> None:
        """A request that arrived over http gets neither: an HSTS header over
        http is discarded by every browser, and a Secure cookie there is a
        cookie the reader's browser will not send back."""
        from conftest import wsgi_request

        status, headers, _ = wsgi_request("GET", "/?token=unit-test-token")
        assert status.startswith("200")
        assert "Strict-Transport-Security" not in headers
        assert "Secure" not in headers.get("Set-Cookie", "")

    def test_scheme_from_the_wsgi_environ(self) -> None:
        from conftest import wsgi_request

        _, headers, _ = wsgi_request(
            "GET",
            "/?token=unit-test-token",
            environ_extra={"wsgi.url_scheme": "https"},
        )
        assert headers.get("Strict-Transport-Security") == f"max-age={HSTS_MAX_AGE_SECONDS}"
        assert "Secure" in headers.get("Set-Cookie", "")

    def test_scheme_from_a_tls_terminating_proxy(self) -> None:
        """A reverse proxy in front of this process leaves ``wsgi.url_scheme``
        at http, so without the forwarded header a TLS deployment is
        indistinguishable from a plaintext one."""
        from conftest import wsgi_request

        _, headers, _ = wsgi_request(
            "GET",
            "/?token=unit-test-token",
            headers={"X-Forwarded-Proto": "HTTPS"},
        )
        assert headers.get("Strict-Transport-Security") == f"max-age={HSTS_MAX_AGE_SECONDS}"
        assert "Secure" in headers.get("Set-Cookie", "")

    def test_every_response_carries_hsts_where_the_request_was_secure(self) -> None:
        """Not just the page routes: an API response is the one a cross-origin
        reader holds a cached copy of, and HSTS is what stops the next request
        for it leaving over plaintext."""
        from conftest import wsgi_request

        _, headers, _ = wsgi_request(
            "GET",
            "/api/health",
            environ_extra={"wsgi.url_scheme": "https"},
        )
        assert headers.get("Strict-Transport-Security") == f"max-age={HSTS_MAX_AGE_SECONDS}"

    def test_the_flag_cannot_relax_anything(self) -> None:
        """A client that claims https over plaintext gets a STRICTER answer, not
        a weaker one: the cookie it is handed is one its own browser will not
        send over the connection it is on, and the HSTS header is discarded."""
        from conftest import wsgi_request

        _, headers, _ = wsgi_request(
            "GET",
            "/?token=unit-test-token",
            headers={"X-Forwarded-Proto": "https"},
            environ_extra={"wsgi.url_scheme": "http"},
        )
        cookie = headers.get("Set-Cookie", "")
        assert cookie
        # The hardening set is unchanged; only the two transport additions
        # are present, and both are additive.
        assert headers.get("X-Frame-Options") == "DENY"
        assert headers.get("Content-Security-Policy")


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

    def test_a_negative_file_offset_does_not_slice_from_the_end(self, monkeypatch: Any) -> None:
        """A negative index counts back from the END of the buffer.

        `data[-10:-5]` is five bytes near the tail of the binary, and the
        length check below it passes, so a document carrying a negative
        `fileOffset` answered the Potato panel with the disassembly of
        unrelated bytes at the requested VA. api.py's /asm and /bytes both
        refuse a negative file offset for this reason; the panel hands this
        function the document's own value, so the refusal belongs where both
        paths arrive.
        """
        import recoverage.disasm as disasm

        binary = b"MZ" + bytes(range(64))
        monkeypatch.setattr(disasm, "_load_dll", lambda target: binary)
        try:
            assert disasm._disassemble_loaded(0x1000, 5, -10, "__neg_offset__") == ""
            assert disasm._disassemble_loaded(0x1000, -5, 0, "__neg_size__") == ""
        finally:
            disasm._disassemble_loaded.cache_clear()


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

    #: The cell-state to bucket fold, written out here rather than read back
    #: from ``server._BUCKET_FOLD`` (which reads it off
    #: ``rebrew.coverage_toml._BUCKET_OF_STATE``), so the walks below are
    #: checked against a literal and the two can be held against each other.
    _FOLD_BY_STATE: ClassVar[dict[str, str]] = {
        "data": "data",
        "exact": "exact",
        "near_match": "near_match",
        "near_matching": "near_match",
        "none": "none",
        "padding": "padding",
        "proven": "proven",
        "reloc": "reloc",
        "size_mismatch": "size_mismatch",
        "stub": "stub",
        "thunk": "thunk",
        "verified": "exact",
    }

    def test_the_state_to_bucket_fold_is_the_one_this_package_writes_down(self) -> None:
        """``_BUCKET_FOLD`` is read off rebrew, not spelled out here any more.

        A hand-written second copy of the fold was a vocabulary this package
        drifted from silently: a state rebrew added was absent from the copy,
        so it summed into no counted bucket while ``Section.covered_bytes``
        still counted it, and the served byte figures stopped reconciling with
        nothing failing. Reading the owner removes the drift; this holds what
        the owner hands over against the mapping this package documents, so a
        rebrew that changes the grouping says so here.
        """
        assert {bucket: set(states) for bucket, states in _BUCKET_FOLD.items()} == {
            bucket: {state for state, b in self._FOLD_BY_STATE.items() if b == bucket}
            for bucket in set(self._FOLD_BY_STATE.values())
        }

    def test_the_bucket_row_matches_a_walk_of_the_cells(self) -> None:
        """The served row is a copy of what rebrew derived; prove they agree.

        ``_bucket_row`` reads ``Section.bucket_counts`` rather than counting
        the cells again, so the fold that decides which state lands in which
        bucket is rebrew's rather than this module's.  Counting the cells here
        is the independent check that the two folds are the same fold.
        """
        import recoverage.server as srv

        snap = self._snap((*self.CELL_STATES, "near_matching", "verified", "drift"))
        section = snap.sections[".text"]
        counts: dict[str, int] = dict.fromkeys(self.BUCKET_KEYS, 0)
        other = 0
        for c in section.cells:
            bucket = self._FOLD_BY_STATE.get(c.state)
            if bucket is None:
                other += 1
            else:
                counts[bucket] += 1
        assert srv._bucket_row(section) == {
            "total_cells": len(section.cells),
            **counts,
            "other": other,
        }

    def test_the_section_summary_matches_a_walk_of_the_cells(self) -> None:
        """The same for the per-section summary, byte sums included.

        ``_section_summary`` reads the reader's ``buckets`` and
        ``bucket_counts`` and keeps its own count of the function NAMES the
        covered cells carry.  Both halves are recomputed here from the cells.
        """
        import recoverage.server as srv

        snap = self._snap(
            ("exact", "verified", "none", "reloc", "data", "thunk", "proven", "size_mismatch")
        )
        section = snap.sections[".text"]
        named = ("exact", "reloc", "near_match", "stub", "padding")
        counts = dict.fromkeys(named, 0)
        sizes = dict.fromkeys(named, 0)
        covered = 0
        total_functions = 0
        for c in section.cells:
            if c.state == "none":
                continue
            covered += c.size
            total_functions += len(c.functions)
            bucket = self._FOLD_BY_STATE.get(c.state)
            if bucket in counts:
                counts[bucket] += 1
                sizes[bucket] += c.size
        assert srv._section_summary(section) == {
            "exactMatches": counts["exact"],
            "relocMatches": counts["reloc"],
            "nearMatchCount": counts["near_match"],
            "stubCount": counts["stub"],
            "paddingCount": counts["padding"],
            "exactBytes": sizes["exact"],
            "relocBytes": sizes["reloc"],
            "nearMatchBytes": sizes["near_match"],
            "stubBytes": sizes["stub"],
            "paddingBytes": sizes["padding"],
            "coveredBytes": covered,
            "totalFunctions": total_functions,
            "size": section.size,
        }

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

    def test_the_1dp_rendering_floors_rather_than_rounds_back_up(self) -> None:
        """``pct_1dp`` is what the one-decimal surfaces print.

        ``"%.1f" % coverage_pct(999_999, 1_000_000)`` is ``"100.0"``: the 2dp
        value is 99.99 and the format rounds it back over the line the
        flooring drew, so a section three bytes short of complete reads as
        complete in the stats table, the Markdown export and the Potato header.
        """
        import recoverage.server as srv

        assert f"{srv.pct_1dp(srv.coverage_pct(999_999, 1_000_000)):.1f}" == "99.9"
        # 99.999% of 100_000 bytes floors to 99.99 the same way.
        assert f"{srv.pct_1dp(srv.coverage_pct(99_999, 100_000)):.1f}" == "99.9"
        # A complete section, and one already at 1dp, pass through unchanged.
        assert srv.pct_1dp(100.0) == 100.0
        assert srv.pct_1dp(0.0) == 0.0
        assert srv.pct_1dp(87.5) == 87.5
        assert srv.pct_1dp(87.45) == 87.4


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

    def test_a_section_with_no_cells_serves_no_bucket_row_and_an_empty_grid(self) -> None:
        """A declared section with no cells is not a section of `none` bytes.

        The old ``GROUP BY section_name`` produced no row for it, and that is
        the answer pinned here: no bucket row to count, an empty cell payload
        rather than an absent one, so the grid renders nothing instead of
        inventing a section-wide miss.
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

    def test_the_summary_s_covered_bytes_are_the_section_s_own(self) -> None:
        """Every section's summary entry carries the reader's covered bytes.

        ``coveredBytes`` is the one figure a section shows in three places at
        once: the summary entry, ``/stats``'s ``covered_bytes``, and Potato's
        header.  rebrew's ``Section`` derives it once, in ``__post_init__``,
        and this package used to re-derive it twice more from the raw cell
        states — with the "every state but ``none`` counts as covered" rule
        spelled out as a literal each time.  A cell state rebrew moved into or
        out of the uncovered set then left the summary and the stats entry
        disagreeing inside a single response, with no test able to see it,
        because the fixture vocabulary is fixed.  The `.data` fixture here is
        half covered, so a fold that dropped its ``none`` cell is caught.
        """
        import recoverage.server as srv

        snap = self._snap()
        summary = srv._summary(snap)
        for name, section in snap.sections.items():
            entry = summary[name] if name != ".text" else summary
            assert entry["coveredBytes"] == section.covered_bytes, name
            # And it is the non-``none`` bytes, not the whole section: .data is
            # one exact cell of two, so reading the total would pass the
            # equality above for .text and fail here.
        data = snap.sections[".data"]
        assert summary[".data"]["coveredBytes"] == sum(
            cell.size for cell in data.cells if cell.state != "none"
        )
        assert summary[".data"]["coveredBytes"] < data.size


class TestSortColumnVocabularyIsShared:
    """The function list's sort columns are ONE vocabulary, narrowed per surface.

    The API page and the Potato table order the same rows, and both reject a
    column they do not carry by answering the default order rather than by
    refusing, so a stale spelling of the column list is invisible: a reader
    asks for a column the surface dropped and gets a list in va order with
    nothing to say so.  Each surface therefore narrows
    `server.FUNCTION_SORT_COLUMNS` instead of writing its own list, and these
    are the three facts that keep the narrowing honest: the package's list is
    the union of the two surfaces', each surface's is a subset of it, and the
    key table covers every column but the one that has an arm of its own.
    """

    def test_the_package_list_is_the_union_of_the_two_surfaces(self) -> None:
        import recoverage.api as api_
        import recoverage.potato as potato_
        import recoverage.server as srv

        rendered = set(potato_.FUNCTION_LIST_COLUMNS)
        assert rendered == {"va", "name", "size", "status"}
        assert set(api_._ALLOWED_SORT) == set(srv.FUNCTION_SORT_COLUMNS)
        assert set(srv.FUNCTION_SORT_COLUMNS) >= rendered

    def test_every_column_but_size_resolves_to_an_attribute(self) -> None:
        """A column with no key would raise on the first row it ordered.

        `size` is the exception and has an arm of its own, because its NULL
        needs a tuple the plain attribute keys do not build.
        """
        import recoverage.server as srv

        assert set(srv.FUNCTION_SORT_FIELDS) | {"size"} == set(srv.FUNCTION_SORT_COLUMNS)
        for field in srv.FUNCTION_SORT_COLUMNS:
            assert callable(srv.function_sort_key(field)), field


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
    """`STATE_SLOTS` from `states.ts`, as state -> palette slot."""
    states_ts = _web("states.ts")
    block = re.search(
        r"const STATE_SLOTS = new Map<string, number>\(\[(.*?)\]\);", states_ts, re.DOTALL
    )
    assert block is not None, "states.ts no longer defines STATE_SLOTS"
    return {name: int(slot) for name, slot in re.findall(r'\["(\w+)",\s*(\d+)\]', block.group(1))}


def _array_items(source: str, name: str) -> list[str]:
    """The string items of one exported array literal in *source*."""
    match = re.search(rf"export const {name} = \[(.*?)\];", source, re.DOTALL)
    assert match is not None, f"{name} is no longer an array literal"
    return [item for item in re.findall(r'"([^"]+)"', match.group(1)) if item != ""]


def _full_fold_pairs() -> list[tuple[str, str]]:
    """The entries of `FULL_FOLD` in `lib/format.ts`, as (key, folded) pairs."""
    source = _web("lib/format.ts")
    body = source.split("const FULL_FOLD = new Map", 1)[1].split("]);", 1)[0]
    return re.findall(r'\["([^"]+)", "([^"]+)"\]', body)


def _filter_keys() -> list[str]:
    """`FILTER_KEY` from `states.ts`, empty first slot included.

    The empty string is load-bearing: it is the key every cell in palette slot
    0 carries, and the SPA never puts it in a filter set, so a slot-0 cell is
    dimmed by any active filter unless a filter exempts it by hand.
    """
    states_ts = _web("states.ts")
    block = re.search(r"export const FILTER_KEY = \[(.*?)\];", states_ts, re.DOTALL)
    assert block is not None, "states.ts no longer defines FILTER_KEY"
    return re.findall(r'"([^"]*)"', block.group(1))


def _spa_ground_state() -> str:
    """The cell state `packSection` marks as the ground a status filter never dims.

    Read from the source rather than restated here, so the pin below is a
    statement about what the map does and not a second copy of it.
    """
    match = re.search(r'ground\[i\] = cell\.state === "(\w+)" \? 1 : 0;', _web("grid/pack.ts"))
    assert match is not None, "pack.ts no longer marks a ground cell in the pack"
    assert "ground === 1" in _web("states.ts"), (
        "survivesFilter no longer exempts the ground, so a status filter dims it again"
    )
    return match.group(1)


def _spa_survives_filter(state: str, active: set[str]) -> bool:
    """The map's status-filter rule, as `states.ts` states it."""
    if not active or state == _spa_ground_state():
        return True
    return _filter_keys()[_packed_slots().get(state, 7)] in active


# Tailwind's stock steps, in the four scales the token layer replaces. A utility
# from one of them is a value nobody chose: the same `text-sm` reads 14px here
# because it happens to coincide with `--text-title` and 12px the day the scale
# moves, and the same `indigo-500` is a color the phosphor ground has no name
# for. The token spellings (`rounded-hair`, `text-label`, `bg-panel`) are not in
# these lists, which is what lets the scan be a plain word-boundary match.
_STOCK_TAILWIND_UTILITIES = re.compile(
    r"\b(?:text|bg|border|ring|fill|stroke|outline|decoration|from|to|via)-"
    r"(?:slate|gray|zinc|neutral|stone|red|orange|amber|yellow|lime|green|emerald"
    r"|teal|cyan|sky|blue|indigo|violet|purple|fuchsia|pink|rose)-"
    r"(?:50|[1-9]00)\b"
    r"|\btext-(?:xs|sm|base|lg|xl|[2-9]xl)\b"
    r"|\brounded-(?:sm|md|lg|xl|[2-3]xl|full)\b"
    r"|\bshadow-(?:sm|md|lg|xl|[2-9]xl|inner)\b"
)

# The `bg-*` and `fill-*` names that are not tokens: `transparent` and the two
# `clip-*` names set no hue, and `current` is the inherited text colour.
_BUILTIN_UTILITY_NAMES = frozenset({"transparent", "clip-path", "clip-border", "current"})


class TestSpaCarriesNoStockTailwindUtilities:
    """Every color, size, radius and shadow the dashboard paints is a token.

    The identity is the relumea brand, and it is written down in
    `web/app/system/tokens.css`: one accent, one neutral family, a radius
    ladder, a named type scale. A stock utility is the one thing that
    reintroduces the framework's palette beside it, and it does so invisibly,
    because `indigo-500` beside `bg-surface` is a correct-looking Tailwind class
    rather than a visible bug. The token file clears Tailwind's stock scales and
    `shadcn/no-unknown-classes` fails a class that generates nothing, so this
    scan is the second of two gates. One such utility
    is a choice; a page of them is the default look the tokens exist to replace,
    so the rule is held here rather than left to review.
    """

    @staticmethod
    def _sources() -> list[Path]:
        return sorted(p for p in WEB_APP.rglob("*") if p.suffix in (".ts", ".tsx"))

    def test_every_frontend_source_is_scanned(self) -> None:
        assert len(self._sources()) >= 10, "the scan found fewer sources than the tree ships"

    def test_no_source_uses_a_stock_utility(self) -> None:
        found: list[str] = []
        for path in self._sources():
            found.extend(
                f"{path.relative_to(REPO_ROOT)}:{number}: {match.group(0)}"
                for number, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1)
                for match in _STOCK_TAILWIND_UTILITIES.finditer(line)
            )
        message = "stock Tailwind utilities outside the token layer:\n  " + "\n  ".join(found)
        assert found == [], message

    def test_every_color_utility_names_a_published_token(self) -> None:
        """A color a component names has to exist, or the utility is a no-op.

        Tailwind 4 resolves a class at build time and silently drops one whose
        theme entry is absent, so a misspelled `bg-pannel` compiles away and
        the panel paints the ground behind it. The scan above cannot see that,
        because the class is not a stock utility: it is a typo in a token name.
        """
        published = set(re.findall(r"--color-([a-z0-9-]+):", _web("system/tokens.css")))
        missing: list[str] = []
        for path in self._sources():
            for number, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
                for name in re.findall(r"\b(?:bg|fill|stroke)-([a-z][a-z0-9-]*)\b", line):
                    if name in _BUILTIN_UTILITY_NAMES or name in published:
                        continue
                    missing.append(f"{path.relative_to(REPO_ROOT)}:{number}: {name}")
        assert missing == [], "color utilities no token publishes:\n  " + "\n  ".join(missing)


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
        states = _web("states.ts")
        assert len(_array_items(states, "PALETTE_VARS")) == 8
        raw_filters = re.search(r"export const FILTER_KEY = \[(.*?)\];", states).group(1)
        assert len(re.findall(r'"([a-z_]*)"', raw_filters)) == 8
        assert len(_array_items(states, "STATE_LABEL")) == 8
        assert max(_packed_slots().values()) == 7

    def test_every_palette_variable_is_a_published_token(self) -> None:
        """The canvas resolves each name at paint time, and a name the token
        file does not declare resolves to nothing: the slot paints black."""
        tokens = _web("system/tokens.css")
        for name in _array_items(_web("states.ts"), "PALETTE_VARS"):
            assert f"{name}:" in tokens, f"{name} is not a token"

    def test_legend_names_every_painted_slot(self) -> None:
        """Every slot the map can paint needs a legend row.

        The legend is rendered from STATE_LABEL, so the rows are its indices:
        a state the map paints into a slot the label table does not reach has
        no word to show in the legend or the hover title.
        """
        app = _web("App.tsx")
        assert "STATE_LABEL.map((label, slot) =>" in app
        labels = len(_array_items(_web("states.ts"), "STATE_LABEL"))
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
        """A legend row draws its swatch from SWATCH_CLASS, and SWATCH_CLASS is
        PALETTE_VARS spelled as utilities, slot for slot, so a row cannot name
        a colour the map paints from somewhere else."""
        app = _web("App.tsx")
        assert "SWATCH_CLASS[slot]" in app
        states = _web("states.ts")
        palette = _array_items(states, "PALETTE_VARS")
        swatches = _array_items(states, "SWATCH_CLASS")
        assert swatches == [f"bg-{name.removeprefix('--color-')}" for name in palette]

    def test_cell_tooltip_names_the_state_and_function(self) -> None:
        """The hover title says what the cell is, not a 0/1 flag."""
        map_source = _web("components/CoverageMap.tsx")
        assert "Block ${count(index)}" in map_source
        assert "STATE_LABEL[pack.states[index]" in map_source
        assert "no function" in map_source


class TestSpaNumericBoundaries:
    """The dashboard's own arithmetic: a range, a fraction and a lattice width,
    each read off the coverage document and each with a bound the Python
    surfaces already applied.

    `rebrew.coverage_toml` reads these columns as plain ints and whatever the
    document spells (only a non-finite FLOAT is nulled on the wire, by
    `server._plain`), so every narrowing the SPA does on them is a place a
    hand-edited or hostile document silently becomes a different number. The
    map and Potato Mode render the same document, so the two apply one bound.
    """

    def test_the_va_lookup_treats_the_cell_end_as_exclusive(self) -> None:
        """`cellIndexForVa` resolved a boundary address to the PREVIOUS cell.

        rebrew's grid writes `cur = cell_end` for the next cell and a cell's
        size is `end - start` (the slice in `useSelection`, `potato`'s hex
        dump), so `end` is the first byte of the NEXT block. Read as
        inclusive, every address on a boundary matched the cell before it,
        and a function's entry VA is exactly a boundary, so every search hit
        and every parent-function link opened the block before the one named.
        """
        source = _web("hooks/useSelection.ts")
        body = source.split("export function cellIndexForVa", 1)[1].split("\nfunction ", 1)[0]
        assert "relative >= cell.start && relative < cell.end" in body
        assert "relative <= cell.end" not in body

    def test_cell_offsets_are_not_narrowed_to_32_bits(self) -> None:
        """`starts`/`ends` hold section-relative byte offsets, read with no
        ceiling in the reader, and were `Uint32Array`: an offset past 2^32
        wrapped to `offset % 2^32` and the map announced an address in a
        different section. A double holds every offset a PE file can."""
        packed = _web("grid/pack.ts").split("export type Packed = {", 1)[1].split("};", 1)[0]
        for column in ("starts", "ends"):
            declared = re.search(rf"{column}: (\w+);", packed)
            assert declared is not None, f"Packed no longer declares {column}"
            assert declared.group(1) == "Float64Array", (
                f"{column} is a {declared.group(1)}: a document offset past its "
                "range wraps silently"
            )

    def test_a_span_past_the_typed_range_saturates(self) -> None:
        """`spans` is a `Uint16Array` and `span` is unbounded in the reader, so
        a stored span above 65535 wrapped to `span % 65536` and the cell was
        laid out over the wrong number of dots."""
        stored = re.search(r"spans\[i\] = (.*?);\n", _web("grid/pack.ts"), re.DOTALL)
        assert stored is not None, "packSection no longer fills spans[i]"
        assert "Math.min(" in stored.group(1), (
            f"spans[i] = {stored.group(1)}: a span past 65535 wraps silently"
        )

    def test_the_lattice_width_is_clamped_to_what_potato_clamps_it_to(self) -> None:
        """`columns` is unbounded in the reader, and `layoutSection` sizes a
        `new Int32Array(rows * cols)` from it, so a document declaring 1e9
        columns asks the renderer for gigabytes. Potato Mode has clamped to
        256 all along; the map drew the same document unbounded."""
        from recoverage.potato import _MAX_GRID_COLUMNS

        exported = re.search(r"export const MAX_GRID_COLUMNS = (\d+);", _web("grid/pack.ts"))
        assert exported is not None, "pack.ts no longer exports MAX_GRID_COLUMNS"
        assert int(exported.group(1)) == _MAX_GRID_COLUMNS
        # And the map has to APPLY it, not merely export it.
        assert "MAX_GRID_COLUMNS" in _web("components/CoverageMap.tsx")

    def test_similarity_is_scaled_only_when_it_is_a_number(self) -> None:
        """Both similarity columns are 0-1 fractions, so the SPA scales by 100.
        The declared type is `number | null`, but the value is document data:
        a string passed `server._plain` untouched, and `"87.3" * 100` is 8730,
        so the panel read `8,730.0%` where Potato omits the row outright."""
        helper = _web("lib/format.ts").split("export function similarityPct", 1)[1].split("}", 1)[0]
        assert 'typeof fraction !== "number"' in helper
        assert "Number.isFinite(fraction)" in helper
        # Every surface that renders one goes through the helper, rather than
        # repeating the unguarded `similarity * 100`.
        panel = _web("components/CoveragePanel.tsx")
        assert "similarityPct(" in panel
        assert "similarity * 100" not in panel

    def test_a_span_the_bounds_cannot_catch_does_not_vanish(self) -> None:
        """A NaN span stored 0, and a cell laid out over no dots is a cell the
        map never draws and no click ever reaches.

        `Math.max` and `Math.min` both RETURN a NaN rather than passing it
        through an argument, so neither the floor of 1 nor the ceiling caught
        it, and the Uint16Array store turned it into a 0 that
        `forEachPlacement`'s `while (left > 0)` skipped whole."""
        pack = _web("grid/pack.ts")
        stored = re.search(r"Number\.isNaN\(rawSpan\)(.*?);\n", pack, re.DOTALL)
        assert stored is not None, "packSection no longer narrows a NaN span"
        assert "MAX_SPAN" in stored.group(1), (
            "a NaN span falls through to the reader's default instead of the bounded store"
        )

    def test_a_non_finite_column_count_cannot_size_the_lattice(self) -> None:
        """`columns` is document data, and a NaN beats every bound it meets:
        `Math.min(NaN, 256)` is NaN, `Math.max(1, NaN, n)` is NaN, and
        `new Int32Array(rows * NaN)` is a zero-length array, so the section
        rendered as a blank canvas instead of a merely narrow one."""
        layout = _web("grid/pack.ts").split("export function layoutSection", 1)[1]
        narrowed = re.search(r"const declared = (.*?);\n", layout, re.DOTALL)
        assert narrowed is not None, "layoutSection no longer narrows declaredColumns"
        assert "Number.isFinite(declaredColumns)" in narrowed.group(1)
        assert "DEFAULT_GRID_COLUMNS" in narrowed.group(1)
        # The narrowed value is the one the lattice is measured from.
        assert "Math.max(1, declared," in layout


# The colour maths behind both token gates. Every relumea token is declared
# once as `light-dark(<light>, <dark>)` in `web/app/system/tokens.css`, a
# verbatim copy of relumea.ai's; relumea.ai's `check:contrast` owns the full
# matrix, and these two classes hold the pairs this dashboard actually paints,
# so a copy that drifted from a measured file fails here.

_THEMES = ("light", "dark")


def _token_pairs() -> dict[str, tuple[str, str]]:
    """`name -> (light, dark)` for every colour token the SPA can read."""
    return {
        name: (light.lower(), dark.lower())
        for name, light, dark in re.findall(
            r"--color-([a-z0-9-]+):\s*light-dark\(\s*(#[0-9a-fA-F]{6}),\s*(#[0-9a-fA-F]{6})\s*\);",
            _web("system/tokens.css"),
        )
    }


def _token(name: str, theme: str) -> tuple[float, float, float]:
    value = _token_pairs()[name][_THEMES.index(theme)]
    return tuple(int(value[index : index + 2], 16) / 255 for index in (1, 3, 5))  # type: ignore[return-value]


def _luminance(rgb: tuple[float, float, float]) -> float:
    def linear(channel: float) -> float:
        return channel / 12.92 if channel <= 0.04045 else ((channel + 0.055) / 1.055) ** 2.4

    red, green, blue = (linear(channel) for channel in rgb)
    return 0.2126 * red + 0.7152 * green + 0.0722 * blue


def _contrast(left: tuple[float, float, float], right: tuple[float, float, float]) -> float:
    darker, lighter = sorted((_luminance(left), _luminance(right)))
    return (lighter + 0.05) / (darker + 0.05)


def _lab(rgb: tuple[float, float, float]) -> tuple[float, float, float]:
    """CIELAB (D65) of an sRGB colour, for the ΔE between two fills."""

    def linear(channel: float) -> float:
        return channel / 12.92 if channel <= 0.04045 else ((channel + 0.055) / 1.055) ** 2.4

    red, green, blue = (linear(channel) for channel in rgb)
    x = (0.4124 * red + 0.3576 * green + 0.1805 * blue) / 0.95047
    y = 0.2126 * red + 0.7152 * green + 0.0722 * blue
    z = (0.0193 * red + 0.1192 * green + 0.9505 * blue) / 1.08883

    def f(value: float) -> float:
        return value ** (1 / 3) if value > 216 / 24389 else (24389 / 27 * value + 16) / 116

    return (116 * f(y) - 16, 500 * (f(x) - f(y)), 200 * (f(y) - f(z)))


def _delta_e(left: tuple[float, float, float], right: tuple[float, float, float]) -> float:
    """CIE76 colour difference."""
    return math.dist(_lab(left), _lab(right))


def _marks() -> list[str]:
    """`MARK_CLASS` from `states.ts`, empty slots included."""
    block = re.search(r"export const MARK_CLASS[^=]*= \[(.*?)\];", _web("states.ts"), re.DOTALL)
    assert block is not None, "states.ts no longer defines MARK_CLASS"
    return re.findall(r'"([^"]*)"', block.group(1))


class TestCellFillsAreDrawnPerTheme:
    """A cell fill is a graphic, so it owes 3:1 against what it is painted on.

    The map paints on `surface` (the card the canvas sits in). The fills are
    `PALETTE_VARS` in `states.ts`, minus the unlit cell, which is the ground
    of an unread byte and is quiet on purpose.

    The fills also sit at one lightness and differ by hue alone, with three
    greens and two greys among them, so a pair closer than `SAME_HUE_DELTA_E`
    must differ in its ink mark (`MARK_CLASS`), and the mark ink must clear the
    floor on the fill it is drawn over.  Padding's fill is the hairline token
    and is exempt from the fill floor; its mark is what makes it visible.
    """

    NON_TEXT_FLOOR = 3.0
    # Measured on the relumea fills: the three greens pair at ΔE 5.9 to 15.6
    # and every other pair is 20.8 or more apart.
    SAME_HUE_DELTA_E = 20.0
    # The ink each mark is drawn in; padding is filler and takes the muted ink.
    MARK_INK: ClassVar[dict[str, str]] = {
        "mark-dots": "text",
        "mark-hatch": "text",
        "mark-rule": "text-muted",
    }

    @staticmethod
    def _fills() -> list[str]:
        palette = _array_items(_web("states.ts"), "PALETTE_VARS")
        # The unlit ground and the padding filler are background, not state.
        quiet = {"--color-cell-unlit", "--color-border-strong"}
        return [name.removeprefix("--color-") for name in palette if name not in quiet]

    def test_every_fill_is_a_light_dark_pair(self) -> None:
        pairs = _token_pairs()
        for name in self._fills():
            light, dark = pairs[name]
            assert light != dark, f"{name} is one value read over two grounds"

    def test_dark_fills_clear_the_non_text_floor(self) -> None:
        low = {
            name: round(_contrast(_token(name, "dark"), _token("surface", "dark")), 2)
            for name in self._fills()
        }
        assert all(ratio >= self.NON_TEXT_FLOOR for ratio in low.values()), low

    def test_light_fills_clear_the_non_text_floor(self) -> None:
        low = {
            name: round(_contrast(_token(name, "light"), _token("surface", "light")), 2)
            for name in self._fills()
        }
        assert all(ratio >= self.NON_TEXT_FLOOR for ratio in low.values()), low

    @pytest.mark.parametrize("theme", _THEMES)
    def test_fills_that_share_a_hue_carry_different_marks(self, theme: str) -> None:
        palette = _array_items(_web("states.ts"), "PALETTE_VARS")
        marks = _marks()
        assert len(marks) == len(palette)
        slots = range(1, len(palette))
        clashes = [
            f"{palette[left]} / {palette[right]}: {marks[left]!r}"
            for left in slots
            for right in slots
            if left < right
            and marks[left] == marks[right]
            and _delta_e(
                _token(palette[left].removeprefix("--color-"), theme),
                _token(palette[right].removeprefix("--color-"), theme),
            )
            < self.SAME_HUE_DELTA_E
        ]
        assert clashes == [], f"{theme}: " + "; ".join(clashes)

    @pytest.mark.parametrize("theme", _THEMES)
    def test_every_mark_is_drawn_in_an_ink_that_clears_the_floor(self, theme: str) -> None:
        palette = _array_items(_web("states.ts"), "PALETTE_VARS")
        css = _web("index.css")
        low: dict[str, float] = {}
        for fill, mark in zip(palette, _marks(), strict=True):
            if mark == "":
                continue
            rule = re.search(rf"@utility {mark} {{(.*?)\n}}", css, re.DOTALL)
            assert rule is not None, mark
            assert f"var(--color-{self.MARK_INK[mark]})" in rule.group(1), mark
            ratio = _contrast(
                _token(self.MARK_INK[mark], theme), _token(fill.removeprefix("--color-"), theme)
            )
            if ratio < self.NON_TEXT_FLOOR:
                low[mark] = round(ratio, 2)
        assert low == {}, f"{theme}: {low}"
        source = _web("components/CoverageMap.tsx")
        for ink in set(self.MARK_INK.values()):
            assert f'resolveColour(probe, "--color-{ink}")' in source, ink
        assert 'mark === "mark-rule" ? muted : ink' in source

    def test_the_padding_slot_carries_a_mark(self) -> None:
        padding = _filter_keys().index("padding")
        assert _marks()[padding] != ""


class TestSpaTextTokensClearTheTextFloor:
    """Every text token the dashboard prints clears 4.5:1 where it prints it.

    The grounds are the ones the shell paints: the page, a card, a chip or
    hover fill, a panel head and the code plate, plus the two tints a message
    sits on (the notice on `live-soft`, the error on `fail-soft`).
    """

    TEXT_FLOOR = 4.5
    GROUNDS = ("bg", "surface", "surface-2", "surface-3", "raised", "code")
    INKS = (
        "text",
        "text-muted",
        "text-faint",
        "st-exact",
        "st-reloc",
        "st-proven",
        "st-near",
        "st-stub",
        "st-fail",
        "syn-keyword",
        "syn-type",
        "syn-string",
        "syn-number",
        "syn-register",
        "syn-call",
        "syn-comment",
    )

    @pytest.mark.parametrize("theme", _THEMES)
    def test_every_ink_clears_the_floor_on_every_ground(self, theme: str) -> None:
        low = [
            f"{ink} on {ground}: {ratio:.2f}"
            for ink in self.INKS
            for ground in self.GROUNDS
            if (ratio := _contrast(_token(ink, theme), _token(ground, theme))) < self.TEXT_FLOOR
        ]
        assert low == [], f"{theme}: " + "; ".join(low)

    @pytest.mark.parametrize("theme", _THEMES)
    @pytest.mark.parametrize(("ink", "tint"), [("text", "live-soft"), ("st-fail", "fail-soft")])
    def test_the_message_lines_clear_the_floor_on_their_tint(
        self, theme: str, ink: str, tint: str
    ) -> None:
        ratio = _contrast(_token(ink, theme), _token(tint, theme))
        assert ratio >= self.TEXT_FLOOR, f"{theme} {ink} on {tint}: {ratio:.2f}"

    def test_every_ink_is_one_the_sources_name(self) -> None:
        """An ink listed here and printed nowhere is a gate over nothing."""
        sources = "".join(
            path.read_text(encoding="utf-8")
            for path in sorted(WEB_APP.rglob("*"))
            if path.suffix in (".ts", ".tsx", ".css") and "system" not in path.parts
        )
        unused = [ink for ink in self.INKS if ink not in sources]
        assert unused == [], unused


class TestSpaTopbarReflowsAtTheNarrowViewport:
    """A topbar row that cannot break is content that cannot be reached.

    1.4.10 asks the page to reflow to 320 CSS px, and the shell clips its
    overflow (`body { overflow-x: clip }` in `index.css`) so no wide child can
    open a horizontal scrollbar. Clipping means a row
    wider than the viewport is not scrolled off to the side: whatever sits past
    the edge is gone, with no scroll position that brings it back. The rows that
    hold the controls therefore wrap, and the search column may shrink.
    """

    #: The topbar rows, and the utility each one needs so a row added beside
    #: them inherits the rule rather than a reviewer's memory of it.
    ROWS: ClassVar[tuple[str, str]] = (
        ("search-row", "flex-wrap"),
        ("actions", "flex-wrap"),
    )

    @staticmethod
    def _class_of(source: str, marker: str) -> str:
        line = next(
            (candidate for candidate in source.splitlines() if f'"{marker} ' in candidate),
            None,
        )
        assert line is not None, f"the topbar no longer renders a {marker!r} row"
        found = re.search(r'className="([^"]+)"', line)
        assert found is not None, f"the {marker!r} row carries no className"
        return found.group(1)

    def test_body_overflow_is_clipped(self) -> None:
        """The premise the rest of this class rests on: if the shell stopped
        clipping, a non-wrapping row would scroll instead of disappearing, and
        the wraps below would be belt rather than braces."""
        assert "overflow-x: clip" in _web("index.css")

    @pytest.mark.parametrize(("marker", "utility"), list(ROWS))
    def test_the_row_wraps(self, marker: str, utility: str) -> None:
        classes = self._class_of(_web("App.tsx"), marker)
        assert utility in classes.split(), f"{marker} cannot wrap: {classes}"

    def test_the_search_column_may_shrink(self) -> None:
        """`min-width: auto` on a flex item resolves to its content minimum, so
        without `min-w-0` the column is as wide as the widest fixed width any
        child declares and wraps nothing."""
        classes = self._class_of(_web("App.tsx"), "search")
        assert "min-w-0" in classes.split(), classes

    def test_the_search_field_is_capped_at_the_column(self) -> None:
        """The field fills its column and may shrink with it: a fixed width
        here is the one child that could hold the column wider than a 320px
        viewport, with the Clear button pushed past the edge."""
        source = _web("App.tsx")
        start = next(
            index for index, line in enumerate(source.splitlines()) if 'id="search-input"' in line
        )
        field = " ".join(source.splitlines()[start : start + 3])
        classes = re.search(r'className="([^"]+)"', field)
        assert classes is not None
        assert {"w-full", "min-w-0"} <= set(classes.group(1).split())


class TestSpaLocaleFormatting:
    """The numbers and the search fold the dashboard prints, not `toFixed`.

    The server has one rule for both: a coverage figure is floored rather than
    rounded, so a project one byte short of complete never reads as complete.
    `format.percent1` is that rule in the browser, and it hands the digits to
    `toLocaleString`, so a served 99.99 reads as "99,9" to a reader whose
    locale writes a comma rather than as "100.0" to everyone. A component that
    formats its own figure undoes both halves of it.
    """

    def test_no_component_formats_a_number_itself(self) -> None:
        offenders = sorted(
            str(path.relative_to(REPO_ROOT))
            for path in WEB_APP.rglob("*")
            if path.suffix in {".ts", ".tsx"}
            and path.name != "format.ts"
            and (".toFixed(" in path.read_text(encoding="utf-8"))
        )
        assert offenders == [], f"toFixed outside lib/format.ts: {offenders}"

    def test_the_served_figures_go_through_the_helpers(self) -> None:
        strip = _web("components/StatsStrip.tsx")
        assert "percentLabel(summary.coveragePercent)" in strip
        assert "percentLabel(sectionPct)" in strip
        assert "count(summary.totalFunctions)" in strip

    def test_the_section_figure_names_its_section(self) -> None:
        """The strip's last figure is the section's coverage, and on a project
        that is complete it reads word for word the same as the target's first
        figure. Unlabelled, one number printed twice reads as one number; the
        section's own name travels with its figure, and neither served value is
        dropped or divided again."""
        strip = _web("components/StatsStrip.tsx")
        assert "{section}</span> {percentLabel(sectionPct)}" in strip
        assert "sectionPct={row?.coverage_pct ?? null}" in strip

    def test_a_percentage_is_one_directional_run(self) -> None:
        """The sign travels with the digits it belongs to.

        `toLocaleString` spells the digits in the reader's script, and `%` is a
        bidi NEUTRAL, so a figure interpolated into a sentence kept the sign
        away from its own number wherever the text around it ran the other way.
        Every surface printing a percentage with a sign goes through the one
        helper that isolates the pair, rather than concatenating the sign at a
        call site.
        """
        fmt = _web("lib/format.ts")
        body = fmt.split("export function percentLabel", 1)[1].split("\n}", 1)[0]
        assert "percent1(percentage)" in body
        assert "isolate(" in body
        similarity = fmt.split("export function similarityPct", 1)[1].split("\n}", 1)[0]
        assert "percentLabel(fraction * 100)" in similarity
        # No call site spells the sign out beside its own figure.
        offenders = sorted(
            str(path.relative_to(REPO_ROOT))
            for path in WEB_APP.rglob("*")
            if path.suffix in {".ts", ".tsx"}
            and path.name != "format.ts"
            and any(needle in path.read_text(encoding="utf-8") for needle in ("}%", "percent1("))
        )
        assert offenders == [], f"percentage spelled at the call site: {offenders}"

    def test_percent1_floors_and_localizes(self) -> None:
        """The helper is the flooring and the locale, not a bare `toFixed`."""
        fmt = _web("lib/format.ts")
        body = fmt.split("export function percent1", 1)[1].split("\n}", 1)[0]
        assert "Math.floor(" in body
        assert "toLocaleString(" in body
        assert "toFixed(" not in body

    def test_the_spa_fold_expansions_are_the_servers_casefold(self) -> None:
        """Every entry of `FULL_FOLD` is what `str.casefold` does to that key.

        The map is the SPA's stand-in for the one-to-many mappings JavaScript
        has no operator for. A spelling Python folds differently leaves the two
        sides of a search disagreeing, which is the bug the table exists to
        close, so the table is checked against the server's own fold rather
        than against a list of expectations.
        """
        assert _full_fold_pairs(), "FULL_FOLD is no longer a map literal"
        for source, folded in _full_fold_pairs():
            assert source.casefold() == folded, source


class TestSpaTimestampRendering:
    """`format.dateTime` renders a document's stamp in the reader's own zone.

    The coverage document's `updated_at` and `last_verify.verified_at` are
    rebrew-written UTC ISO strings carrying an offset, so they name an instant
    and the browser reads them correctly on its own. A stamp with no time of
    day names a CALENDAR DAY instead, and the two ISO forms `Date` reads by
    are not the same: a bare `2026-09-29` is UTC midnight, a naive
    `2026-09-29T00:00:00` is the reader's own midnight. Parsed as it arrived,
    a day-only stamp read as the day before for every reader west of UTC
    (America/Sao_Paulo, UTC-3, reads "Mon Sep 28" for a stamp that names the
    29th), which is the date-shift the format's own reading of a naive string
    is meant to prevent.
    """

    def test_a_day_only_stamp_is_read_as_a_calendar_day(self) -> None:
        body = _web("lib/format.ts").split("export function dateTime", 1)[1].split("\n}", 1)[0]
        assert "DATE_ONLY.test(stamp)" in body, "a day-only stamp has no reader-side anchor"
        assert "T00:00:00" in body, "the day is not anchored to the reader's midnight"

    def test_the_day_only_form_is_a_whole_date_and_nothing_else(self) -> None:
        """The pattern must not swallow a stamp that carries a time or an offset.

        A greedy `^\\d{4}-\\d{2}-\\d{2}` would rewrite `2026-09-29T12:00:00Z`
        into a value with no offset, and the instant rebrew stored would then
        be read as the reader's noon rather than as UTC noon.

        The `u` flag is required alongside: it is what makes the pattern the
        Unicode-aware parser the lint gate asks for, and it leaves `\\d` the
        ASCII digits it already was, so a non-ASCII digit spelling of a day
        still fails the test and falls back to the raw string.
        """
        match = re.search(r"const DATE_ONLY = /(.+?)/(\w*);", _web("lib/format.ts"))
        assert match is not None, "DATE_ONLY is no longer a pattern literal"
        # Flags ride after the closing delimiter, so only the pattern body is
        # compared: the `u` flag oxlint's require-unicode-regexp asks for does
        # not change what this pattern matches (`\d` is ASCII under `u` too).
        assert match.group(1) == r"^\d{4}-\d{2}-\d{2}$", match.group(1)
        assert "u" in match.group(2), f"DATE_ONLY lost its u flag: /{match.group(2)}/"

    #: The reader zones the render is driven in, and the calendar day each of
    #: them must show for the stamps below. One well west of UTC, one east of
    #: it, one on a zone that observes DST, so a reader whose own clock is a
    #: different offset from the writer's is exercised rather than assumed.
    ZONE_DAYS: ClassVar[dict[str, tuple[str, str]]] = {
        # (day-only stamp -> the day it names, instant stamp -> the reader's day)
        "America/Sao_Paulo": ("2026-09-29", "28"),
        "Europe/Warsaw": ("2026-09-29", "29"),
        "Pacific/Auckland": ("2026-09-29", "29"),
    }

    #: An instant two hours after UTC midnight on the 29th: still the 29th
    #: east of Greenwich, already the 28th west of it. The two renderings of it
    #: cannot both name one day, which is what makes the pair a real oracle.
    WEST_OF_UTC_STAMP = "2026-09-29T02:00:00+00:00"

    def test_the_rendered_day_is_the_readers_own_calendar_day(self) -> None:
        """The shipped function, run in a reader's zone, not a description of it.

        The two assertions above read `lib/format.ts` as text, so they hold
        whatever the code says about itself and say nothing about what a
        browser does with it: a `DATE_ONLY.test` inverted, or the anchor time
        half carrying an offset, both pass them and both move the day off the
        calendar for every reader outside the writer's zone. Running the
        module under a `TZ` is what proves the rendering.
        """
        bun = shutil.which("bun")
        if bun is None:
            pytest.skip("bun not on PATH")

        driver = (
            "import { dateTime } from " + json.dumps(str(WEB_APP / "lib" / "format.ts")) + ";\n"
            "console.log(JSON.stringify([dateTime(process.argv[2]), "
            "dateTime(process.argv[3]), dateTime('not a timestamp')]));\n"
        )
        with tempfile.TemporaryDirectory() as tmp:
            script = Path(tmp) / "render.ts"
            script.write_text(driver, encoding="utf-8")
            rendered: dict[str, list[str]] = {}
            for zone, (day_only, _west_day) in self.ZONE_DAYS.items():
                proc = subprocess.run(
                    [bun, "run", str(script), day_only, self.WEST_OF_UTC_STAMP],
                    capture_output=True,
                    text=True,
                    timeout=60,
                    check=False,
                    env={**os.environ, "TZ": zone},
                )
                assert proc.returncode == 0, f"dateTime harness failed to run: {proc.stderr}"
                rendered[zone] = json.loads(proc.stdout)

        for zone, (_day_only, west_day) in self.ZONE_DAYS.items():
            as_written, instant, unreadable = rendered[zone]
            # A day-only stamp names a calendar day, so every reader's zone
            # shows that day. The digit guards are spelled as lookaround
            # because `toLocaleString` picks its own ordering and separators:
            # a bare "29" would be satisfied by a year or a clock that carried
            # one, and neither is the day under test.
            assert as_written != _day_only, f"{zone}: the stamp was not rendered ({as_written!r})"
            assert re.search(r"(?<!\d)29(?!\d)", as_written), (
                f"{zone}: day-only stamp lost its day ({as_written!r})"
            )
            assert not re.search(r"(?<!\d)28(?!\d)", as_written), (
                f"{zone}: day-only stamp moved a day ({as_written!r})"
            )
            # The same function, given an instant, converts it: west of UTC the
            # 29th in the document is the 28th on the reader's wall clock. A
            # renderer that echoed the writer's zone fails this, and the zones
            # on both sides of Greenwich are what make it fail loudly.
            assert re.search(rf"(?<!\d){west_day}(?!\d)", instant), (
                f"{zone}: {instant!r} is not the reader's own day"
            )
            assert unreadable == "not a timestamp", f"{zone}: an unreadable stamp was rendered"


class TestSpaSearchFoldsLikeTheServer:
    """The search box compares in the same form `server.fold_match` does.

    The dashboard runs its own search over the served `search_index` while
    `/functions?search=` and the Potato list run `server.fold_match`, so the
    two surfaces can disagree about a name they are both looking at. Both
    halves of the server's fold are reproduced in the browser: the composition
    by `normalize("NFC")` and the case half by `FULL_FOLD`, which is what
    `toLowerCase` has no operator for. The composition is the one that silently
    reports "0 matches" for a symbol a macOS-side tool wrote NFD.
    """

    def test_both_sides_of_the_search_go_through_the_shared_fold(self) -> None:
        """A needle folded one way and a haystack folded another never match."""
        app = _web("App.tsx")
        # The haystack is folded once per index (`foldedIndex`) and the needle
        # once per keystroke (`matchedNames`); the two together are the whole
        # comparison, and neither half may reach for a fold of its own.
        search = app.split("const foldedIndex", 1)[1].split("const matchedFns", 1)[0]
        assert search.count("foldForSearch(") == 2, "the needle and the haystack fold differently"
        assert "toLowerCase()" not in search, "the search folds somewhere other than foldForSearch"

    def test_the_haystack_is_folded_per_index_and_not_per_keystroke(self) -> None:
        """The fold is the cost, and only the index decides the haystack.

        `foldForSearch` is `normalize` + `toLowerCase` + a full-fold replace,
        so running it over every function in the target on every character
        typed is a main-thread task that grows with the target and never gets
        any cheaper: measured in `bun` over a synthetic index, 90 ms per
        keystroke at 20k entries against 1.4 ms for a substring test over rows
        folded once. The memo's dependency list is what keeps the fold off the
        keystroke path, and the per-keystroke pass has to read the folded rows
        rather than rebuild them.
        """
        app = _web("App.tsx")
        folded = re.search(
            r"const foldedIndex = useMemo\(\(\) => \{.*?\}, \[(.*?)\]\);",
            app,
            re.DOTALL,
        )
        assert folded is not None, "the folded search index is no longer a memo"
        deps = [dep.strip() for dep in folded.group(1).split(",")]
        assert deps == ["coverage.searchIndex"], (
            "the haystack is rebuilt for something other than a new index"
        )
        matched = re.search(
            r"const matchedNames = useMemo\(\(\) => \{.*?\}, \[(.*?)\]\);",
            app,
            re.DOTALL,
        )
        assert matched is not None, "the match pass is no longer a memo"
        assert "foldedIndex" in matched.group(1), "the match pass does not read the folded rows"

    def test_the_fold_composes_to_nfc(self) -> None:
        """`toLowerCase` alone compares "café" NFD and NFC as different
        strings, which is the whole defect: the coverage document carries
        whichever spelling the tool that wrote it used, and the user types the
        composed one."""
        fmt = _web("lib/format.ts")
        body = re.search(
            r"export function foldForSearch\(text: string\): string \{\s*return (.*?);\s*\}",
            fmt,
            re.DOTALL,
        )
        assert body is not None, "foldForSearch is no longer a one-expression helper"
        assert '.normalize("NFC")' in body.group(1)
        assert body.group(1).index(".normalize(") < body.group(1).index(".toLowerCase()"), (
            "lowercasing before composing is not the same fold"
        )

    def test_the_fold_agrees_with_the_server_on_the_nfd_pair(self) -> None:
        """The property the fold exists for, asserted on the server's side.

        The TS cannot be executed from here (no JS runtime in the test
        environment), so the oracle is the composition itself: a name and its
        NFD twin are one key under `fold_text`, which is the equality the SPA's
        fold has to reproduce.
        """
        import unicodedata

        from recoverage.server import fold_text

        nfc = unicodedata.normalize("NFC", "café")
        nfd = unicodedata.normalize("NFD", nfc)
        assert nfc != nfd, "the two spellings are one string, so this asserts nothing"
        assert fold_text(nfc) == fold_text(nfd)


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

    def test_the_grid_state_is_rebuilt_on_the_section_alone(self) -> None:
        """The rebuilt state starts at `focus: 0`, so it is the section's
        geometry that may drop it and nothing else. `paint` is a function of the
        selection, the filters and the match set, so listing it in the teardown's
        deps re-ran the rebuild on every click and every search keystroke, and
        the roving cursor went back to the first block on the render the click
        that moved it caused. `geometry` is keyed on `pack` and `declaredColumns`,
        which is the section, so the section is still the trigger."""
        map_source = _web("components/CoverageMap.tsx")
        rebuild = map_source.index("focus: 0,")
        end = map_source.index("}, [", rebuild)
        deps = map_source[end : map_source.index("]);", end)]
        assert "paint" not in deps, deps
        assert "pack" in deps and "geometry" in deps, deps

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

    def test_the_served_shell_names_potato_mode_when_scripting_is_off(self) -> None:
        """The dashboard IS the inlined bundle, so a reader without scripting
        otherwise sits on the boot line forever. Potato Mode is the same
        coverage as server-rendered HTML, and the shell has to name it."""
        shell = (REPO_ROOT / "src" / "recoverage" / "assets" / "index.html").read_text(
            encoding="utf-8"
        )
        assert "<noscript>" in shell
        assert 'href="/potato"' in shell

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

    def test_the_remembered_target_seeds_the_selection_before_the_list_lands(self) -> None:
        """`/data` and `/stats` must not wait a round trip behind `/api/targets`.

        The target id the server will pick is either in the URL or in
        `localStorage`, and both are readable before the shell mounts. Waiting
        for the list to say which target to load put a full request round trip
        between the first paint and the map on every plain reload, which is the
        visit `recoverage serve` is pointed at. The remembered id is validated
        against the list either way, and the validation below already replaced a
        remembered id the server no longer serves, so a stale entry costs the
        404 it costs today.
        """
        app = _web("App.tsx")
        seeded = re.search(
            r"const \[target, setTarget\] = useState<string>\(\s*\(\) => (.*?),\s*\)",
            app,
            re.DOTALL,
        )
        assert seeded is not None, "the target state is no longer a lazy initializer"
        assert 'params.get("target")' in seeded.group(1), "the URL no longer seeds the selection"
        assert "readStored(TARGET_KEY)" in seeded.group(1), (
            "the remembered target is not read until the target list answers"
        )

    def test_a_superseded_load_clears_the_previous_targets_error(self) -> None:
        """Seeding from a remembered id can name a target the server has dropped.

        The effect re-runs on every load, and the previous load's refusal is
        about a document nobody is asking for any more: left up, the red line
        for a target that was deleted yesterday sits over the real target's map
        while it loads.
        """
        coverage = _web("hooks/useCoverage.ts")
        end = coverage.index("void load(section, control.signal);")
        start = coverage.rindex("useEffect(", 0, end)
        assert "setLoadError(null)" in coverage[start:end], (
            "a new load keeps the error of the one it replaced"
        )


class TestSpaTargetScopedState:
    """Nothing a target's payloads put in state outlives that target.

    A target switch replaces every document behind the dashboard, so the
    previous target's cells, paths, search index and stats are answers to a
    question about a different binary: the map paints one target's blocks
    under another's addresses and the code pane fetches from the previous
    target's `sourceRoot`. `reload` drops the same state for a rebuild, and a
    target switch reaches neither, so the target is the invalidation signal.
    Browser-observable behaviour lives in `tests/test_playwright.py`; these pin
    the wiring Python cannot otherwise see.
    """

    def test_a_target_switch_clears_the_accumulated_payloads(self) -> None:
        coverage = _web("hooks/useCoverage.ts")
        effect = coverage.index("shownTarget.current === target")
        effect = coverage.index("}, [target]);", effect)
        block = coverage[coverage.index("useEffect(", effect - 400) : effect]
        for reset in (
            "setSections({})",
            "setSearchIndex({})",
            "setPaths({})",
            "setStats(null)",
            "setStatsError(null)",
            "setCellError(null)",
            "indexed.current = null",
        ):
            assert reset in block, f"a target switch keeps {reset} out of its own clear"

    def test_the_clear_runs_before_the_request_the_switch_starts(self) -> None:
        """A fast response merged into state the clear then emptied is a
        dashboard that never fills in, so the clear is declared first."""
        coverage = _web("hooks/useCoverage.ts")
        assert coverage.index("shownTarget.current === target") < coverage.index(
            "void load(section, control.signal);"
        )

    def test_the_clear_aborts_the_previous_target_cell_fetches(self) -> None:
        """They resolve into the clear, and each abandoned section kept a
        multi-megabyte /data response downloading to a `merge` nothing reads."""
        coverage = _web("hooks/useCoverage.ts")
        start = coverage.index("shownTarget.current === target")
        end = coverage.index("}, [target]);", start)
        assert "control.abort();" in coverage[start:end]
        assert "inflight.current.clear();" in coverage[start:end]

    def test_a_deferred_jump_does_not_outlive_its_target(self) -> None:
        """The marker is a bare address, and the retry effect keys on
        `coverage.sections`, which a target switch replaces: a marker left
        behind resolved against the new target's rows."""
        app = _web("App.tsx")
        clear = app.index("deferredJump.current = null;\n  }, [target]);")
        assert clear < app.index("}, [coverage.sections, jumpToAddress]);")


class TestSpaJumpAndSearch:
    """The search set and the jump must agree on what a cell stores.

    `.text` cells hold the function's name (or a VA spelling); the search index
    is keyed by name and carries the VA. The dimming pass compares against both,
    and Enter jumps to the first matched name.
    """

    def test_matched_set_carries_names_and_va_spellings(self) -> None:
        app = _web("App.tsx")
        # The set is seeded with every matched NAME and then extended with that
        # name's VA spelling, so a `.text` cell holding either one dims. The
        # generic is the names' own: every member is a string, and a numeric arm
        # no call site can satisfy is a type wider than the set is.
        assert "new Set<string>(matchedNames)" in app
        assert "matched.add(String(va))" in app
        assert "coverage.searchIndex[name]?.va" in app

    def test_enter_jumps_to_a_matched_block_in_the_section_on_screen(self) -> None:
        app = _web("App.tsx")
        # The section wins over the target-wide set: the set's own order is
        # whatever order the index arrived in, and taking its first entry put
        # the jump in a sibling, switching tabs away from the map the reader
        # was looking at.
        assert "active?.cells?.findIndex(" in app
        assert 'matchedFns?.has(String(cell.functions?.[0] ?? ""))' in app
        assert "setSelectedIndex(local);" in app

    def test_enter_outside_the_section_lands_on_the_lowest_matched_address(self) -> None:
        app = _web("App.tsx")
        assert "[...matchedNames].toSorted((left, right) => vaOf(left) - vaOf(right))" in app
        assert "jumpToAddress(toVa(entry.va))" in app

    def test_the_status_line_says_when_the_section_holds_none_of_the_matches(self) -> None:
        """A target-wide count beside a wholly dimmed map is the confusion.

        Switching section keeps the query, so a reader who lands on a section
        the hits are not in reads a match count that says nothing about the grid
        under it.
        """
        app = _web("App.tsx")
        # The section name arrives from the coverage document, so it is
        # isolated before it joins the sentence (format.isolate).
        assert "none in ${isolate(section ??" in app
        hint = "searchHint(matchedNames.size, sectionMatches, active?.name ?? null, resultsOpen)"
        assert hint in app


class TestSpaBidirectionalText:
    """A value out of a coverage document is laid out in its own direction.

    Every name the dashboard shows comes from a PE image, so a target whose
    symbols are Arabic, Hebrew or a mix of the two with ASCII is a document the
    reader can have, not a hypothetical. In a page whose base direction is
    left-to-right the bidirectional algorithm then reorders such a value
    against the punctuation and the numbers around it, so a name reads in an
    order its author never wrote and a trailing address moves to the other side
    of the cell.

    Two mechanisms, and the difference is which one fits: `dir="auto"` on an
    element whose value stands alone (a metadata cell, a panel title) reads the
    value's own first strong character, while a value interpolated into a
    sentence of the page's own English needs the Unicode isolate pair, because
    no attribute on an ancestor can carve a run out of a text node.
    """

    def test_a_standalone_document_value_takes_its_own_direction(self) -> None:
        assert 'dir="auto"' in _web("components/ui/meta.tsx")
        assert 'id="panel-title"\n            dir="auto"' in _web("components/CoveragePanel.tsx")

    def test_isolate_wraps_a_value_in_the_unicode_isolate_pair(self) -> None:
        fmt = _web("lib/format.ts")
        assert 'const FSI = "\\u2068";' in fmt
        assert 'const PDI = "\\u2069";' in fmt
        body = fmt.split("export function isolate", 1)[1].split("\n}", 1)[0]
        assert "${FSI}" in body
        assert "${PDI}" in body

    def test_a_name_inside_a_sentence_is_isolated(self) -> None:
        """The map's cursor description, the panel's modal title, the pending
        and error lines, and the search status all read a document name inside
        a sentence the page owns."""
        assert "isolate(String(name))" in _web("components/CoverageMap.tsx")
        panel = _web("components/CoveragePanel.tsx")
        assert "const title = isolate(fn?.name ?? subject);" in panel
        assert "setModal({ title: `${heading}: ${title}`" in panel
        app = _web("App.tsx")
        assert "Loading ${isolate(active.name)}" in app
        assert "Could not load the {isolate(active.name)} map" in app

    def test_the_map_announces_the_isolated_name(self) -> None:
        """The `role="status"` paragraph is where a screen reader hears the
        block, so the same isolation the canvas tooltip needs applies to the
        announced text; both read `describe`."""
        map_ts = _web("components/CoverageMap.tsx")
        assert "isolate(section.name)} coverage map" in map_ts


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
            srv._clear_auth_failures(WSGI_PEER)
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

    def test_resolved_targets_are_not_published_under_a_superseded_snapshot(
        self, project: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """A rebuild that commits mid-read must not be answered from a stale list.

        The memo is keyed on the coverage snapshot AND filed under that key, so
        the token has to be taken before the read it describes and re-checked at
        publish.  Taken after the read, it names the build that landed during
        it while the list is built from the previous one: a target added by that
        build is then missing from /api/targets, the dropdown and Potato Mode
        for the rest of its life, because the invalidation that would have
        cleared the entry has already run.
        """
        import recoverage.server as srv

        write_coverage(project / "db", "FROMDB", {".text": _cell_section(["exact"])})
        monkeypatch.setenv("RECOVERAGE_DB", str(project / "db"))
        clear_target_cache()

        tokens = iter([(1, 1), (2, 2)])
        monkeypatch.setattr(srv, "_snapshot_db_mtime", lambda: next(tokens))

        assert [t["id"] for t in srv.resolve_targets()] == ["FROMDB"]
        assert srv._RESOLVED_TARGETS_CACHE is None, (
            "the list was filed under the fingerprint of the build that "
            "superseded the one it was read from"
        )

    def test_resolved_targets_publish_when_the_snapshot_holds_still(
        self, project: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """The re-check must not cost the memo its whole point.

        A rebuild that does not land during the read is the ordinary case, and
        there the entry is published and the next call is served from it.
        """
        import recoverage.server as srv

        write_coverage(project / "db", "FROMDB", {".text": _cell_section(["exact"])})
        monkeypatch.setenv("RECOVERAGE_DB", str(project / "db"))
        clear_target_cache()

        calls: list[int] = []

        def stable() -> tuple[int, int]:
            calls.append(1)
            return (7, 7)

        monkeypatch.setattr(srv, "_snapshot_db_mtime", stable)

        assert [t["id"] for t in srv.resolve_targets()] == ["FROMDB"]
        assert srv._RESOLVED_TARGETS_CACHE is not None
        reads = len(calls)
        assert [t["id"] for t in srv.resolve_targets()] == ["FROMDB"]
        # One more read, for the key: the second call is served from the entry
        # the first published, it does not merge the list again.
        assert len(calls) == reads + 1

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


class TestSpaDocumentPathsArePercentEncoded:
    """A document-supplied path must be encoded before it becomes a URL.

    ``paths.sourceRoot`` and ``paths.originalDll`` arrive raw from a coverage
    document and go straight into a ``fetch`` and an ``href``.  ``sameOriginPath``
    answers a question about ORIGIN and hands the value back untouched, so every
    character a URL treats as structure still means structure: a
    ``paths.sourceRoot`` of ``src/a#b`` reached the browser as
    ``src/a#b/main.c``, the fragment was resolved away, and the request went to
    ``/src/a``.  The same ``#`` inside a file name was already encoded to
    ``%23``, which is the asymmetry these cases pin.

    Executed through bun against the shipped TypeScript, so the assertion is the
    URL a browser resolves rather than the string the helper happened to build.
    """

    #: (sourceRoot, file, expected pathname + search after resolution).
    CASES: ClassVar[list[tuple[str, str, str]]] = [
        ("src/FAKEDLL", "main.c", "/src/FAKEDLL/main.c"),
        ("/src/FAKEDLL", "main.c", "/src/FAKEDLL/main.c"),
        # The failing inputs: a fragment, a query and a bare percent sign in the
        # ROOT, each of which the browser reads as structure rather than as a
        # character of the path.  The same characters in the file half already
        # survived, which is what made the two halves disagree.
        ("src/a#b", "main.c", "/src/a%23b/main.c"),
        ("src/a?b", "main.c", "/src/a%3Fb/main.c"),
        ("src/100%", "main.c", "/src/100%25/main.c"),
        ("src/a#b", "a#b/c d.c", "/src/a%23b/a%23b/c%20d.c"),
        # Non-ASCII and spaces: encoded, and still resolving to the same path the
        # filesystem holds.
        ("src/café", "main.c", "/src/caf%C3%A9/main.c"),
        ("src/my dir", "main.c", "/src/my%20dir/main.c"),
    ]

    #: (document originalDll, target, expected fetch pathname).
    DLL_CASES: ClassVar[list[tuple[str | None, str, str]]] = [
        (None, "FAKEDLL", "/original/FAKEDLL.dll"),
        ("", "FAKEDLL", "/original/FAKEDLL.dll"),
        ("/original/a#b.dll", "FAKEDLL", "/original/a%23b.dll"),
        ("/original/café.dll", "FAKEDLL", "/original/caf%C3%A9.dll"),
        # The guard still owns the origin: an off-origin value is not encoded
        # into a request, it falls back to the target's own binary.
        ("//evil.example/x.dll", "FAKEDLL", "/original/FAKEDLL.dll"),
        ("https://evil.example/x.dll", "FAKEDLL", "/original/FAKEDLL.dll"),
    ]

    def test_document_paths_are_encoded_into_the_url(self) -> None:
        bun = shutil.which("bun")
        if bun is None:
            pytest.skip("bun not on PATH")

        driver = (
            "import { sourceFileUrl } from "
            + json.dumps(str(WEB_APP / "lib" / "format.ts"))
            + ";\n"
            "import { originalDllPath } from "
            + json.dumps(str(WEB_APP / "hooks" / "useOriginalBinary.ts"))
            + ";\n"
            "const payload = JSON.parse(await Bun.file(process.argv[2]).text());\n"
            "const BASE = 'http://dashboard.invalid/';\n"
            "const resolve = (u) => { const p = new URL(u, BASE); "
            "return p.pathname + p.search; };\n"
            "console.log(JSON.stringify([\n"
            "  ...payload.source.map(([root, file]) => resolve(sourceFileUrl(root, file))),\n"
            "  ...payload.dll.map(([doc, target]) => resolve(originalDllPath(doc, target))),\n"
            "]));\n"
        )
        payload = {"source": self.CASES, "dll": self.DLL_CASES}
        with tempfile.TemporaryDirectory() as tmp:
            script = Path(tmp) / "paths.ts"
            script.write_text(driver, encoding="utf-8")
            cases = Path(tmp) / "cases.json"
            cases.write_text(json.dumps(payload), encoding="utf-8")
            proc = subprocess.run(
                [bun, "run", str(script), str(cases)],
                capture_output=True,
                text=True,
                timeout=60,
                check=False,
            )
        assert proc.returncode == 0, f"path harness failed to run: {proc.stderr}"
        expected = [want for _root, _file, want in self.CASES] + [
            want for _doc, _target, want in self.DLL_CASES
        ]
        assert json.loads(proc.stdout) == expected, (
            "a document path reached the URL unencoded, or the fallback was encoded twice"
        )

    def test_fallback_roots_are_spelled_raw(self) -> None:
        """Wiring: an already-encoded fallback would be encoded a second time.

        ``sourceFileUrl`` encodes both halves, so a fallback that pre-encodes the
        target id lands as ``my%2520target`` for a target spelled with a space.
        """
        app = _web("App.tsx")
        assert "`/src/${target}`" in app
        assert "encodeURIComponent(target)" not in app


class TestHljsThemeFollowsAppTokens:
    """The dashboard stylesheet reads the token layer and restates nothing.

    `web/app/index.css` holds the highlight.js rules and the base rules; every
    colour in it is a `var(--color-*)` the relumea token file declares. A hex
    typed here would survive a palette change as an orphan: the code pane keeps
    the old hue and nothing fails.
    """

    def test_every_referenced_token_is_declared(self) -> None:
        tokens = _web("system/tokens.css")
        for name in sorted(set(re.findall(r"var\((--color-[a-z0-9-]+)\)", _web("index.css")))):
            assert f"{name}:" in tokens, f"index.css reads {name}, which no token declares"

    def test_no_colour_is_spelled_as_a_literal(self) -> None:
        css = _web("index.css")
        literals = re.findall(r"#[0-9a-fA-F]{3,8}\b|\brgba?\(|\bhsla?\(", css)
        assert literals == [], f"index.css spells colours by hand: {literals}"


class TestMtimeNsToUtc:
    """The one mtime -> instant conversion, at the calendar and sign edges.

    ``/api/health``'s ``mtime_utc`` and Potato Mode's footer both render
    through it, from a value that came off the filesystem, so the arms worth
    pinning are the ones a normal rebuild never reaches: a stamp before the
    epoch, a stamp inside a leap day, a stamp on the 32-bit boundary, and the
    nanosecond remainder that decides whether the minute is the one the file
    landed in or the one it has not reached.
    """

    NS = 1_000_000_000

    @staticmethod
    def _ns(whole: str) -> int:
        """The epoch-second value of an ISO instant, as nanoseconds."""
        return int(datetime.fromisoformat(whole).timestamp()) * TestMtimeNsToUtc.NS

    def test_a_pre_epoch_stamp_names_the_second_before_it(self) -> None:
        """A document restored from an archive with a pre-1970 stamp.

        ``divmod`` floors, so a negative nanosecond count splits into a second
        and a POSITIVE remainder.  Truncating toward zero instead would put
        the remainder on the wrong side of the second and report an instant a
        whole second late.
        """
        assert mtime_ns_to_utc(-1) == datetime(1969, 12, 31, 23, 59, 59, 999999, tzinfo=UTC)
        assert mtime_ns_to_utc(-1_500_000_000) == datetime(
            1969, 12, 31, 23, 59, 58, 500000, tzinfo=UTC
        )
        # The exact instant, which is what the epoch float beside the ISO
        # stamp in /api/health is derived from.
        assert mtime_ns_to_utc(-1_500_000_000).timestamp() == -1.5

    @pytest.mark.parametrize(
        "instant",
        ["2024-02-29T00:00:00+00:00", "2024-02-29T23:59:59+00:00", "2000-02-29T12:00:00+00:00"],
    )
    def test_a_leap_day_stamp_names_that_day(self, instant: str) -> None:
        assert mtime_ns_to_utc(self._ns(instant)) == datetime.fromisoformat(instant)

    @pytest.mark.parametrize(
        "instant",
        ["2023-02-28T23:59:59+00:00", "2027-03-01T00:00:00+00:00", "2100-03-01T00:00:00+00:00"],
    )
    def test_a_non_leap_year_does_not_gain_a_february_29(self, instant: str) -> None:
        """1900 and 2100 are divisible by 4 and are not leap years, so a
        conversion that assumed four-year periods would land a day out on
        every March 1 in those years."""
        assert mtime_ns_to_utc(self._ns(instant)) == datetime.fromisoformat(instant)

    def test_a_stamp_past_the_32_bit_epoch_is_not_wrapped(self) -> None:
        """The 2038 boundary is where a 32-bit ``time_t`` reader rolls over to
        1906; nothing here is 32-bit, and the stamp past it must keep going."""
        assert mtime_ns_to_utc(2_147_483_648 * self.NS) == datetime(
            2038, 1, 19, 3, 14, 8, tzinfo=UTC
        )
        assert mtime_ns_to_utc(4_102_444_800 * self.NS) == datetime(2100, 1, 1, 0, 0, 0, tzinfo=UTC)

    def test_the_nanosecond_remainder_truncates(self) -> None:
        """999_999_999 ns is under a microsecond, so it renders as the same
        instant, while a remainder past a microsecond keeps it: the stamp
        never runs ahead of the data it describes."""
        assert mtime_ns_to_utc(1_700_000_000 * self.NS + 999).microsecond == 0
        assert mtime_ns_to_utc(1_700_000_000 * self.NS + 999_999_999).microsecond == 999999
        # The last nanosecond before a minute boundary stays in its own minute,
        # which is the arm Potato's footer renders to the minute.
        assert (
            mtime_ns_to_utc(self._ns("2023-11-14T22:14:50+00:00") - 1).strftime("%Y-%m-%d %H:%M")
            == "2023-11-14 22:14"
        )

    def test_a_stamp_the_clock_cannot_name_renders_the_extreme(self) -> None:
        """The clamp, both ends, and that it never raises: an mtime is
        filesystem input, and a freshness stamp is never worth a 500."""
        assert mtime_ns_to_utc(253_402_300_800 * self.NS) == datetime(
            9999, 12, 31, 23, 59, 59, tzinfo=UTC
        )
        assert mtime_ns_to_utc(-62_135_596_801 * self.NS) == datetime(1, 1, 1, 0, 0, 0, tzinfo=UTC)

    def test_the_result_is_aware_in_utc(self) -> None:
        """Aware, so it cannot be compared with a naive datetime built from a
        local wall clock, and in UTC, so a host's TZ cannot move the stamp."""
        stamp = mtime_ns_to_utc(1_700_000_000 * self.NS)
        assert stamp.tzinfo is not None
        assert stamp.utcoffset() == timedelta(0)


class TestSpaFirstPaint:
    """The shell's own frame: the theme it paints in, and the marks the map is
    read through.

    Each of these reached a running dashboard and was visible in a screenshot of
    it, and each is invisible to the compiler: a swatch with no box, a `text-*`
    name the merger reads as a colour, and a theme applied one frame after the
    document has already been painted.
    """

    @staticmethod
    def _shell() -> str:
        return (REPO_ROOT / "src" / "recoverage" / "assets" / "index.html").read_text(
            encoding="utf-8"
        )

    def test_the_shell_sets_the_theme_before_the_bundle_runs(self) -> None:
        """A pinned theme is applied before the first paint, not a frame later.

        The tokens resolve through `color-scheme`, which `data-theme` on <html>
        pins. The bundle sets the same attribute, but after the shell has
        painted in the OS theme, so a reader who pinned the other one saw the
        page flip. With nothing stored the attribute stays off and the OS
        decides, so the shell never asks the media query itself.
        """
        shell = self._shell()
        applied = shell.index("document.documentElement.dataset.theme = stored")
        assert applied < shell.index('id="root"'), (
            "the shell paints its first frame before the theme is applied"
        )
        assert shell.count('localStorage.getItem("recoverage_theme")') == 1
        assert "prefers-color-scheme" not in shell.split("<script>", 1)[1].split("</script>", 1)[0]
        assert '<meta name="color-scheme" content="light dark">' in shell
        assert 'const THEME_KEY = "recoverage_theme";' in _web("App.tsx"), (
            "the pre-paint attribute and the app no longer read the same setting"
        )

    @pytest.mark.parametrize("source", ["App.tsx", "components/StatsStrip.tsx"])
    def test_the_swatch_is_a_sized_box(self, source: str) -> None:
        """A fill on an unsized span is a colour nobody can see.

        The legend under the map and the filter pills both name a state beside
        the fill the map paints it in; a swatch with no size was a 0x0 box, so
        the key to the map printed the words and never the colours.
        """
        swatches = re.findall(r'"swatch ([^"]+)"', _web(source))
        assert swatches, f"{source} draws no swatch"
        for classes in swatches:
            assert "size-2.5" in classes.split(), classes

    @pytest.mark.parametrize(
        ("prefix", "group"),
        [
            ("text", "text"),
            ("radius", "radius"),
            ("shadow", "shadow"),
            ("leading", "leading"),
            ("tracking", "tracking"),
        ],
    )
    def test_every_token_scale_name_is_known_to_the_merger(self, prefix: str, group: str) -> None:
        """`twMerge` knows only Tailwind's default scale names.

        An unknown `text-*` reads as a text COLOUR, so a control's size lost to
        its colour and rendered at 16px. An unknown `rounded-*` joins no group,
        so an override kept both classes and the section tabs drew at the
        Button recipe's 9px radius instead of `rounded-chip`.
        """
        merger = _web("lib/cn.ts")
        listed = re.search(rf"^\s*{group}: \[([^\]]*)\]", merger, re.MULTILINE)
        assert listed is not None, f"cn.ts extends no {group} scale"
        declared = re.findall(rf"^\s*--{prefix}-([a-z]+):", _web("system/tokens.css"), re.MULTILINE)
        assert declared, f"the token file names no {prefix} scale"
        assert sorted(re.findall(r'"([a-z]+)"', listed.group(1))) == sorted(declared)
