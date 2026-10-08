"""Coverage documents: per-file incremental reload and the parse persisted across restarts.

Driven through ``server.coverage_snapshots``, the read every route goes
through.  A restart is ``documents._STATE`` back at ``None``, which is the one
piece of state a new process does not have; the cache directory is the
per-test ``$XDG_CACHE_HOME`` the conftest installs.
"""

from __future__ import annotations

import gc
import logging
import os
import threading
import time
import tomllib
from pathlib import Path
from typing import Any

import pytest
from coverage_fixture import cell, coverage_dir, write_coverage
from rebrew.coverage_toml import load_coverage_from

from recoverage import documents, metrics, server


def _sections(size: int) -> dict[str, dict[str, Any]]:
    return {
        ".text": {
            "va": 0x1000,
            "size": size,
            "fileOffset": 0x200,
            "unitBytes": 16,
            "columns": 8,
            "cells": [cell(0, 16, "exact"), cell(16, size, "none")],
        }
    }


@pytest.fixture
def db(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    directory = coverage_dir(tmp_path)
    monkeypatch.setenv("RECOVERAGE_DB", str(directory))
    monkeypatch.setattr(documents, "_STATE", None)
    metrics.CACHES.reset()
    write_coverage(directory, "GAME", _sections(64))
    write_coverage(directory, "TOOL", _sections(32))
    return directory


def _document_cache() -> dict[str, int]:
    return metrics.CACHES.snapshot().get(metrics.DOCUMENT_CACHE, {"hits": 0, "misses": 0})


def _restart(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(documents, "_STATE", None)
    metrics.CACHES.reset()


def _forbid_parse(monkeypatch: pytest.MonkeyPatch) -> None:
    def refuse(_text: str) -> dict[str, Any]:
        raise AssertionError("tomllib.loads ran on a cached document")

    monkeypatch.setattr(tomllib, "loads", refuse)


def test_snapshots_equal_rebrews_own_reader(db: Path) -> None:
    snaps = server.coverage_snapshots()
    for target in ("GAME", "TOOL"):
        assert snaps[target] == load_coverage_from(db, target)


def test_a_restart_reads_the_persisted_parse(db: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    first = server.coverage_snapshots()
    assert _document_cache() == {"hits": 0, "misses": 2}

    _restart(monkeypatch)
    _forbid_parse(monkeypatch)
    second = server.coverage_snapshots()

    assert _document_cache() == {"hits": 2, "misses": 0}
    assert second == first


def test_a_rebuild_reparses_only_the_document_it_rewrote(db: Path) -> None:
    before = server.coverage_snapshots()
    write_coverage(db, "GAME", _sections(128))
    after = server.coverage_snapshots()

    assert after is not before
    assert after["TOOL"] is before["TOOL"]
    assert after["GAME"].sections[".text"].size == 128
    assert _document_cache() == {"hits": 0, "misses": 3}


def test_an_unchanged_directory_returns_the_same_mapping(db: Path) -> None:
    assert server.coverage_snapshots() is server.coverage_snapshots()


def test_a_touch_over_the_same_bytes_keeps_the_snapshot(db: Path) -> None:
    before = server.coverage_snapshots()["GAME"]
    path = db / "coverage-GAME.toml"
    st = path.stat()
    os.utime(path, ns=(st.st_atime_ns, st.st_mtime_ns + 1_000_000_000))

    assert server.coverage_snapshots()["GAME"] is before
    assert _document_cache() == {"hits": 0, "misses": 2}


def test_a_rewritten_document_misses_its_stale_cache_entry(
    db: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    server.coverage_snapshots()
    write_coverage(db, "GAME", _sections(256))

    _restart(monkeypatch)
    snaps = server.coverage_snapshots()

    assert snaps["GAME"].sections[".text"].size == 256
    assert _document_cache() == {"hits": 1, "misses": 1}


def test_a_corrupt_cache_file_falls_back_to_the_parse(
    db: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    first = server.coverage_snapshots()
    root = documents.cache_dir()
    assert root is not None
    slots = sorted(root.glob("*.json"))
    assert len(slots) == 2
    for slot in slots:
        slot.write_bytes(b'{"format": 1, "sha256": ')

    _restart(monkeypatch)
    assert server.coverage_snapshots() == first
    assert _document_cache() == {"hits": 0, "misses": 2}


def test_a_cache_entry_rebrew_refuses_falls_back_to_the_document(
    db: Path, monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
) -> None:
    """A cache file stands in for the TOML and gets no more trust than it: one
    whose hash matches but whose content fails the schema is discarded, and the
    good document behind it is served rather than reported unreadable."""
    first = server.coverage_snapshots()
    root = documents.cache_dir()
    assert root is not None
    for slot in root.glob("*.json"):
        text = slot.read_text(encoding="utf-8")
        slot.write_text(text.replace('"version":1', '"version":99'), encoding="utf-8")

    _restart(monkeypatch)
    with caplog.at_level(logging.WARNING, logger="recoverage"):
        assert server.coverage_snapshots() == first
    assert caplog.text.count("discarding the cached parse") == 2
    assert _document_cache() == {"hits": 0, "misses": 2}

    # The fallback parse rewrote the slots, so the next start hits again.
    _restart(monkeypatch)
    _forbid_parse(monkeypatch)
    assert server.coverage_snapshots() == first
    assert _document_cache() == {"hits": 2, "misses": 0}


def test_an_unwritable_cache_still_serves_and_warns_once(
    db: Path,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    caplog: pytest.LogCaptureFixture,
) -> None:
    blocker = tmp_path / "not-a-dir"
    blocker.write_text("", encoding="utf-8")
    monkeypatch.setenv("XDG_CACHE_HOME", str(blocker))
    monkeypatch.setattr(documents, "_WRITE_WARNED", False)

    with caplog.at_level(logging.WARNING, logger="recoverage"):
        snaps = server.coverage_snapshots()

    assert sorted(snaps) == ["GAME", "TOOL"]
    assert caplog.text.count("coverage cache: cannot write") == 1


def test_a_relative_xdg_cache_home_is_ignored(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("XDG_CACHE_HOME", "relative/cache")
    assert documents.cache_dir() == Path.home() / ".cache" / "recoverage" / "documents"


def test_the_cache_keeps_the_most_recently_used_slots(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """One slot per document path, so served directories cannot grow it forever,
    and a temp file a killed write left behind is swept with them."""
    monkeypatch.setattr(documents, "_CACHE_MAX_SLOTS", 2)
    monkeypatch.setattr(documents, "_STATE", None)
    metrics.CACHES.reset()
    root = documents.cache_dir()
    assert root is not None
    root.mkdir(parents=True)
    leftover = root / "killed-write.tmp"
    leftover.write_bytes(b"{")
    old = time.time() - documents._STALE_TMP_SECONDS - 60
    os.utime(leftover, (old, old))
    fresh = root / "in-progress.tmp"
    fresh.write_bytes(b"{")

    directories = [coverage_dir(tmp_path, name) for name in ("a", "b", "c")]
    for directory in directories:
        write_coverage(directory, "GAME", _sections(64))
        monkeypatch.setenv("RECOVERAGE_DB", str(directory))
        server.coverage_snapshots()
        # Age every slot already written, so recency is ordered even on a
        # filesystem whose mtime is coarser than this loop.
        for slot in root.glob("*.json"):
            st = slot.stat()
            os.utime(slot, ns=(st.st_atime_ns, st.st_mtime_ns - 10**9))

    assert len(list(root.glob("*.json"))) == 2
    assert not leftover.exists()
    assert fresh.exists()

    # The oldest directory's slot is the one that went: its next start parses.
    _restart(monkeypatch)
    monkeypatch.setenv("RECOVERAGE_DB", str(directories[0]))
    server.coverage_snapshots()
    assert _document_cache() == {"hits": 0, "misses": 1}


def test_a_cold_herd_parses_each_document_once(db: Path) -> None:
    """The post-rebuild refetch herd must not parse one document per thread."""
    threads = 8
    barrier = threading.Barrier(threads)
    results: list[dict[str, Any]] = []

    def read() -> None:
        barrier.wait()
        results.append(dict(server.coverage_snapshots()))

    workers = [threading.Thread(target=read) for _ in range(threads)]
    for worker in workers:
        worker.start()
    for worker in workers:
        worker.join(timeout=30)

    assert len(results) == threads
    assert _document_cache() == {"hits": 0, "misses": 2}


@pytest.mark.parametrize("enabled", [True, False])
def test_a_load_leaves_the_collector_as_it_found_it(db: Path, enabled: bool) -> None:
    was = gc.isenabled()
    try:
        if not enabled:
            gc.disable()
        server.coverage_snapshots()
        assert gc.isenabled() is enabled
    finally:
        if was:
            gc.enable()


def test_an_unreadable_document_is_logged_on_one_line(
    db: Path, caplog: pytest.LogCaptureFixture
) -> None:
    """The filename and the parse error are document input: a line break in
    either must not split the warning into a forged second record."""
    try:
        broken = db / "coverage-a\nb\u2028c.toml"
        broken.write_text("version = [\n", encoding="utf-8")
    except (OSError, ValueError):
        pytest.skip("the filesystem cannot name a file with a line break")

    with caplog.at_level(logging.WARNING, logger="recoverage"):
        snaps = server.coverage_snapshots()

    assert sorted(snaps) == ["GAME", "TOOL"]
    [record] = [r for r in caplog.records if "skipping" in r.getMessage()]
    message = record.getMessage()
    assert "\n" not in message
    assert "\u2028" not in message


def test_an_unreadable_document_is_reported_by_name_and_reason(db: Path) -> None:
    """The skipped document is named with its error, in the same state the
    readable ones come from, and the reason drops the absolute path."""
    (db / "coverage-BROKEN.toml").write_text("version = [\n", encoding="utf-8")

    assert sorted(documents.load_all(db)) == ["GAME", "TOOL"]
    [(name, target, reason)] = documents.unreadable(db)
    assert (name, target) == ("coverage-BROKEN.toml", "BROKEN")
    assert reason.startswith("malformed TOML (")
    assert str(db) not in reason

    (db / "coverage-BROKEN.toml").unlink()
    assert documents.unreadable(db) == ()
