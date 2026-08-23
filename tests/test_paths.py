"""Tests for recoverage._paths — db path resolution with rebrew-project.toml support."""

from __future__ import annotations

import os
import sqlite3
from pathlib import Path
from urllib.parse import unquote, urlparse

import pytest

from recoverage._paths import _db_path, sqlite_ro_uri

# ---------------------------------------------------------------------------


class TestResolveDbPath:
    def test_fallback_when_no_toml(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        """Falls back to <cwd>/db/coverage.db when no rebrew-project.toml is present."""
        monkeypatch.chdir(tmp_path)
        result = _db_path()
        assert result == tmp_path.resolve() / "db" / "coverage.db"

    def test_reads_db_dir_from_project_section(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Reads [project] db_dir and appends coverage.db to the resolved path."""
        monkeypatch.chdir(tmp_path)
        toml = tmp_path / "rebrew-project.toml"
        toml.write_text('[project]\ndb_dir = "mydb"\n', encoding="utf-8")
        result = _db_path()
        assert result == tmp_path.resolve() / "mydb" / "coverage.db"

    def test_relative_db_dir_resolved_against_cwd(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """db_dir is resolved relative to cwd (same as rebrew's config.py _resolve())."""
        monkeypatch.chdir(tmp_path)
        toml = tmp_path / "rebrew-project.toml"
        toml.write_text('[project]\ndb_dir = "subdir/data"\n', encoding="utf-8")
        result = _db_path()
        assert result == tmp_path.resolve() / "subdir" / "data" / "coverage.db"

    def test_missing_db_dir_key_uses_fallback(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """When rebrew-project.toml has a [project] section but no db_dir, fall back."""
        monkeypatch.chdir(tmp_path)
        toml = tmp_path / "rebrew-project.toml"
        toml.write_text('[project]\nname = "myproject"\n', encoding="utf-8")
        result = _db_path()
        assert result == tmp_path.resolve() / "db" / "coverage.db"

    def test_empty_db_dir_string_uses_fallback(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """An empty-string db_dir is treated the same as absent — fall back."""
        monkeypatch.chdir(tmp_path)
        toml = tmp_path / "rebrew-project.toml"
        toml.write_text('[project]\ndb_dir = ""\n', encoding="utf-8")
        result = _db_path()
        assert result == tmp_path.resolve() / "db" / "coverage.db"

    def test_invalid_toml_uses_fallback(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """A malformed rebrew-project.toml is silently ignored — fall back."""
        monkeypatch.chdir(tmp_path)
        toml = tmp_path / "rebrew-project.toml"
        toml.write_text("this is not valid toml }{", encoding="utf-8")
        result = _db_path()
        assert result == tmp_path.resolve() / "db" / "coverage.db"

    def test_no_project_section_uses_fallback(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """A TOML file without a [project] section falls back to the default."""
        monkeypatch.chdir(tmp_path)
        toml = tmp_path / "rebrew-project.toml"
        toml.write_text('[targets.foo]\nbinary = "foo.exe"\n', encoding="utf-8")
        result = _db_path()
        assert result == tmp_path.resolve() / "db" / "coverage.db"

    def test_result_ends_with_coverage_db(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Regardless of configuration, the filename is always coverage.db."""
        monkeypatch.chdir(tmp_path)
        toml = tmp_path / "rebrew-project.toml"
        toml.write_text('[project]\ndb_dir = "custom"\n', encoding="utf-8")
        result = _db_path()
        assert result.name == "coverage.db"

    def test_result_is_absolute(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        """Returned path is always absolute."""
        monkeypatch.chdir(tmp_path)
        assert _db_path().is_absolute()


class TestDbPathMemoInvalidation:
    """_db_path() memoizes resolution; a changed config must still take effect."""

    def test_rewritten_config_is_picked_up(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Rewriting rebrew-project.toml re-points the DB path on the next call."""
        monkeypatch.chdir(tmp_path)
        toml = tmp_path / "rebrew-project.toml"
        toml.write_text('[project]\ndb_dir = "first"\n', encoding="utf-8")
        assert _db_path() == tmp_path.resolve() / "first" / "coverage.db"
        toml.write_text('[project]\ndb_dir = "second"\n', encoding="utf-8")
        assert _db_path() == tmp_path.resolve() / "second" / "coverage.db"

    def test_same_size_rewrite_is_picked_up(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """A byte-for-byte-same-length rewrite invalidates via the stat fingerprint."""
        monkeypatch.chdir(tmp_path)
        toml = tmp_path / "rebrew-project.toml"
        toml.write_text('[project]\ndb_dir = "aaaaaa"\n', encoding="utf-8")
        assert _db_path() == tmp_path.resolve() / "aaaaaa" / "coverage.db"
        toml.write_text('[project]\ndb_dir = "bbbbbb"\n', encoding="utf-8")
        # Force a fresh mtime even on coarse-timestamp filesystems.
        st = toml.stat()
        os.utime(toml, ns=(st.st_mtime_ns + 1_000_000, st.st_mtime_ns + 1_000_000))
        assert _db_path() == tmp_path.resolve() / "bbbbbb" / "coverage.db"

    def test_deleted_config_falls_back(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Deleting the config after it was cached returns to the default path."""
        monkeypatch.chdir(tmp_path)
        toml = tmp_path / "rebrew-project.toml"
        toml.write_text('[project]\ndb_dir = "custom"\n', encoding="utf-8")
        assert _db_path() == tmp_path.resolve() / "custom" / "coverage.db"
        toml.unlink()
        assert _db_path() == tmp_path.resolve() / "db" / "coverage.db"

    def test_cwd_change_switches_resolution(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Two directories resolve independently despite the shared memo."""
        other = tmp_path / "other"
        other.mkdir()
        (tmp_path / "rebrew-project.toml").write_text(
            '[project]\ndb_dir = "one"\n', encoding="utf-8"
        )
        monkeypatch.chdir(tmp_path)
        assert _db_path() == tmp_path.resolve() / "one" / "coverage.db"
        monkeypatch.chdir(other)
        assert _db_path() == other.resolve() / "db" / "coverage.db"


class TestSqliteRoUri:
    def test_appends_mode_ro_query(self) -> None:
        uri = sqlite_ro_uri(Path("/some/proj/db/coverage.db"))
        assert uri.startswith("file:///")
        assert uri.endswith("?mode=ro")

    def test_percent_encodes_uri_reserved_characters(self) -> None:
        """?, #, and % in the path must be encoded or SQLite truncates/rewrites it."""
        # A bare "/proj ..." is relative on Windows (no drive), so compare
        # suffix-wise instead of assuming one absolute spelling per platform.
        p = Path("/proj 1#2?3%/db/coverage.db")
        path_part = urlparse(sqlite_ro_uri(p)).path
        assert unquote(path_part).endswith("/proj 1#2?3%/db/coverage.db")

    def test_relative_path_resolved_against_cwd(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.chdir(tmp_path)
        uri = sqlite_ro_uri(Path("db/coverage.db"))
        assert urlparse(uri).path.endswith("/db/coverage.db")

    def test_round_trip_open_db_in_hostile_directory(self, tmp_path: Path) -> None:
        """A real read-only open under a directory full of URI-reserved characters.

        The name must also be a legal Windows filename (no ``?``), so the
        query-separator class is covered by the percent-encode unit test
        above instead; #, %, &, = and + exercise escaping in a real open.
        """
        db_dir = tmp_path / "dir with # % & = + spaces"
        db_dir.mkdir()
        db = db_dir / "coverage.db"
        conn = sqlite3.connect(db)
        conn.execute("CREATE TABLE t (v TEXT)")
        conn.execute("INSERT INTO t VALUES ('ok')")
        conn.commit()
        conn.close()

        ro = sqlite3.connect(sqlite_ro_uri(db), uri=True)
        try:
            assert ro.execute("SELECT v FROM t").fetchone()[0] == "ok"
            with pytest.raises(sqlite3.OperationalError):
                ro.execute("INSERT INTO t VALUES ('no')")
        finally:
            ro.close()
