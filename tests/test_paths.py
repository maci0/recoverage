"""Tests for recoverage._paths — db path resolution with rebrew-project.toml support."""

from __future__ import annotations

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


class TestSqliteRoUri:
    def test_appends_mode_ro_query(self) -> None:
        uri = sqlite_ro_uri(Path("/some/proj/db/coverage.db"))
        assert uri.startswith("file:///")
        assert uri.endswith("?mode=ro")

    def test_percent_encodes_uri_reserved_characters(self) -> None:
        """?, #, and % in the path must be encoded or SQLite truncates/rewrites it."""
        p = Path("/proj 1#2?3%/db/coverage.db")
        path_part = urlparse(sqlite_ro_uri(p)).path
        assert unquote(path_part) == "/proj 1#2?3%/db/coverage.db"

    def test_relative_path_resolved_against_cwd(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.chdir(tmp_path)
        uri = sqlite_ro_uri(Path("db/coverage.db"))
        assert urlparse(uri).path.endswith("/db/coverage.db")

    def test_round_trip_open_db_in_hostile_directory(self, tmp_path: Path) -> None:
        """A real read-only open under a directory full of URI-reserved characters."""
        db_dir = tmp_path / "dir with # % ? & spaces"
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
