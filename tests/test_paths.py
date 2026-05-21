"""Tests for recoverage._paths — db path resolution with rebrew-project.toml support."""

from __future__ import annotations

from pathlib import Path

import pytest

from recoverage._paths import _resolve_db_path


# ---------------------------------------------------------------------------


class TestResolveDbPath:
    def test_fallback_when_no_toml(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        """Falls back to <cwd>/db/coverage.db when no rebrew-project.toml is present."""
        monkeypatch.chdir(tmp_path)
        result = _resolve_db_path()
        assert result == tmp_path.resolve() / "db" / "coverage.db"

    def test_reads_db_dir_from_project_section(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Reads [project] db_dir and appends coverage.db to the resolved path."""
        monkeypatch.chdir(tmp_path)
        toml = tmp_path / "rebrew-project.toml"
        toml.write_text('[project]\ndb_dir = "mydb"\n', encoding="utf-8")
        result = _resolve_db_path()
        assert result == tmp_path.resolve() / "mydb" / "coverage.db"

    def test_relative_db_dir_resolved_against_cwd(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """db_dir is resolved relative to cwd (same as rebrew's config.py _resolve())."""
        monkeypatch.chdir(tmp_path)
        toml = tmp_path / "rebrew-project.toml"
        toml.write_text('[project]\ndb_dir = "subdir/data"\n', encoding="utf-8")
        result = _resolve_db_path()
        assert result == tmp_path.resolve() / "subdir" / "data" / "coverage.db"

    def test_missing_db_dir_key_uses_fallback(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """When rebrew-project.toml has a [project] section but no db_dir, fall back."""
        monkeypatch.chdir(tmp_path)
        toml = tmp_path / "rebrew-project.toml"
        toml.write_text('[project]\nname = "myproject"\n', encoding="utf-8")
        result = _resolve_db_path()
        assert result == tmp_path.resolve() / "db" / "coverage.db"

    def test_empty_db_dir_string_uses_fallback(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """An empty-string db_dir is treated the same as absent — fall back."""
        monkeypatch.chdir(tmp_path)
        toml = tmp_path / "rebrew-project.toml"
        toml.write_text('[project]\ndb_dir = ""\n', encoding="utf-8")
        result = _resolve_db_path()
        assert result == tmp_path.resolve() / "db" / "coverage.db"

    def test_invalid_toml_uses_fallback(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """A malformed rebrew-project.toml is silently ignored — fall back."""
        monkeypatch.chdir(tmp_path)
        toml = tmp_path / "rebrew-project.toml"
        toml.write_text("this is not valid toml }{", encoding="utf-8")
        result = _resolve_db_path()
        assert result == tmp_path.resolve() / "db" / "coverage.db"

    def test_no_project_section_uses_fallback(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """A TOML file without a [project] section falls back to the default."""
        monkeypatch.chdir(tmp_path)
        toml = tmp_path / "rebrew-project.toml"
        toml.write_text('[targets.foo]\nbinary = "foo.exe"\n', encoding="utf-8")
        result = _resolve_db_path()
        assert result == tmp_path.resolve() / "db" / "coverage.db"

    def test_result_ends_with_coverage_db(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Regardless of configuration, the filename is always coverage.db."""
        monkeypatch.chdir(tmp_path)
        toml = tmp_path / "rebrew-project.toml"
        toml.write_text('[project]\ndb_dir = "custom"\n', encoding="utf-8")
        result = _resolve_db_path()
        assert result.name == "coverage.db"

    def test_result_is_absolute(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        """Returned path is always absolute."""
        monkeypatch.chdir(tmp_path)
        assert _resolve_db_path().is_absolute()
