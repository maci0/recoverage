"""Tests for recoverage._paths — coverage directory resolution."""

from __future__ import annotations

import os
from pathlib import Path

import pytest

from recoverage._paths import _db_path

# ────────────────────────────────────────────────────────────────────────────────────────

# The memo key is (mtime_ns, size), so a rewrite only invalidates it when the
# mtime actually moves.  Two writes can land in the same timestamp tick on a
# filesystem with coarse mtime resolution, which would make the rewrite tests
# read the stale cache.  The bump must be a whole number of seconds so it also
# clears a 1 s or 2 s granularity tick, and larger than any plausible tick.
_MTIME_BUMP_NS = 2_000_000_000


def _force_distinct_mtime(path: Path) -> None:
    """Push *path*'s mtime past the previous value on coarse-timestamp filesystems."""
    bumped = path.stat().st_mtime_ns + _MTIME_BUMP_NS
    os.utime(path, ns=(bumped, bumped))


class TestResolveDbPath:
    def test_fallback_when_no_toml(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        """Falls back to <cwd>/db when no rebrew-project.toml is present."""
        monkeypatch.chdir(tmp_path)
        result = _db_path()
        assert result == tmp_path.resolve() / "db"

    def test_reads_db_dir_from_project_section(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Reads [project] db_dir and returns the resolved coverage directory."""
        monkeypatch.chdir(tmp_path)
        toml = tmp_path / "rebrew-project.toml"
        toml.write_text('[project]\ndb_dir = "mydb"\n', encoding="utf-8")
        result = _db_path()
        assert result == tmp_path.resolve() / "mydb"

    def test_relative_db_dir_resolved_against_cwd(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """db_dir is resolved relative to cwd (same as rebrew's config.py _resolve())."""
        monkeypatch.chdir(tmp_path)
        toml = tmp_path / "rebrew-project.toml"
        toml.write_text('[project]\ndb_dir = "subdir/data"\n', encoding="utf-8")
        result = _db_path()
        assert result == tmp_path.resolve() / "subdir" / "data"

    def test_missing_db_dir_key_uses_fallback(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """When rebrew-project.toml has a [project] section but no db_dir, fall back."""
        monkeypatch.chdir(tmp_path)
        toml = tmp_path / "rebrew-project.toml"
        toml.write_text('[project]\nname = "myproject"\n', encoding="utf-8")
        result = _db_path()
        assert result == tmp_path.resolve() / "db"

    def test_empty_db_dir_string_uses_fallback(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """An empty-string db_dir is treated the same as absent — fall back."""
        monkeypatch.chdir(tmp_path)
        toml = tmp_path / "rebrew-project.toml"
        toml.write_text('[project]\ndb_dir = ""\n', encoding="utf-8")
        result = _db_path()
        assert result == tmp_path.resolve() / "db"

    def test_invalid_toml_is_an_error(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """A present file that is not valid TOML must not select another database."""
        from rebrew.workspace import WorkspaceConfigError

        monkeypatch.chdir(tmp_path)
        toml = tmp_path / "rebrew-project.toml"
        toml.write_text("this is not valid toml }{", encoding="utf-8")
        with pytest.raises(WorkspaceConfigError):
            _db_path()

    def test_request_refuses_invalid_project_file(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """A request must not open a fallback database when the project file is broken."""
        import json

        from conftest import decode_body, wsgi_get

        monkeypatch.chdir(tmp_path)
        (tmp_path / "rebrew-project.toml").write_text("this is not valid toml }{", encoding="utf-8")
        status, headers, body = wsgi_get("/api/health")
        assert status.startswith("503")
        payload = json.loads(decode_body(body, headers))
        assert payload["error"] == "Database unavailable"
        assert payload["code"] == "db_unavailable"
        assert b"Traceback" not in body

    def test_explicit_db_still_serves_when_the_project_file_is_broken(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """RECOVERAGE_DB is applied before the project file is read."""
        from conftest import wsgi_get

        db = Path("db").resolve()
        monkeypatch.chdir(tmp_path)
        (tmp_path / "rebrew-project.toml").write_text("this is not valid toml }{", encoding="utf-8")
        monkeypatch.setenv("RECOVERAGE_DB", str(db))
        status, _, body = wsgi_get("/api/health")
        assert status.startswith("200"), body

    def test_no_project_section_uses_fallback(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """A TOML file without a [project] section falls back to the default."""
        monkeypatch.chdir(tmp_path)
        toml = tmp_path / "rebrew-project.toml"
        toml.write_text('[targets.foo]\nbinary = "foo.exe"\n', encoding="utf-8")
        result = _db_path()
        assert result == tmp_path.resolve() / "db"

    def test_result_names_the_db_dir(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        """Regardless of configuration, the last component is the db dir."""
        monkeypatch.chdir(tmp_path)
        toml = tmp_path / "rebrew-project.toml"
        toml.write_text('[project]\ndb_dir = "custom"\n', encoding="utf-8")
        result = _db_path()
        assert result.name == "custom"

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
        assert _db_path() == tmp_path.resolve() / "first"
        toml.write_text('[project]\ndb_dir = "second"\n', encoding="utf-8")
        _force_distinct_mtime(toml)
        assert _db_path() == tmp_path.resolve() / "second"

    def test_same_size_rewrite_is_picked_up(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """A byte-for-byte-same-length rewrite invalidates via the stat fingerprint."""
        monkeypatch.chdir(tmp_path)
        toml = tmp_path / "rebrew-project.toml"
        toml.write_text('[project]\ndb_dir = "aaaaaa"\n', encoding="utf-8")
        assert _db_path() == tmp_path.resolve() / "aaaaaa"
        toml.write_text('[project]\ndb_dir = "bbbbbb"\n', encoding="utf-8")
        _force_distinct_mtime(toml)
        assert _db_path() == tmp_path.resolve() / "bbbbbb"

    def test_deleted_config_falls_back(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Deleting the config after it was cached returns to the default path."""
        monkeypatch.chdir(tmp_path)
        toml = tmp_path / "rebrew-project.toml"
        toml.write_text('[project]\ndb_dir = "custom"\n', encoding="utf-8")
        assert _db_path() == tmp_path.resolve() / "custom"
        toml.unlink()
        assert _db_path() == tmp_path.resolve() / "db"

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
        assert _db_path() == tmp_path.resolve() / "one"
        monkeypatch.chdir(other)
        assert _db_path() == other.resolve() / "db"

    def test_env_override_beats_project_config(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """RECOVERAGE_DB lets a service run from outside the project root."""
        monkeypatch.delenv("RECOVERAGE_DB", raising=False)
        (tmp_path / "rebrew-project.toml").write_text(
            '[project]\ndb_dir = "one"\n', encoding="utf-8"
        )
        monkeypatch.chdir(tmp_path)
        monkeypatch.setenv("RECOVERAGE_DB", str(tmp_path / "elsewhere"))
        assert _db_path() == tmp_path / "elsewhere"
        # Unset again: the project resolution returns, with no stale memo.
        monkeypatch.delenv("RECOVERAGE_DB")
        assert _db_path() == tmp_path.resolve() / "one"
