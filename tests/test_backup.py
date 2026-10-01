"""Tests for recoverage.backup — verified backup and restore of the documents.

The properties pinned here are the ones a backup that is only ever written
would not have, and they are the ones an incident needs:

* a backup is READ BACK before it reports success, and a member whose bytes
  were altered after the fact is refused by name (the check that makes a backup
  a backup rather than a hypothesis);
* a restore writes nothing until every member has been verified, so a corrupt
  archive cannot leave the coverage directory half-overwritten;
* a restore refuses to roll coverage back over a document that has changed
  since, because the history and verify arrays it would discard are the ones
  `regen` cannot rebuild;
* an empty coverage directory produces an alert, not an empty archive that
  restores to an empty dashboard;
* a member name in the manifest cannot write outside the directory the restore
  was pointed at.
"""

from __future__ import annotations

import io
import json
import tarfile
from pathlib import Path

import pytest
from coverage_fixture import build_synthetic_coverage, write_coverage
from typer.testing import CliRunner

from recoverage import backup
from recoverage.backup import (
    FORMAT_VERSION,
    MANIFEST_NAME,
    BackupError,
    backup_dir_from_env,
    default_backup_dir,
    restore_backup,
    verify_backup,
    write_backup,
)
from recoverage.cli import app

runner = CliRunner()


@pytest.fixture
def db(tmp_path: Path) -> Path:
    """The coverage DIRECTORY holding the shared synthetic document.

    ``build_synthetic_coverage`` returns the document it wrote; the parent is
    what this module backs up, and the tests below say ``db`` when they mean
    the directory so a reader is not counting on the fixture's return value.
    """
    return build_synthetic_coverage(tmp_path / "db").parent


@pytest.fixture
def archive(db: Path, tmp_path: Path) -> Path:
    """A verified archive of *db*, written outside it."""
    path = tmp_path / "backups" / "snapshot.tar"
    write_backup(db, path)
    return path


class TestWriteBackup:
    """A backup that reports success has been read back."""

    def test_round_trips_every_document(self, db: Path, tmp_path: Path) -> None:
        info = write_backup(db, tmp_path / "snap.tar")
        assert [name for name, _s, _d in info.members] == [
            p.name for p in sorted(db.glob("coverage-*.toml"))
        ]

    def test_the_archive_holds_the_document_bytes(self, db: Path, tmp_path: Path) -> None:
        path = tmp_path / "snap.tar"
        write_backup(db, path)
        with tarfile.open(path) as tar:
            names = set(tar.getnames())
            assert MANIFEST_NAME in names
            for document in sorted(db.glob("coverage-*.toml")):
                assert document.name in names
                handle = tar.extractfile(document.name)
                assert handle is not None
                assert handle.read() == document.read_bytes()

    def test_reports_the_members_and_their_digests(self, db: Path, tmp_path: Path) -> None:
        info = write_backup(db, tmp_path / "snap.tar")
        name, size, digest = info.members[0]
        document = db / name
        assert size == document.stat().st_size
        assert len(digest) == 64
        assert info.total_bytes == size

    def test_two_targets_are_both_covered(self, tmp_path: Path) -> None:
        """A backup is a directory-wide copy, not one target's document.

        The failure this pins is a job written against one target that quietly
        leaves the rest of the directory uncovered when a project grows one.
        """
        directory = tmp_path / "db"
        build_synthetic_coverage(directory)
        write_coverage(directory, "OTHER", {}, functions=[])
        info = write_backup(directory, tmp_path / "snap.tar")
        assert sorted(name for name, _s, _d in info.members) == [
            "coverage-FAKEDLL.toml",
            "coverage-OTHER.toml",
        ]

    def test_an_empty_coverage_directory_is_a_refusal(self, tmp_path: Path) -> None:
        """An empty archive verifies, and restoring it empties the dashboard.

        A job that wrote one would report success on the run where the build
        failed, and the first reader to need it would take the coverage
        directory with it.
        """
        empty = tmp_path / "db"
        empty.mkdir()
        with pytest.raises(BackupError, match="nothing to back up"):
            write_backup(empty, tmp_path / "snap.tar")

    def test_a_missing_directory_is_a_refusal(self, tmp_path: Path) -> None:
        with pytest.raises(BackupError, match="nothing to back up"):
            write_backup(tmp_path / "absent", tmp_path / "snap.tar")

    def test_the_default_destination_is_outside_the_coverage_directory(
        self, db: Path, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
    ) -> None:
        """A backup inside the directory it backs up backs itself up next time."""
        monkeypatch.setenv("RECOVERAGE_BACKUP_DIR", str(tmp_path / "out"))
        info = write_backup(db)
        assert info.path.parent == tmp_path / "out"
        assert db not in info.path.parents

    def test_a_directory_destination_gets_the_stamped_name(self, db: Path, tmp_path: Path) -> None:
        info = write_backup(db, tmp_path)
        assert info.path.parent == tmp_path
        assert info.path.name.startswith("coverage-")
        assert info.path.suffix == ".tar"

    def test_two_backups_of_the_same_bytes_are_identical(self, db: Path, tmp_path: Path) -> None:
        """The member mtime is pinned, so a diff of two backups compares coverage."""
        first = tmp_path / "a.tar"
        second = tmp_path / "b.tar"
        write_backup(db, first)
        write_backup(db, second)
        # `created` differs by design; the members do not.
        with tarfile.open(first) as a, tarfile.open(second) as b:
            for member in a.getnames():
                if member == MANIFEST_NAME:
                    continue
                assert a.extractfile(member).read() == b.extractfile(member).read()  # type: ignore[union-attr]

    def test_no_temp_file_survives_a_successful_write(self, db: Path, tmp_path: Path) -> None:
        write_backup(db, tmp_path / "snap.tar")
        assert sorted(p.name for p in tmp_path.iterdir()) == ["db", "snap.tar"]


class TestVerifyBackup:
    """Restore runs this first, so every refusal is made before a write."""

    def test_a_good_archive_describes_itself(self, archive: Path) -> None:
        info = verify_backup(archive)
        assert info.path == archive
        assert info.created
        assert info.members[0][0].endswith(".toml")

    def test_a_tampered_member_is_refused_by_name(self, archive: Path, tmp_path: Path) -> None:
        """The member is named, so a corrupt archive is one file, not "corrupt"."""
        tampered = tmp_path / "tampered.tar"
        with tarfile.open(archive) as source, tarfile.open(tampered, "w") as sink:
            for member in source.getmembers():
                data = source.extractfile(member).read()  # type: ignore[union-attr]
                if member.name.endswith(".toml"):
                    data = data.replace(b"FAKEDLL", b"TAMPERD")
                info = tarfile.TarInfo(member.name)
                info.size = len(data)
                sink.addfile(info, io.BytesIO(data))
        with pytest.raises(BackupError, match="does not match its manifest digest"):
            verify_backup(tampered)

    def test_a_truncated_member_is_refused(self, archive: Path, tmp_path: Path) -> None:
        """The size check lands before the digest one, and says the same thing.

        A member shortened by a truncated write is the failure a size field
        catches for free, and naming both halves in one message is what lets a
        reader tell a short write from a rewritten one.
        """
        truncated = tmp_path / "truncated.tar"
        with tarfile.open(archive) as source, tarfile.open(truncated, "w") as sink:
            for member in source.getmembers():
                data = source.extractfile(member).read()  # type: ignore[union-attr]
                if member.name.endswith(".toml"):
                    data = data[: len(data) // 2]
                info = tarfile.TarInfo(member.name)
                info.size = len(data)
                sink.addfile(info, io.BytesIO(data))
        with pytest.raises(BackupError, match="bytes, manifest says"):
            verify_backup(truncated)

    def test_a_tar_that_is_not_a_backup_is_refused(self, tmp_path: Path) -> None:
        other = tmp_path / "other.tar"
        with tarfile.open(other, "w"):
            pass
        with pytest.raises(BackupError, match="not a recoverage backup"):
            verify_backup(other)

    def test_a_missing_archive_is_refused(self, tmp_path: Path) -> None:
        with pytest.raises(BackupError, match="not a readable backup"):
            verify_backup(tmp_path / "absent.tar")

    def test_another_format_version_is_refused(self, archive: Path, tmp_path: Path) -> None:
        """A restore must not extract a layout it does not know."""
        other = tmp_path / "v2.tar"
        with tarfile.open(archive) as source, tarfile.open(other, "w") as sink:
            for member in source.getmembers():
                data = source.extractfile(member).read()  # type: ignore[union-attr]
                if member.name == MANIFEST_NAME:
                    manifest = json.loads(data)
                    manifest["format"] = FORMAT_VERSION + 1
                    data = json.dumps(manifest).encode("utf-8")
                info = tarfile.TarInfo(member.name)
                info.size = len(data)
                sink.addfile(info, io.BytesIO(data))
        with pytest.raises(BackupError, match="is not version"):
            verify_backup(other)


class TestRestoreBackup:
    """The disaster path: the documents are gone, and then they are back."""

    def test_restores_every_document_after_the_directory_is_wiped(
        self, db: Path, archive: Path
    ) -> None:
        expected = {p.name: p.read_bytes() for p in db.glob("coverage-*.toml")}
        for document in db.glob("coverage-*.toml"):
            document.unlink()
        written = restore_backup(archive, db)
        assert sorted(p.name for p in written) == sorted(expected)
        for name, data in expected.items():
            assert (db / name).read_bytes() == data

    def test_restores_into_a_directory_that_does_not_exist(
        self, db: Path, archive: Path, tmp_path: Path
    ) -> None:
        fresh = tmp_path / "fresh"
        written = restore_backup(archive, fresh)
        assert written and written[0].parent == fresh

    def test_restoring_what_is_already_there_is_a_no_op(self, db: Path, archive: Path) -> None:
        before = {p.name: p.read_bytes() for p in db.glob("coverage-*.toml")}
        restore_backup(archive, db)
        assert {p.name: p.read_bytes() for p in db.glob("coverage-*.toml")} == before

    def test_a_document_that_has_moved_on_is_refused(self, db: Path, archive: Path) -> None:
        """The history and verify arrays the rollback would discard are gone for good."""
        document = next(db.glob("coverage-*.toml"))
        document.write_text(document.read_text() + "\n# a later regen\n", encoding="utf-8")
        with pytest.raises(BackupError, match="refusing to roll coverage back"):
            restore_backup(archive, db)

    def test_force_overrides_that_refusal_and_nothing_else(self, db: Path, archive: Path) -> None:
        expected = {p.name: p.read_bytes() for p in db.glob("coverage-*.toml")}
        document = next(db.glob("coverage-*.toml"))
        document.write_text(document.read_text() + "\n# a later regen\n", encoding="utf-8")
        restore_backup(archive, db, force=True)
        for name, data in expected.items():
            assert (db / name).read_bytes() == data

    def test_a_corrupt_archive_writes_nothing_at_all(
        self, db: Path, archive: Path, tmp_path: Path
    ) -> None:
        """All-or-nothing: the refusal lands before the first replace."""
        good = {p.name: p.read_bytes() for p in db.glob("coverage-*.toml")}
        tampered = tmp_path / "tampered.tar"
        with tarfile.open(archive) as source, tarfile.open(tampered, "w") as sink:
            for member in source.getmembers():
                data = source.extractfile(member).read()  # type: ignore[union-attr]
                if member.name.endswith(".toml"):
                    data = data.replace(b"FAKEDLL", b"TAMPERD")
                info = tarfile.TarInfo(member.name)
                info.size = len(data)
                sink.addfile(info, io.BytesIO(data))
        with pytest.raises(BackupError):
            restore_backup(tampered, db)
        assert {p.name: p.read_bytes() for p in db.glob("coverage-*.toml")} == good

    def test_a_traversing_member_name_cannot_escape_the_directory(
        self, db: Path, archive: Path, tmp_path: Path
    ) -> None:
        """A manifest is an editable file; its member names are not trusted."""
        evil = tmp_path / "evil.tar"
        with tarfile.open(archive) as source, tarfile.open(evil, "w") as sink:
            for member in source.getmembers():
                data = source.extractfile(member).read()  # type: ignore[union-attr]
                if member.name == MANIFEST_NAME:
                    manifest = json.loads(data)
                    manifest["members"].append(
                        {
                            "name": "../escaped.toml",
                            "size": len(data),
                            "sha256": backup._digest(data),
                        }
                    )
                    data = json.dumps(manifest).encode("utf-8")
                info = tarfile.TarInfo(member.name)
                info.size = len(data)
                sink.addfile(info, io.BytesIO(data))
        with pytest.raises(BackupError, match="not a coverage document"):
            restore_backup(evil, db)
        assert not (db.parent / "escaped.toml").exists()

    def test_a_member_not_named_as_a_document_is_refused(
        self, db: Path, archive: Path, tmp_path: Path
    ) -> None:
        """The glob that reads the directory is the same one that reads a member."""
        other = tmp_path / "other.tar"
        with tarfile.open(archive) as source, tarfile.open(other, "w") as sink:
            for member in source.getmembers():
                data = source.extractfile(member).read()  # type: ignore[union-attr]
                if member.name == MANIFEST_NAME:
                    manifest = json.loads(data)
                    manifest["members"].append(
                        {"name": "notes.txt", "size": len(data), "sha256": backup._digest(data)}
                    )
                    data = json.dumps(manifest).encode("utf-8")
                info = tarfile.TarInfo(member.name)
                info.size = len(data)
                sink.addfile(info, io.BytesIO(data))
        with pytest.raises(BackupError, match="not a coverage document"):
            restore_backup(other, db)

    def test_the_restored_bytes_are_a_document_the_server_reads(
        self, db: Path, archive: Path
    ) -> None:
        """A restore that lands bytes the reader refuses is not a restore."""
        from rebrew.coverage_toml import load_all_coverage_from

        document = next(db.glob("coverage-*.toml"))
        document.write_text("this is not toml = = =\n", encoding="utf-8")
        with pytest.raises(BackupError):
            restore_backup(archive, db)
        restore_backup(archive, db, force=True)
        assert load_all_coverage_from(db)


class TestBackupLocation:
    """Where the archive goes when nothing names a directory."""

    def test_the_default_sits_beside_the_coverage_directory(self, tmp_path: Path) -> None:
        db = tmp_path / "project" / "db"
        assert default_backup_dir(db) == tmp_path / "project" / "backups"

    def test_the_environment_wins(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("RECOVERAGE_BACKUP_DIR", str(tmp_path / "elsewhere"))
        assert backup_dir_from_env(tmp_path / "db") == tmp_path / "elsewhere"

    def test_a_blank_environment_falls_back(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setenv("RECOVERAGE_BACKUP_DIR", "   ")
        assert backup_dir_from_env(tmp_path / "db") == default_backup_dir(tmp_path / "db")


class TestBackupCli:
    """The two commands an operator and a cron job actually run."""

    def test_the_commands_back_up_the_directory_the_server_reads(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """A backup of a different directory than the one served protects nothing.

        The two reach the coverage directory through the same `_db_path`, so
        RECOVERAGE_DB moves them together with the request path. This pins that
        they have not acquired a resolution of their own.
        """
        from recoverage._paths import _db_path as resolve

        db = build_synthetic_coverage(tmp_path / "db").parent
        monkeypatch.setenv("RECOVERAGE_DB", str(db))
        assert resolve() == db
        result = runner.invoke(app, ["backup", "--to", str(tmp_path / "s.tar"), "--json"])
        assert result.exit_code == 0, result.output
        assert json.loads(result.output)["path"] == str(tmp_path / "s.tar")
        with tarfile.open(tmp_path / "s.tar") as tar:
            assert {Path(n).name for n in tar.getnames()} == {
                p.name for p in db.glob("coverage-*.toml")
            } | {MANIFEST_NAME}

    def test_backup_then_restore_through_the_cli(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        db = build_synthetic_coverage(tmp_path / "db").parent
        archive = tmp_path / "snap.tar"
        monkeypatch.setenv("RECOVERAGE_DB", str(db))
        result = runner.invoke(app, ["backup", "--to", str(archive)])
        assert result.exit_code == 0, result.output
        assert archive.exists()
        for document in db.glob("coverage-*.toml"):
            document.unlink()
        result = runner.invoke(app, ["restore", str(archive)])
        assert result.exit_code == 0, result.output
        assert list(db.glob("coverage-*.toml"))

    def test_backup_json_is_machine_readable(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """A scheduled job reads this, not the table."""
        db = build_synthetic_coverage(tmp_path / "db").parent
        monkeypatch.setenv("RECOVERAGE_DB", str(db))
        result = runner.invoke(app, ["backup", "--to", str(tmp_path / "s.tar"), "--json"])
        assert result.exit_code == 0, result.output
        payload = json.loads(result.output)
        assert payload["members"][0]["name"].endswith(".toml")
        assert len(payload["members"][0]["sha256"]) == 64

    def test_backup_of_nothing_exits_one(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        empty = tmp_path / "db"
        empty.mkdir()
        monkeypatch.setenv("RECOVERAGE_DB", str(empty))
        result = runner.invoke(app, ["backup", "--to", str(tmp_path / "s.tar")])
        assert result.exit_code == 1
        assert not (tmp_path / "s.tar").exists()

    def test_restore_of_a_bad_archive_exits_one(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        db = build_synthetic_coverage(tmp_path / "db").parent
        archive = tmp_path / "snap.tar"
        write_backup(db, archive)
        archive.write_bytes(b"not a tar at all")
        monkeypatch.setenv("RECOVERAGE_DB", str(db))
        result = runner.invoke(app, ["restore", str(archive)])
        assert result.exit_code == 1
        assert "Error" in result.output + str(result.stderr or "")

    def test_restore_refuses_a_rollback_without_force(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        db = build_synthetic_coverage(tmp_path / "db").parent
        archive = tmp_path / "snap.tar"
        write_backup(db, archive)
        document = next(db.glob("coverage-*.toml"))
        document.write_text(document.read_text() + "\n# newer\n", encoding="utf-8")
        monkeypatch.setenv("RECOVERAGE_DB", str(db))
        result = runner.invoke(app, ["restore", str(archive)])
        assert result.exit_code == 1
        assert "# newer" in document.read_text()
        result = runner.invoke(app, ["restore", str(archive), "--force"])
        assert result.exit_code == 0, result.output
        assert "# newer" not in document.read_text()
