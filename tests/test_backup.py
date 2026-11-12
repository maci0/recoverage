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
  was pointed at;
* the default archive name is a UTC instant whatever the host's zone is, so
  the backup directory sorts chronologically across a DST transition and a
  filename matches the schedule that wrote it.
"""

from __future__ import annotations

import io
import json
import os
import stat
import tarfile
import time
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, cast

import pytest
from coverage_fixture import build_synthetic_coverage, write_coverage
from typer.testing import CliRunner

from recoverage import backup
from recoverage.backup import (
    FORMAT_VERSION,
    MANIFEST_NAME,
    BackupError,
    BackupInfo,
    backup_dir_from_env,
    check_backup_freshness,
    default_backup_dir,
    newest_archive_age_hours,
    restore_backup,
    verify_all_backups,
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
    return cast(Path, build_synthetic_coverage(tmp_path / "db")).parent


@pytest.fixture
def archive(db: Path, tmp_path: Path) -> Path:
    """A verified archive of *db*, written outside it."""
    path = tmp_path / "backups" / "snapshot.tar"
    write_backup(db, path)
    return path


class TestWriteBackup:
    """A backup that reports success has been read back."""

    def test_an_out_of_range_wall_clock_still_stamps(
        self, db: Path, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """A pre-1970 or far-future clock must not raise on any platform.

        ``datetime.fromtimestamp`` raises OSError on Windows outside roughly
        1970-3000.  The stamp is built from the epoch instead, so a frozen
        replay clock at 0.0 stamps the epoch rather than crashing backup.
        """
        monkeypatch.setattr(backup.clock, "wall_time", lambda: 0.0)
        info = write_backup(db, tmp_path)
        assert info.path.name.startswith("coverage-19700101T000000")
        assert info.created.startswith("1970-01-01T00:00:00")

    def test_backup_attempts_directory_sync_where_supported(
        self, db: Path, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """The real writer must reach fsync with an open directory descriptor."""
        directory_attempts: list[int] = []
        file_attempts: list[int] = []
        real_fsync = os.fsync

        def observed_fsync(descriptor: int) -> None:
            attempts = (
                directory_attempts if stat.S_ISDIR(os.fstat(descriptor).st_mode) else file_attempts
            )
            attempts.append(descriptor)
            real_fsync(descriptor)

        monkeypatch.setattr(os, "fsync", observed_fsync)
        archive = tmp_path / "sync.tar"
        write_backup(db, archive)
        assert verify_backup(archive).members
        assert file_attempts
        if os.name == "nt":
            assert not directory_attempts
        else:
            assert directory_attempts

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

    def test_the_stamped_name_is_utc_and_sorts_as_one(
        self, db: Path, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """The name is UTC whatever the host's zone is, and sorts by instant.

        docs/RECOVERY.md tells an operator to pin their crontab to a stated
        zone and then to read the archive name beside an incident timeline, so
        the name has to answer a UTC instant rather than the host's wall clock:
        a name following ``TZ`` puts the same run at two different-looking
        times either side of a DST transition, and the two sort wrong against
        the directory they are the index to.  Fixed width for the same reason:
        a lexicographic sort IS the sort ``_ARCHIVE_PREFIX`` documents.
        """
        if not hasattr(time, "tzset"):
            pytest.skip("no time.tzset() on this platform")
        # A fixed instant, so the name is a function of the clock and the zone
        # rather than of when the suite happened to run.
        monkeypatch.setattr(backup.clock, "wall_time", lambda: 1_700_000_000.0)
        expected = datetime.fromtimestamp(1_700_000_000.0, tz=UTC)
        previous = os.environ.get("TZ")
        written: list[str] = []
        # `zone` holds a slash ("Europe/Warsaw"), so it is the PATH that gets
        # flattened, not the zone name itself.
        zones = (("Europe/Warsaw", "warsaw"), ("Pacific/Kiritimati", "kiritimati"), ("UTC", "utc"))
        try:
            for zone, folder in zones:
                monkeypatch.setenv("TZ", zone)
                time.tzset()
                # A directory destination, so the name is the stamped one the
                # default path builds rather than a name we chose.
                out = tmp_path / folder
                out.mkdir(exist_ok=True)
                written.append(write_backup(db, out).path.name)
        finally:
            if previous is None:
                monkeypatch.delenv("TZ", raising=False)
            else:
                monkeypatch.setenv("TZ", previous)
            time.tzset()
        # The same instant, so the same name: the host's zone cannot reach it.
        assert written[0] == written[1] == written[2]
        # Fixed width, zero padded, and carrying the ``Z`` the manifest's
        # instant carries, so `sort` orders the directory by instant.
        assert written[0] == "coverage-" + expected.strftime("%Y%m%dT%H%M%S.%fZ") + ".tar"
        assert sorted(written) == written

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

    def test_a_repeat_write_never_silently_replaces_the_first(
        self, db: Path, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Idempotency: a second run at the same instant must not lose the first.

        The stamped name is a function of the clock, so a cron retry, a
        replayed run, or any two runs inside one frozen/patched instant name
        the same file.  ``os.replace`` made run two silently overwrite run
        one — the earlier backup gone, with nothing saying so.  The publish
        must fail-if-exists and leave the first archive's bytes intact.
        An identical retry converges to the existing archive (verified),
        so a redelivery never mints a duplicate that prunes a distinct one.
        """
        monkeypatch.setattr(backup.clock, "wall_time", lambda: 1_700_000_000.123456)
        out = tmp_path / "out"
        out.mkdir()
        first = write_backup(db, out)
        first_bytes = first.path.read_bytes()
        second = write_backup(db, out)
        # Idempotent retry: identical documents converge to the existing
        # archive instead of minting a duplicate that prunes a distinct one.
        assert second.path == first.path
        assert [p.name for p in out.iterdir()] == [first.path.name]
        assert first.path.read_bytes() == first_bytes

    def test_a_repeat_write_to_an_explicit_path_is_refused(self, db: Path, tmp_path: Path) -> None:
        path = tmp_path / "snap.tar"
        write_backup(db, path)
        with pytest.raises(BackupError, match="already exists"):
            write_backup(db, path)

    def test_a_retry_of_identical_bytes_returns_the_existing_archive(
        self, db: Path, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """A cron retry whose first run landed converges, not refuses."""
        monkeypatch.setattr(backup.clock, "wall_time", lambda: 1_700_000_000.123456)
        path = tmp_path / "snap.tar"
        first = write_backup(db, path)
        again = write_backup(db, path)
        assert again.path == first.path
        assert again.members == first.members

    def test_two_concurrent_backups_converge_to_one_archive(self, db: Path, tmp_path: Path) -> None:
        """A second execution under concurrent back-to-back runs creates no extra archive."""
        import threading

        out = tmp_path / "out"
        out.mkdir()
        barrier = threading.Barrier(2)
        results: list[Path] = []

        def run() -> None:
            barrier.wait()
            results.append(write_backup(db, out).path)

        threads = [threading.Thread(target=run) for _ in range(2)]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join()
        assert len(results) == 2
        assert results[0] == results[1]
        assert len(list(out.glob("coverage-*.tar"))) == 1


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


class TestArchiveSizeBounds:
    """A verify holds every member's bytes in memory, so the reader is bounded.

    The archive under the reader is not necessarily one recoverage wrote: a
    restore takes whatever path the operator hands it, and ``tarfile`` trusts
    the length a header declares.  These pin that the two limits are applied to
    the HEADERS, before the data pass allocates anything, and that a member
    carrying one name twice is refused rather than silently resolved to the
    last one.
    """

    def test_a_member_over_the_single_member_limit_is_refused(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """The limit is read where the reader lives, so a test can drive it."""
        monkeypatch.setattr(backup, "_MAX_MEMBER_BYTES", 8)
        fat = tmp_path / "fat.tar"
        with tarfile.open(fat, "w") as sink:
            payload = b"0123456789"
            info = tarfile.TarInfo("coverage-fat.toml")
            info.size = len(payload)
            sink.addfile(info, io.BytesIO(payload))
            empty = {"format": FORMAT_VERSION, "created": "x", "members": []}
            manifest = json.dumps(empty).encode()
            mi = tarfile.TarInfo(MANIFEST_NAME)
            mi.size = len(manifest)
            sink.addfile(mi, io.BytesIO(manifest))
        with pytest.raises(BackupError, match="one member may hold"):
            verify_backup(fat)

    def test_an_oversized_manifest_is_refused_before_extracting(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Metadata has the member ceiling even though it is outside the total."""
        cap = 4096
        monkeypatch.setattr(backup, "_MAX_MEMBER_BYTES", cap)
        oversized = tmp_path / "oversized-manifest.tar"
        payload = b"x"
        manifest = (
            json.dumps(
                {
                    "format": FORMAT_VERSION,
                    "created": "x",
                    "members": [
                        {"name": "coverage-x.toml", "size": 1, "sha256": backup._digest(payload)}
                    ],
                }
            )
            .encode()
            .ljust(cap + 1, b" ")
        )
        with tarfile.open(oversized, "w") as sink:
            for name, data in (("coverage-x.toml", payload), (MANIFEST_NAME, manifest)):
                info = tarfile.TarInfo(name)
                info.size = len(data)
                sink.addfile(info, io.BytesIO(data))
        extracted: list[str] = []
        extract = tarfile.TarFile.extractfile

        def observe_extract(self: tarfile.TarFile, member: Any) -> Any:
            extracted.append(member.name)
            return extract(self, member)

        monkeypatch.setattr(tarfile.TarFile, "extractfile", observe_extract)
        with pytest.raises(BackupError, match=r"manifest\.json.*one member may hold"):
            verify_backup(oversized)
        assert extracted == []

    def test_an_archive_over_the_total_limit_is_refused(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Members each under the single-member cap, together over the total.

        A per-member check alone lets every one of them through; the running
        total is what refuses the archive, and it does so on the header pass,
        so nothing over the cap is ever held in memory.  The bound is lowered
        rather than a gigabyte of payload written, because the header pass is
        what is under test and it reads no member data.
        """
        monkeypatch.setattr(backup, "_MAX_MEMBER_BYTES", 64)
        monkeypatch.setattr(backup, "_MAX_ARCHIVE_BYTES", 96)
        wide = tmp_path / "wide.tar"
        with tarfile.open(wide, "w") as sink:
            for index in range(4):
                payload = b"x" * 48
                info = tarfile.TarInfo(f"coverage-{index}.toml")
                info.size = len(payload)
                sink.addfile(info, io.BytesIO(payload))
            empty = {"format": FORMAT_VERSION, "created": "x", "members": []}
            manifest = json.dumps(empty).encode()
            mi = tarfile.TarInfo(MANIFEST_NAME)
            mi.size = len(manifest)
            sink.addfile(mi, io.BytesIO(manifest))
        with pytest.raises(BackupError, match="total limit"):
            verify_backup(wide)

    def test_manifest_bytes_do_not_count_against_the_payload_caps(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Data members fitting the caps verify even though the manifest
        would push the summed size over the total cap."""
        monkeypatch.setattr(backup, "_MAX_MEMBER_BYTES", 1_000_000)
        monkeypatch.setattr(backup, "_MAX_ARCHIVE_BYTES", 96)
        covers = tmp_path / "caps.tar"
        payload = b"x" * 32
        with tarfile.open(covers, "w") as sink:
            for index in range(3):
                info = tarfile.TarInfo(f"coverage-{index}.toml")
                info.size = len(payload)
                sink.addfile(info, io.BytesIO(payload))
            manifest = json.dumps(
                {
                    "format": FORMAT_VERSION,
                    "created": "x",
                    "members": [
                        {
                            "name": f"coverage-{i}.toml",
                            "size": len(payload),
                            "sha256": backup._digest(payload),
                        }
                        for i in range(3)
                    ],
                }
            ).encode()
            mi = tarfile.TarInfo(MANIFEST_NAME)
            mi.size = len(manifest)
            sink.addfile(mi, io.BytesIO(manifest))
        verify_backup(covers)

    def test_prune_orders_by_stamped_instant_not_name(self, tmp_path: Path) -> None:
        """Same-microsecond neighbours (``-2`` suffix) prune by instant."""
        backup_dir = tmp_path / "backups"
        backup_dir.mkdir()
        stamped = []
        for i in range(31):
            # Formatted as _stamp does: date + HHMMSS + "." + 6-digit usec
            name = f"{backup._ARCHIVE_PREFIX}20240101T000000.{i:06d}Z{backup._ARCHIVE_SUFFIX}"
            p = backup_dir / name
            p.write_bytes(b"x")
            stamped.append(p)
        tie = (
            backup_dir
            / f"{backup._ARCHIVE_PREFIX}20240101T000000.000000Z-2{backup._ARCHIVE_SUFFIX}"
        )
        tie.write_bytes(b"x")
        orig_verify = backup.verify_backup
        backup.verify_backup = lambda path: BackupInfo(path, "", (), 0)
        try:
            backup._prune_old_archives(backup_dir)
        finally:
            backup.verify_backup = orig_verify
        remaining = sorted(p.name for p in backup_dir.iterdir())
        assert len(remaining) == 30, remaining
        assert stamped[30].name in remaining

    def test_prune_skips_when_survivors_do_not_verify(self, tmp_path: Path) -> None:
        """Prune will not delete into a directory with no verified edge.

        The oldest retained archive is the recovery point for a logical
        corruption discovered later.  When it (and every survivor) fails
        verification, deleting the older archives would discard the only
        recovery point the operator has; prune skips instead and leaves
        the corruption for the freshness monitor to surface.
        """
        backup_dir = tmp_path / "backups"
        backup_dir.mkdir()
        stamped = []
        for i in range(31):
            name = f"{backup._ARCHIVE_PREFIX}20240101T000000.{i:06d}Z{backup._ARCHIVE_SUFFIX}"
            p = backup_dir / name
            p.write_bytes(b"x")  # not a readable archive
            stamped.append(p)
        backup._prune_old_archives(backup_dir)
        remaining = sorted(p.name for p in backup_dir.iterdir())
        assert len(remaining) == 31, remaining

    def test_prune_deletes_after_a_survivor_verifies(self, tmp_path: Path) -> None:
        """One verified survivor lets the prune proceed normally.

        Ordering is by stamped instant, so the survivor checked is the
        newest retained archive, not the oldest one the restore would
        reach for; the other survivors stay junk the verify only sampled.
        """
        backup_dir = tmp_path / "backups"
        backup_dir.mkdir()
        stamped = []
        for i in range(31):
            name = f"{backup._ARCHIVE_PREFIX}20240101T000000.{i:06d}Z{backup._ARCHIVE_SUFFIX}"
            p = backup_dir / name
            p.write_bytes(b"x")
            stamped.append(p)

        # The survivor the prune checks is the newest (stamped[-1]); that
        # one verifies, the older ones are junk the verify only sampled.
        orig_verify = backup.verify_backup
        backup.verify_backup = lambda path: BackupInfo(path, "", (), 0)
        try:
            backup._prune_old_archives(backup_dir)
        finally:
            backup.verify_backup = orig_verify
        remaining = sorted(p.name for p in backup_dir.iterdir())
        assert len(remaining) == 30, remaining
        assert stamped[0].name not in remaining

    def test_a_duplicated_member_name_is_refused(self, tmp_path: Path) -> None:
        """Two members under one name are not resolved by picking the last."""
        data = b"second"
        duplicate = tmp_path / "dup.tar"
        with tarfile.open(duplicate, "w") as sink:
            for payload in (b"first", data):
                info = tarfile.TarInfo("coverage-a.toml")
                info.size = len(payload)
                sink.addfile(info, io.BytesIO(payload))
            manifest = json.dumps(
                {
                    "format": FORMAT_VERSION,
                    "created": "now",
                    "members": [
                        {
                            "name": "coverage-a.toml",
                            "size": len(data),
                            "sha256": backup._digest(data),
                        }
                    ],
                }
            ).encode("utf-8")
            info = tarfile.TarInfo(MANIFEST_NAME)
            info.size = len(manifest)
            sink.addfile(info, io.BytesIO(manifest))
        with pytest.raises(BackupError, match="appears twice"):
            verify_backup(duplicate)


class TestRestoreBackup:
    """The disaster path: the documents are gone, and then they are back."""

    def test_the_archive_is_read_once(
        self, db: Path, archive: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """The members written are the members that were verified.

        A restore that verified through one read and then re-read the tar to
        get the bytes writes a second copy of a file it never checked, and pays
        two full passes over it to do so.
        """
        for document in db.glob("coverage-*.toml"):
            document.unlink()
        reads = 0
        real_open = tarfile.open

        def counting_open(*args: Any, **kwargs: Any) -> Any:
            nonlocal reads
            reads += 1
            return real_open(*args, **kwargs)

        monkeypatch.setattr(backup.tarfile, "open", counting_open)
        written = restore_backup(archive, db)
        assert written
        assert reads == 1

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
        before = {
            p.name: (p.read_bytes(), p.stat().st_mtime_ns) for p in db.glob("coverage-*.toml")
        }
        restore_backup(archive, db)
        assert {
            p.name: (p.read_bytes(), p.stat().st_mtime_ns) for p in db.glob("coverage-*.toml")
        } == before

    def test_a_second_force_restore_of_the_same_archive_is_a_no_op(
        self, db: Path, archive: Path
    ) -> None:
        """Rerunning a forced restore converges instead of rewriting again.

        The first forced restore rolls a differing document back; a retry
        or replayed drill running it again must leave the now-identical
        bytes (and their mtime, which freshness checks read as a build)
        untouched.
        """
        document = next(db.glob("coverage-*.toml"))
        document.write_bytes(document.read_bytes() + b"\n# newer\n")
        restore_backup(archive, db, force=True)
        before = (document.read_bytes(), document.stat().st_mtime_ns)
        restore_backup(archive, db, force=True)
        assert (document.read_bytes(), document.stat().st_mtime_ns) == before

    @pytest.mark.parametrize("failure", ["stage", "publish"])
    @pytest.mark.parametrize("original", [None, b"newer original"])
    def test_a_later_io_failure_restores_the_original_directory(
        self,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
        failure: str,
        original: bytes | None,
    ) -> None:
        source = tmp_path / "source"
        for target in ("A", "B"):
            write_coverage(source, target, {})
        archive = tmp_path / "backup.tar"
        write_backup(source, archive)
        destination = tmp_path / "destination"
        destination.mkdir()
        first = destination / "coverage-A.toml"
        if original is not None:
            first.write_bytes(original)
        untouched = destination / "inventory.json"
        untouched.write_bytes(b"keep inventory")
        real_write = backup._atomic_write
        real_replace = Path.replace

        def fail_write(path: Path, data: bytes) -> None:
            if failure == "stage" and path.name == "coverage-B.toml":
                raise OSError("disk full")
            real_write(path, data)

        def fail_replace(path: Path, target: Path) -> Path:
            if failure == "publish" and target == destination / "coverage-B.toml":
                raise PermissionError("destination locked")
            return real_replace(path, target)

        monkeypatch.setattr(backup, "_atomic_write", fail_write)
        monkeypatch.setattr(Path, "replace", fail_replace)
        expected = "disk full" if failure == "stage" else "destination locked"
        with pytest.raises(BackupError, match=expected):
            restore_backup(archive, destination, force=True)
        if original is not None:
            assert first.read_bytes() == original
        else:
            assert not first.exists()
        assert not (destination / "coverage-B.toml").exists()
        assert untouched.read_bytes() == b"keep inventory"
        assert {path.name for path in destination.iterdir()} == (
            {first.name, untouched.name} if original is not None else {untouched.name}
        )

    def test_a_failed_rollback_retains_the_original_files(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        source = tmp_path / "source"
        for target in ("A", "B"):
            write_coverage(source, target, {})
        archive = tmp_path / "backup.tar"
        write_backup(source, archive)
        destination = tmp_path / "destination"
        destination.mkdir()
        (destination / "coverage-A.toml").write_bytes(b"newer original")
        real_replace = Path.replace

        def fail_replace(path: Path, target: Path) -> Path:
            if target == destination / "coverage-B.toml" or path.parent.name == "previous":
                raise PermissionError("destination locked")
            return real_replace(path, target)

        monkeypatch.setattr(Path, "replace", fail_replace)
        with pytest.raises(BackupError, match="original files retained"):
            restore_backup(archive, destination, force=True)
        retained = list(destination.glob(".restore-*/previous/coverage-A.toml"))
        assert len(retained) == 1
        assert retained[0].read_bytes() == b"newer original"

    def test_force_does_not_replace_a_directory_after_writing_other_members(
        self, tmp_path: Path
    ) -> None:
        source = tmp_path / "source"
        for target in ("A", "B"):
            write_coverage(source, target, {})
        archive = tmp_path / "backup.tar"
        write_backup(source, archive)
        destination = tmp_path / "destination"
        (destination / "coverage-B.toml").mkdir(parents=True)
        with pytest.raises(BackupError, match="cannot restore"):
            restore_backup(archive, destination, force=True)
        assert not (destination / "coverage-A.toml").exists()

    def test_rollback_keeps_an_unchanged_document_it_never_touched(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """An unchanged member was never published, so rollback must not delete it."""
        source = tmp_path / "source"
        for target in ("A", "B"):
            write_coverage(source, target, {})
        archive = tmp_path / "backup.tar"
        write_backup(source, archive)
        destination = tmp_path / "destination"
        destination.mkdir()
        (destination / "coverage-A.toml").write_bytes((source / "coverage-A.toml").read_bytes())
        (destination / "coverage-B.toml").write_bytes(b"newer original B")
        real_replace = Path.replace

        def fail_replace(path: Path, target: Path) -> Path:
            if target == destination / "coverage-B.toml" and path.parent.name != "previous":
                raise PermissionError("destination locked")
            return real_replace(path, target)

        monkeypatch.setattr(Path, "replace", fail_replace)
        with pytest.raises(BackupError, match="destination locked"):
            restore_backup(archive, destination, force=True)
        assert (destination / "coverage-A.toml").read_bytes() == (
            source / "coverage-A.toml"
        ).read_bytes()
        assert (destination / "coverage-B.toml").read_bytes() == b"newer original B"

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

    def test_restore_removes_a_stale_document_the_archive_does_not_hold(
        self, tmp_path: Path
    ) -> None:
        """A restore to the archive's snapshot set, not a merge into the live set.

        A document the archive does not hold (deleted from the source
        between backups, or newly written by a bad build) must not survive
        the restore: leaving it serves a target the restore never had,
        the exact partial-restore the manifest exists to prevent.
        """
        source = tmp_path / "source"
        for target in ("A", "B"):
            write_coverage(source, target, {})
        archive = tmp_path / "backup.tar"
        write_backup(source, archive)
        destination = tmp_path / "destination"
        destination.mkdir()
        for path in source.glob("coverage-*.toml"):
            (destination / path.name).write_bytes(path.read_bytes())
        (destination / "coverage-C.toml").write_bytes(b"stale target\n")
        (destination / "inventory.json").write_bytes(b"keep inventory")
        restore_backup(archive, destination, force=True)
        assert (destination / "coverage-C.toml").exists() is False
        assert (destination / "inventory.json").read_bytes() == b"keep inventory"
        assert sorted(p.name for p in destination.glob("coverage-*.toml")) == [
            "coverage-A.toml",
            "coverage-B.toml",
        ]

    def test_stale_documents_are_refused_without_force(self, tmp_path: Path) -> None:
        source = tmp_path / "source"
        write_coverage(source, "A", {})
        archive = tmp_path / "backup.tar"
        write_backup(source, archive)
        destination = tmp_path / "destination"
        destination.mkdir()
        (destination / "coverage-Z.toml").write_bytes(b"stale target\n")
        with pytest.raises(BackupError, match="would be removed"):
            restore_backup(archive, destination)
        assert (destination / "coverage-Z.toml").exists()
        assert not (destination / "coverage-A.toml").exists()

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
        with pytest.raises(BackupError, match="does not match its manifest digest"):
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
        with pytest.raises(BackupError, match="not a safe flat member name"):
            restore_backup(evil, db)
        assert not (db.parent / "escaped.toml").exists()

    def test_a_manifest_member_absent_from_the_archive_is_refused(
        self, db: Path, archive: Path, tmp_path: Path
    ) -> None:
        """A manifest entry naming bytes the archive does not hold is a refusal."""
        other = tmp_path / "other.tar"
        payload = b"notes payload"
        with tarfile.open(archive) as source, tarfile.open(other, "w") as sink:
            for member in source.getmembers():
                data = source.extractfile(member).read()  # type: ignore[union-attr]
                if member.name == MANIFEST_NAME:
                    manifest = json.loads(data)
                    manifest["members"].append(
                        {
                            "name": "notes.txt",
                            "size": len(payload),
                            "sha256": backup._digest(payload),
                        }
                    )
                    data = json.dumps(manifest).encode("utf-8")
                info = tarfile.TarInfo(member.name)
                info.size = len(data)
                sink.addfile(info, io.BytesIO(data))
        with pytest.raises(BackupError, match="is not a regular file"):
            restore_backup(other, db)

    def test_the_restored_bytes_are_a_document_the_server_reads(
        self, db: Path, archive: Path
    ) -> None:
        """A restore that lands bytes the reader refuses is not a restore."""
        from rebrew.coverage_toml import load_all_coverage_from

        document = next(db.glob("coverage-*.toml"))
        document.write_text("this is not toml = = =\n", encoding="utf-8")
        with pytest.raises(BackupError, match="refusing to roll coverage back"):
            restore_backup(archive, db)
        restore_backup(archive, db, force=True)
        assert load_all_coverage_from(db)


class TestReferencedFiles:
    """A portable export's referenced inputs travel with its backup."""

    def _write_with_binary(self, tmp_path: Path, binary_name: str = "game.exe") -> Path:
        db = tmp_path / "db"
        db.mkdir()
        write_coverage(db, "FAKEDLL", {}, functions=[], paths={"originalDll": binary_name})
        (db / binary_name).write_bytes(b"binary-bytes")
        return db

    def test_referenced_binary_is_archived_and_restored(self, tmp_path: Path) -> None:
        db = self._write_with_binary(tmp_path)
        archive = tmp_path / "snap.tar"
        info = write_backup(db, archive)
        names = [name for name, _s, _d in info.members]
        assert "game.exe" in names
        (db / "game.exe").unlink()
        document = next(db.glob("coverage-*.toml"))
        document.write_bytes(b"stale")
        written = restore_backup(archive, db, force=True)
        names_written = [w.name for w in written]
        assert "game.exe" in names_written
        assert (db / "game.exe").read_bytes() == b"binary-bytes"

    def test_missing_referenced_binary_is_a_refusal(self, tmp_path: Path) -> None:
        db = tmp_path / "db"
        db.mkdir()
        write_coverage(db, "FAKEDLL", {}, functions=[], paths={"originalDll": "game.exe"})
        with pytest.raises(BackupError, match="not present"):
            write_backup(db, tmp_path / "snap.tar")

    def test_referenced_path_escaping_the_snapshot_is_a_refusal(self, tmp_path: Path) -> None:
        db = tmp_path / "db"
        db.mkdir()

        write_coverage(db, "FAKEDLL", {}, functions=[], paths={"originalDll": "../game.exe"})
        with pytest.raises(BackupError, match="escapes the snapshot directory"):
            write_backup(db, tmp_path / "snap.tar")

    def test_backslash_ref_from_a_windows_written_export_is_archived(self, tmp_path: Path) -> None:
        # Portable exports are cross-platform documents: a Windows writer
        # spells separators as "\\", which POSIX Path would read as one
        # flat filename. Backup must fold it to "/" like the source-root
        # reader does, or it refuses a binary that is present.
        db = tmp_path / "db"
        (db / "binaries").mkdir(parents=True)
        (db / "binaries" / "game.exe").write_bytes(b"binary-bytes")
        write_coverage(db, "FAKEDLL", {}, functions=[], paths={"originalDll": "binaries\\game.exe"})
        archive = tmp_path / "snap.tar"
        info = write_backup(db, archive)
        assert "game.exe" in [name for name, _s, _d in info.members]

    def test_backslash_traversal_ref_is_an_escape_refusal(self, tmp_path: Path) -> None:
        db = tmp_path / "db"
        db.mkdir()
        write_coverage(db, "FAKEDLL", {}, functions=[], paths={"originalDll": "..\\game.exe"})
        with pytest.raises(BackupError, match="escapes the snapshot directory"):
            write_backup(db, tmp_path / "snap.tar")

    def test_a_source_root_tree_is_refused_by_name_not_as_a_missing_file(
        self, tmp_path: Path
    ) -> None:
        # sourceRoot names a tree, which the flat archive cannot carry. The
        # refusal names the exclusion (back the tree up through its project)
        # rather than "not present", which would read as a file to copy in.
        db = tmp_path / "db"
        (db / "src").mkdir(parents=True)
        (db / "src" / "a.c").write_text("int x;\n")
        write_coverage(db, "FAKEDLL", {}, functions=[], paths={"sourceRoot": "src"})
        with pytest.raises(BackupError, match="source tree"):
            write_backup(db, tmp_path / "snap.tar")

    def test_a_source_root_refuses_even_when_absent(self, tmp_path: Path) -> None:
        # A backup that archives around an absent sourceRoot would restore
        # the map and silently drop the source pane, so the key alone refuses.
        db = tmp_path / "db"
        db.mkdir()
        write_coverage(db, "FAKEDLL", {}, functions=[], paths={"sourceRoot": "src"})
        with pytest.raises(BackupError, match="source tree"):
            write_backup(db, tmp_path / "snap.tar")

    def test_an_original_dll_alongside_a_source_root_still_refuses(self, tmp_path: Path) -> None:
        # The binary is the one reference the archive carries; a document
        # naming both still refuses on the tree, and writes no archive.
        db = tmp_path / "db"
        db.mkdir()
        (db / "game.exe").write_bytes(b"binary-bytes")
        write_coverage(
            db,
            "FAKEDLL",
            {},
            functions=[],
            paths={"originalDll": "game.exe", "sourceRoot": "src"},
        )
        archive = tmp_path / "snap.tar"
        with pytest.raises(BackupError, match="source tree"):
            write_backup(db, archive)
        assert not archive.exists()


class TestBackupFreshness:
    """A backup schedule that stops running must fail a monitor, not vanish."""

    def test_no_directory_is_a_refusal(self, tmp_path: Path) -> None:
        with pytest.raises(BackupError, match="no backup directory"):
            check_backup_freshness(tmp_path / "missing")

    def test_empty_directory_is_a_refusal(self, tmp_path: Path) -> None:
        (tmp_path / "empty").mkdir()
        with pytest.raises(BackupError, match="no stamped backup"):
            check_backup_freshness(tmp_path / "empty")

    def test_fresh_archive_passes_and_reports_its_age(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        db = tmp_path / "db"
        db.mkdir()
        build_synthetic_coverage(db)
        out = tmp_path / "backups"
        out.mkdir()
        archive = out / "coverage-20260101T000000.000000Z.tar"
        write_backup(db, archive)
        # The name stamps 2026-01-01, so a clock an hour after it is fresh.
        inner = backup._archive_stamp_instant(archive.name)
        assert inner is not None
        monkeypatch.setattr(backup.clock, "wall_time", lambda: inner.timestamp() + 3600)
        age = newest_archive_age_hours(out)
        assert age is not None and age == pytest.approx(1.0)
        check_backup_freshness(out)

    def test_overdue_archive_is_a_refusal(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        out = tmp_path / "backups"
        out.mkdir()
        archive = out / "coverage-20260101T000000.000000Z.tar"
        archive.write_bytes(b"placeholder")
        # The name stamps an instant, so the patched clock past it makes the
        # archive overdue regardless of its mtime.
        monkeypatch.setattr(backup.clock, "wall_time", lambda: 1_000_000_000.0)
        with pytest.raises(BackupError, match="overdue"):
            check_backup_freshness(out)

    def test_newest_is_the_stamped_instant_not_the_mtime(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """A clock step moves a later write's mtime with it: keying on mtime
        let the older-named archive read as newest (freshness monitor then
        verified the wrong archive while the newest content sat untrusted)."""
        out = tmp_path / "backups"
        out.mkdir()
        newer = out / "coverage-20260101T000000.000000Z.tar"
        newer.write_bytes(b"placeholder")
        older = out / "coverage-20200101T000000.000000Z.tar"
        older.write_bytes(b"placeholder")
        # The older archive written later (after the clock stepped back):
        # its mtime reads newer.  The name index must still win.
        os.utime(older, (1_900_000_000, 1_900_000_000))
        os.utime(newer, (1_000_000_000, 1_000_000_000))
        assert backup._newest_stamped_archive(out) == newer
        inner = backup._archive_stamp_instant(newer.name)
        assert inner is not None
        monkeypatch.setattr(backup.clock, "wall_time", lambda: inner.timestamp() + 3600)
        age = newest_archive_age_hours(out)
        assert age is not None and age == pytest.approx(1.0)

    def test_a_hand_made_coverage_archive_is_not_a_stamped_backup(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Only the module's own name shape counts: an operator's other
        ``coverage-*.tar`` carrying a fresh mtime is not the newest backup."""
        out = tmp_path / "backups"
        out.mkdir()
        stamped = out / "coverage-20200101T000000.000000Z.tar"
        stamped.write_bytes(b"placeholder")
        hand_made = out / "coverage-manual.tar"
        hand_made.write_bytes(b"placeholder")
        os.utime(hand_made, (1_900_000_000, 1_900_000_000))
        assert backup._newest_stamped_archive(out) == stamped

    def test_verify_all_catches_a_corrupt_older_archive(self, db: Path, tmp_path: Path) -> None:
        """check-backup verifies only the newest; a corrupt older archive is
        the one a logical-corruption restore reaches for, so the whole
        retention set must be provable."""
        out = tmp_path / "backups"
        out.mkdir()
        write_backup(db, out / "coverage-20200101T000000.000000Z.tar")
        write_backup(db, out / "coverage-20260101T000000.000000Z.tar")
        archives = verify_all_backups(out)
        assert len(archives) == 2
        (out / "coverage-20200101T000000.000000Z.tar").write_bytes(b"not a tar")
        with pytest.raises(BackupError, match="not a readable backup"):
            verify_all_backups(out)
        inner = backup._archive_stamp_instant("coverage-20260101T000000.000000Z.tar")
        assert inner is not None

    def test_verify_backups_cli_fails_on_a_corrupt_older_archive(
        self, db: Path, tmp_path: Path
    ) -> None:
        out = tmp_path / "backups"
        out.mkdir()
        write_backup(db, out / "coverage-20200101T000000.000000Z.tar")
        write_backup(db, out / "coverage-20260101T000000.000000Z.tar")
        (out / "coverage-20200101T000000.000000Z.tar").write_bytes(b"not a tar")
        result = runner.invoke(app, ["verify-backups", str(out)])
        assert result.exit_code == 1, result.output

    def test_a_corrupt_newest_archive_is_not_fresh(
        self, db: Path, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Age alone is not freshness: a corrupt newest archive passes an
        mtime check and then fails the restore it was meant to protect against."""
        out = tmp_path / "backups"
        out.mkdir()
        write_backup(db, out / "coverage-20200101T000000.000000Z.tar")
        newest = out / "coverage-20260101T000000.000000Z.tar"
        newest.write_bytes(b"not a tar")
        inner = backup._archive_stamp_instant(newest.name)
        assert inner is not None
        monkeypatch.setattr(backup.clock, "wall_time", lambda: inner.timestamp() + 3600)
        with pytest.raises(BackupError, match="does not verify"):
            check_backup_freshness(out)

    def test_a_symlink_named_like_an_archive_is_not_a_backup(self, tmp_path: Path) -> None:
        """A link is not a backup: counting it let a symlink pass a freshness
        monitor for bytes nobody wrote, while the prune path refuses links."""
        out = tmp_path / "backups"
        out.mkdir()
        target = out / "real.tar"
        target.write_bytes(b"placeholder")
        (out / "coverage-20260101T000000.000000Z.tar").symlink_to(target)
        with pytest.raises(BackupError, match="no stamped backup"):
            check_backup_freshness(out)

    def test_a_failed_verify_leaves_no_archive_behind(
        self, db: Path, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """An unverified archive left in the backup directory becomes its newest
        file and reads as fresh on mtime alone."""
        out = tmp_path / "backups"

        def fail(path: Path) -> None:
            raise BackupError("simulated verify failure")

        monkeypatch.setattr(backup, "verify_backup", fail)
        with pytest.raises(BackupError, match="simulated verify failure"):
            write_backup(db, out / "coverage-20260101T000000.000000Z.tar")
        assert out.exists()
        assert list(out.glob("*")) == []

    @pytest.mark.parametrize("bound", [float("inf"), float("nan"), -1.0])
    def test_a_non_finite_or_negative_bound_is_refused(self, tmp_path: Path, bound: float) -> None:
        """inf/nan compare False against every age, so an unguarded bound
        reads a stale backup as fresh; a negative bound fails even a fresh
        one. The bound is refused, not compared."""
        out = tmp_path / "backups"
        out.mkdir()
        (out / "coverage-20260101T000000.000000Z.tar").write_bytes(b"placeholder")
        with pytest.raises(BackupError, match="non-negative"):
            check_backup_freshness(out, max_age_hours=bound)


class TestBackupLocation:
    """Where the archive goes when nothing names a directory."""

    def test_the_default_sits_beside_the_coverage_directory(self, tmp_path: Path) -> None:
        db = tmp_path / "project" / "db"
        assert default_backup_dir(db) == tmp_path / "project" / "backups"

    def test_the_environment_wins(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("RECOVERAGE_BACKUP_DIR", str(tmp_path / "elsewhere"))
        assert backup_dir_from_env(tmp_path / "db") == tmp_path / "elsewhere"

    def test_a_blank_environment_is_refused(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """A set-but-blank backup dir fails instead of silently using the default."""
        monkeypatch.setenv("RECOVERAGE_BACKUP_DIR", "   ")
        with pytest.raises(BackupError, match="set but empty"):
            backup_dir_from_env(tmp_path / "db")

    def test_write_backup_refuses_a_blank_environment(
        self, db: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setenv("RECOVERAGE_BACKUP_DIR", "")
        with pytest.raises(BackupError, match="set but empty"):
            write_backup(db)


class TestRestoreDrill:
    """The drill proves a restore, not merely that an archive exists."""

    def test_drill_restores_and_serves_a_fresh_directory(
        self, db: Path, archive: Path, tmp_path: Path
    ) -> None:
        """A drill into an empty directory restores and the reader serves it."""
        drill = tmp_path / "drill"
        result = runner.invoke(app, ["restore-drill", str(archive), "--into", str(drill), "--json"])
        assert result.exit_code == 0, result.output
        payload = json.loads(result.stdout)
        assert payload["documents"] == [p.name for p in db.glob("coverage-*.toml")]
        assert payload["targets"]
        assert sorted(p.name for p in drill.glob("coverage-*.toml")) == payload["documents"]

    def test_drill_refuses_a_dirty_directory(self, archive: Path, tmp_path: Path) -> None:
        """A drill directory that already holds files proves nothing: refuse it."""
        drill = tmp_path / "drill"
        drill.mkdir()
        (drill / "stale.txt").write_text("stale", encoding="utf-8")
        result = runner.invoke(app, ["restore-drill", str(archive), "--into", str(drill)])
        assert result.exit_code == 1, result.output
        assert "already holds" in result.output
        assert not list(drill.glob("coverage-*.toml"))

    def test_drill_refuses_a_corrupt_archive(self, tmp_path: Path) -> None:
        """A corrupt archive fails the drill before any restore lands."""
        bad = tmp_path / "bad.tar"
        bad.write_bytes(b"not a tar")
        drill = tmp_path / "drill"
        result = runner.invoke(app, ["restore-drill", str(bad), "--into", str(drill)])
        assert result.exit_code == 1, result.output
        assert not list(drill.glob("coverage-*.toml")) if drill.exists() else True

    def test_a_drill_rerun_converges_instead_of_refusing(
        self, archive: Path, tmp_path: Path
    ) -> None:
        """Re-running a completed drill is a no-op, not a refusal.

        A scheduled drill is replayed by its scheduler and a retry runs
        after the first answer was lost: the second run must leave the
        restored bytes (and their mtime) untouched and exit 0, exactly as
        a second forced restore of the same archive does.
        """
        drill = tmp_path / "drill"
        first = runner.invoke(app, ["restore-drill", str(archive), "--into", str(drill)])
        assert first.exit_code == 0, first.output
        before = {
            entry.name: (entry.read_bytes(), entry.stat().st_mtime_ns)
            for entry in drill.glob("coverage-*.toml")
        }
        assert before
        second = runner.invoke(app, ["restore-drill", str(archive), "--into", str(drill)])
        assert second.exit_code == 0, second.output
        after = {
            entry.name: (entry.read_bytes(), entry.stat().st_mtime_ns)
            for entry in drill.glob("coverage-*.toml")
        }
        assert after == before
        assert sorted(entry.name for entry in drill.iterdir()) == sorted(before)

    def test_a_drill_rerun_still_refuses_a_tampered_document(
        self, archive: Path, tmp_path: Path
    ) -> None:
        """Convergence requires the archive's bytes, not merely its names.

        A document edited after the first drill is a dirty drill: the
        rerun must refuse it rather than re-prove the archive over bytes
        it no longer holds.
        """
        drill = tmp_path / "drill"
        first = runner.invoke(app, ["restore-drill", str(archive), "--into", str(drill)])
        assert first.exit_code == 0, first.output
        document = next(drill.glob("coverage-*.toml"))
        document.write_bytes(document.read_bytes() + b"\n# tampered\n")
        second = runner.invoke(app, ["restore-drill", str(archive), "--into", str(drill)])
        assert second.exit_code == 1, second.output
        assert "already holds" in second.output

    def test_drill_does_not_need_a_snapshot_selection(
        self, archive: Path, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """The drill target is --into, not RECOVERAGE_SNAPSHOTS: no selection needed."""
        monkeypatch.delenv("RECOVERAGE_SNAPSHOTS", raising=False)
        drill = tmp_path / "drill"
        result = runner.invoke(app, ["restore-drill", str(archive), "--into", str(drill)])
        assert result.exit_code == 0, result.output
        assert list(drill.glob("coverage-*.toml"))


class TestBackupCli:
    """The two commands an operator and a cron job actually run."""

    def test_the_commands_back_up_the_directory_the_server_reads(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """A backup of a different directory than the one served protects nothing.

        The two reach the coverage directory through the same `coverage_source`, so
        RECOVERAGE_SNAPSHOTS moves them together with the request path. This pins that
        they have not acquired a resolution of their own.
        """
        from recoverage._paths import coverage_source as resolve

        db = build_synthetic_coverage(tmp_path / "db").parent
        monkeypatch.setenv("RECOVERAGE_SNAPSHOTS", str(db))
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
        monkeypatch.setenv("RECOVERAGE_SNAPSHOTS", str(db))
        result = runner.invoke(app, ["backup", "--to", str(archive)])
        assert result.exit_code == 0, result.output
        assert archive.exists()
        for document in db.glob("coverage-*.toml"):
            document.unlink()
        result = runner.invoke(app, ["restore", str(archive)])
        assert result.exit_code == 0, result.output
        assert list(db.glob("coverage-*.toml"))
        # The one synthetic document is counted as one, not as "document(s)".
        assert "Restored 1 document to" in result.output

    def test_backup_json_is_machine_readable(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """A scheduled job reads this, not the table."""
        db = build_synthetic_coverage(tmp_path / "db").parent
        monkeypatch.setenv("RECOVERAGE_SNAPSHOTS", str(db))
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
        monkeypatch.setenv("RECOVERAGE_SNAPSHOTS", str(empty))
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
        monkeypatch.setenv("RECOVERAGE_SNAPSHOTS", str(db))
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
        monkeypatch.setenv("RECOVERAGE_SNAPSHOTS", str(db))
        result = runner.invoke(app, ["restore", str(archive)])
        assert result.exit_code == 1
        assert "# newer" in document.read_text()
        result = runner.invoke(app, ["restore", str(archive), "--force"])
        assert result.exit_code == 0, result.output
        assert "# newer" not in document.read_text()

    def test_a_backup_destination_inside_the_coverage_directory_is_refused(self, db: Path) -> None:
        with pytest.raises(BackupError, match="inside the coverage directory"):
            write_backup(db, db / "backups" / "snap.tar")

    def test_a_leftover_staging_directory_is_refused_before_any_write(
        self, db: Path, archive: Path, tmp_path: Path
    ) -> None:
        leftover = db / ".restore-interrupted"
        leftover.mkdir()
        (leftover / "previous").mkdir()
        (leftover / "previous" / "coverage-a.toml").write_bytes(b"original")
        with pytest.raises(BackupError, match="interrupted restore"):
            restore_backup(archive, db)
        assert (leftover / "previous" / "coverage-a.toml").read_bytes() == b"original"

    @pytest.mark.parametrize("bad_name", [[], {}], ids=["array", "object"])
    @pytest.mark.parametrize("command", ["verify", "restore"])
    def test_non_text_manifest_names_use_the_json_error_envelope(
        self,
        db: Path,
        archive: Path,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
        bad_name: object,
        command: str,
    ) -> None:
        """An editable manifest must be validated before names become set keys."""
        monkeypatch.setenv("RECOVERAGE_SNAPSHOTS", str(db))
        good = runner.invoke(app, ["verify", str(archive), "--json"])
        assert good.exit_code == 0, good.output
        assert json.loads(good.output)["members"]
        before = {p.name: p.read_bytes() for p in db.iterdir()}
        malformed = tmp_path / "malformed-name.tar"
        with tarfile.open(archive) as source, tarfile.open(malformed, "w") as sink:
            for member in source.getmembers():
                data = source.extractfile(member).read()  # type: ignore[union-attr]
                if member.name == MANIFEST_NAME:
                    manifest = json.loads(data)
                    manifest["members"].append({"name": bad_name, "size": 0, "sha256": ""})
                    data = json.dumps(manifest).encode()
                info = tarfile.TarInfo(member.name)
                info.size = len(data)
                sink.addfile(info, io.BytesIO(data))
        args = [command, str(malformed), "--json"]
        if command == "restore":
            args.append("--force")
        result = runner.invoke(app, args)
        assert result.exit_code == 1
        assert not isinstance(result.exception, TypeError), result.exception
        error = json.loads(result.output)["error"]
        assert "not a safe flat member name" in error["message"]
        assert {p.name: p.read_bytes() for p in db.iterdir()} == before

    def test_verify_command_proves_an_archive_without_restoring_it(
        self, db: Path, archive: Path, tmp_path: Path
    ) -> None:
        result = runner.invoke(app, ["verify", str(archive)])
        assert result.exit_code == 0, result.output
        assert "Verified backup" in result.output
        tampered = tmp_path / "tampered.tar"
        with tarfile.open(archive) as source, tarfile.open(tampered, "w") as sink:
            for member in source.getmembers():
                data = source.extractfile(member).read()  # type: ignore[union-attr]
                if member.name.endswith(".toml"):
                    data = data[: len(data) // 2]
                info = tarfile.TarInfo(member.name)
                info.size = len(data)
                sink.addfile(info, io.BytesIO(data))
        result = runner.invoke(app, ["verify", str(tampered)])
        assert result.exit_code == 1


class TestCheckBackupBoundParsing:
    """--max-age-hours spellings that must not read as a fresh verdict."""

    @pytest.mark.parametrize("bound", ["inf", "-inf", "nan", "1_0", "-5", "1e3", ""])
    def test_a_bad_max_age_hours_is_a_usage_error(self, tmp_path: Path, bound: str) -> None:
        db = build_synthetic_coverage(tmp_path / "db").parent
        out = tmp_path / "backups"
        out.mkdir()
        write_backup(db, out / "coverage-20260101T000000.000000Z.tar")
        result = runner.invoke(app, ["check-backup", str(out), "--max-age-hours", bound])
        assert result.exit_code == 2, (bound, result.output)
        assert "--max-age-hours" in result.output + str(result.stderr or "")

    def test_a_decimal_max_age_hours_is_accepted(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        db = build_synthetic_coverage(tmp_path / "db").parent
        out = tmp_path / "backups"
        out.mkdir()
        archive = out / "coverage-20260101T000000.000000Z.tar"
        write_backup(db, archive)
        inner = backup._archive_stamp_instant(archive.name)
        assert inner is not None
        monkeypatch.setattr(backup.clock, "wall_time", lambda: inner.timestamp() + 3600)
        result = runner.invoke(app, ["check-backup", str(out), "--max-age-hours", "25.5"])
        assert result.exit_code == 0, result.output

    def test_a_bound_wider_than_a_float_is_a_usage_error(self, tmp_path: Path) -> None:
        """A bound past the float range must not overflow to infinity.

        ``_checked_max_age_hours`` builds the value from integers instead of
        through ``float()``; a digit run wide enough to overflow the float
        used to reach the comparison as ``inf`` (or crash with ``OverflowError``),
        so the stale-backup monitor read every age as fresh.  That is the
        failure ``--min-coverage`` already guards against, and the one this
        bound exists to catch: the monitor must refuse rather than pass.
        """
        db = build_synthetic_coverage(tmp_path / "db").parent
        out = tmp_path / "backups"
        out.mkdir()
        write_backup(db, out / "coverage-20260101T000000.000000Z.tar")
        result = runner.invoke(app, ["check-backup", str(out), "--max-age-hours", "1" * 400])
        assert result.exit_code == 2, result.output
        assert "--max-age-hours" in result.output + str(result.stderr or "")
