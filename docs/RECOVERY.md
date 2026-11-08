# Recovery runbook

Recoverage normally reads live Rebrew project inputs. Its refresh operation
writes no project files. Preserve source, configuration, inventories, layout
packages, function/data/type metadata and reference binaries through the project’s
own version control and backups. `recoverage backup` never backs up that project.

## The state inventory

| State | Owner | Recovery |
|---|---|---|
| Function identities, verdicts and `status_history` | Rebrew function metadata | Restore the canonical project store |
| Data identities and verification evidence | Rebrew data metadata | Restore the canonical project store |
| Binary, inventory, source and layout evidence | Project | Restore the matching project inputs |
| Portable `coverage-<target>.toml` exports | Explicit snapshot directory | Verified `recoverage backup` / `restore` |
| Referenced original binaries and source roots named in `metadata.paths` | Explicit snapshot directory (must be inside it) | Archived flat beside the documents; `backup` refuses a set whose referenced file is absent, escaping, or name-colliding, because a restore without it serves the map but not `/asm` or the source pane |
| Parse caches and in-process memos | Recoverage | Rebuilt on demand |
| Retained ops inputs: staged files, the selected binary, and any temp snapshot a call builds under the ops workspace | `RECOVERAGE_OPS_FILESTORE` / `RECOVERAGE_OPS_WORKSPACE` (`recoverage ops call`/`serve`) | Not covered by `recoverage backup`; the backend that staged them re-supplies them, so losing the store loses in-flight work, not coverage history |

The ops workspace holds scratch: a retained snapshot is a temp directory
under it, removed when the call returns. Its loss mid-call aborts the call
rather than corrupting a served document. The filestore is the backend's
object store, keyed by retained keys and hashed on read; treat it as
ephemeral input, never as the record — the record is the backend's own
retained manifest. Neither directory is archived by `recoverage backup`,
and neither needs to be for a restore to be honest: a restore that
claimed them would be claiming bytes it never read.

Before retiring older exports, run
`rebrew coverage import-history --snapshots <directory> --dry-run`, review the
counts, then run the same command without `--dry-run`. This preserves historical
transitions without changing current verdicts. Keep the original exports until
that import and the resulting live view have been checked.

## Recovery procedures

For a live project, restore damaged inputs from a matching project backup and run
`recoverage check --json`. Input changes refresh the view automatically;
`recoverage regen` requests an immediate read. A missing or corrupt target is
reported explicitly, while healthy targets remain available. Never restore a
portable export over a canonical metadata file.

For explicit offline snapshots, select their directory for each operation:

```bash
RECOVERAGE_SNAPSHOTS=/srv/snapshots recoverage backup --to /srv/backups/nightly.tar
RECOVERAGE_SNAPSHOTS=/srv/restored recoverage restore /srv/backups/nightly.tar
RECOVERAGE_SNAPSHOTS=/srv/restored recoverage check --json
```

Restore validates every member before publishing files. Existing differing
files require `--force`; review the named files before choosing to replace them.
Stop readers during restore. A handled write failure rolls earlier replacements
back; if rollback also fails, the error names the directory retaining the original
files. A process or machine crash can leave a `.restore-*` directory behind;
restore refuses while one is present — its `previous/` files are the only copy of
the pre-restore documents, so inspect them, restore those files by hand if needed,
remove the directory, then retry before serving the exports.
Offline readers detect restored files automatically. `regen` refuses offline
mode because only Rebrew can derive a fresh export from the original inputs.

## RPO and RTO

RPO is the backup cadence: with the nightly schedule below, a portable export
can be up to 24 hours old at restore time, plus whatever ``metadata.paths``
inputs were copied into the snapshot between runs. The schedule is the only
bound — there is no point-in-time recovery inside this package, so logical
corruption (bad code writing bad data for hours) is recovered by restoring
the oldest archive that predates it, not by replaying transactions. RTO is
measured, not assumed: run the drill against a copy of the production-sized
snapshot, record the elapsed time, and budget that figure plus the time to
copy the archive from its volume. A portable archive cannot recover project
inputs it never contained — canonical metadata, source, configuration and
unreferenced binaries are outside it by design (see below), and a backup
refuses to claim otherwise.

## Backup schedule

Use a separate backup volume and state the schedule’s time zone explicitly:

```cron
CRON_TZ=UTC
17 3 * * * RECOVERAGE_SNAPSHOTS=/srv/snapshots RECOVERAGE_BACKUP_DIR=/srv/backups recoverage backup --json >> /var/log/recoverage-backup.log 2>&1
```

The archive is verified before success is reported. On hosts whose cron lacks
`CRON_TZ`, configure the daemon’s time zone explicitly. Archive timestamps use UTC.
Keep the backup volume separate from the snapshot directory: a destination inside
the coverage directory is refused, because an archive there shares its failure
domain with the data it protects (one directory deletion removes both). Alert on
the job itself — a missing log line or a non-zero exit is a missed backup, and an
empty coverage directory exits 1 rather than writing an empty archive. The job
exiting 0 only while it runs means a job that stops running fails nothing, so
monitor the backup directory too:

```cron
CRON_TZ=UTC
30 4 * * * recoverage check-backup /srv/backups
```

`check-backup` exits 1 when the backup directory does not exist, holds no
stamped archive, or its newest archive is older than `--max-age-hours`
(default 25, one missed nightly run plus an hour of slack). A schedule that
runs less often than daily passes its own `--max-age-hours`. Between
drills, run `recoverage verify /srv/backups/nightly.tar` to re-prove an archive
older runs wrote or that was copied to another volume; it writes nothing and
needs no `RECOVERAGE_SNAPSHOTS` selection.

## Restore drills

Run a drill against a fresh directory, leaving the live source untouched:

```bash
drill=$(mktemp -d)
RECOVERAGE_SNAPSHOTS="$drill/snapshots" recoverage restore /srv/backups/nightly.tar
RECOVERAGE_SNAPSHOTS="$drill/snapshots" recoverage check --json
```

Record the archive, elapsed time and document count, then remove the drill
copy after inspection. A successful `tar -tf` alone does not exercise validation.

## Recovering without this tool

Archives are POSIX tar files containing flat members — the `coverage-<target>.toml` documents,
any referenced original binaries or source files the documents named, and `manifest.json`.
Extract into an offline snapshot directory. The manifest records each member’s size and
SHA256; verify those digests before serving restored data.

## What is deliberately not covered

Recoverage backup excludes canonical project metadata, source, reference binaries,
configuration, build output, caches, and the ops filestore/workspace above.
Back up those through their owning project or backend.
