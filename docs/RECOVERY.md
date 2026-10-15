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
| Parse caches and in-process memos | Recoverage | Rebuilt on demand |

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
Offline readers detect restored files automatically. `regen` refuses offline
mode because only Rebrew can derive a fresh export from the original inputs.

## RPO and RTO

The backup schedule and retention determine the recovery point. Measure restore
time against a copy to establish the recovery time; neither is bounded by the
software. A portable archive cannot recover project inputs it never contained.

## Backup schedule

Use a separate backup volume and state the schedule’s time zone explicitly:

```cron
CRON_TZ=UTC
17 3 * * * RECOVERAGE_SNAPSHOTS=/srv/snapshots RECOVERAGE_BACKUP_DIR=/srv/backups recoverage backup --json >> /var/log/recoverage-backup.log 2>&1
```

The archive is verified before success is reported. On hosts whose cron lacks
`CRON_TZ`, configure the daemon’s time zone explicitly. Archive timestamps use UTC.

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

Archives are POSIX tar files containing flat `coverage-<target>.toml` members and
`manifest.json`. Extract into an offline snapshot directory. The manifest records
each member’s size and SHA256; verify those digests before serving restored data.

## What is deliberately not covered

Recoverage backup excludes canonical project metadata, source, reference binaries,
configuration, build output and caches. Back up those through their owning project.
