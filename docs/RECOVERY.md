# Recovery runbook

What survives, what is lost, and how to get it back. Written from what this
tree actually does; every command below is one this package ships.

## The state inventory

Everything recoverage writes, and what it is worth:

| State | Where | Rebuilt from a `regen`? | Backed up by `recoverage backup`? |
|-------|-------|------------------------|-----------------------------------|
| Coverage documents | `db/coverage-<target>.toml` | **partly** — see below | **yes** |
| Status history | inside each document (`history`) | **no** — carried forward from the previous document | **yes** |
| Verify results | inside each document (`verify_results`) | **no** — carried forward the same way | **yes** |
| Parse cache | `$XDG_CACHE_HOME/recoverage/documents/` | yes, on first read | no (correctly: derived) |
| In-process memos, ETags | the serving process | yes, per stat | no (correctly: derived) |
| Regen lock | `db/.recoverage-regen.lock` | released by the OS when its holder exits | no (correctly: an empty lock) |

**The coverage documents are the only durable state, and they are only partly
rebuildable.** rebrew's `write_coverage_toml` reads the previous document and
merges into it: `history` accumulates the status-delta chain across every
build, and `verify_results` carries the last verification forward. Both come
from the file being overwritten, not from the source tree. So:

* the **facts** — sections, cells, functions, globals — come back from a regen
  against the built binaries;
* the **history and the verify results** come back only from a copy of the
  previous document.

Losing the documents therefore does not mean losing the coverage map; it means
losing every status transition before the rebuild and every verification since
the last one. That is what the backup is for.

## RPO and RTO

Neither is bounded by the software. A regen restores the facts in as long as
the catalog analysis takes on that target; the history and verify results are
recoverable only as far back as the oldest backup that still verifies.

So the numbers are deployment decisions, and these are the questions to answer
before choosing them:

* **RPO** is the age of the newest archive you can still restore. It is the
  schedule of `recoverage backup`, plus how long the storage holding the
  archives keeps them. A nightly cron means an RPO of one build's work; a
  backup run on every regen means an RPO of one regen.
* **RTO** is how long the restore takes: the archive is read, verified and
  written whole, so it scales with the size of the coverage documents, not
  with the size of the binaries. Measure it once with
  `recoverage restore <archive>` against a copy — that run is also the restore
  drill (below).

## Recovery procedures

### A target's document is missing, truncated or corrupt

1. Find the newest archive holding it:
   ```bash
   tar -tf backups/coverage-*.tar | grep coverage-<target>
   ```
2. Restore it. A missing file is restored without complaint; a file that is
   *present but differs* is a refusal, which is the case where you want to read
   the message:
   ```bash
   recoverage restore backups/<newest>.tar
   ```
3. If the refusal names a document you mean to lose, re-run with `--force`:
   ```bash
   recoverage restore backups/<newest>.tar --force
   ```
4. `recoverage regen`, so the served snapshots and ETags follow the restored
   bytes. A running server notices on its own through the document watcher,
   but a regen also re-derives anything the build changed.

### The whole coverage directory is gone

1. The directory itself is not state. Recreate it wherever the project expects
   it, or point at the restore with `RECOVERAGE_DB`:
   ```bash
   mkdir -p db
   RECOVERAGE_DB="$PWD/db" recoverage restore backups/<newest>.tar
   ```
2. `recoverage regen` to bring the facts back to the current binaries, which
   restores the coverage map even when no archive survives.
3. Only the history and verify results need the archive, and only up to the
   age of its newest verified member.

### The binary is gone but the coverage is not

The documents outlive the binaries they describe, which is the point of backing
them up: `/api/targets/<target>/data`, the map and Potato Mode all read the
document. Restore the binary and re-run the regen to refresh the facts.

### Recovering without this tool

The archive is a POSIX tar, so:

```bash
tar -xf backups/<archive>.tar db/            # or extract a single member
cat <(tar -xOf backups/<archive>.tar manifest.json)
```

`manifest.json` carries each member's size and sha256, so `sha256sum` on the
extracted files is the same check `recoverage restore` makes before it writes
anything.

## Backup schedule

The archive is written by `recoverage backup`, which verifies it before
reporting success — the exit code says the archive can be read back, not that a
write returned. Run it whenever the coverage documents change:

```cron
17 3 * * *  cd /srv/project && RECOVERAGE_BACKUP_DIR=/srv/backups recoverage backup --json >> /var/log/recoverage-backup.log 2>&1
```

**The schedule is the RPO.** Put `RECOVERAGE_BACKUP_DIR` on a different volume
from `db/` — a different disk, or a different host — or the backup protects
against nothing that taking the coverage directory down would not take with it.
Within one host and one filesystem, a mistaken `rm -rf db/` still reaches it.

## Restore drills

An unrestored backup is a hypothesis. Run this on a schedule (monthly is
typical), against a copy rather than the live directory:

```bash
drill=$(mktemp -d)
RECOVERAGE_DB="$drill/db" recoverage restore /srv/backups/<newest>.tar
recoverage stats --json            # exits 2 if nothing parses
recoverage regen                   # optional: the facts follow from the binaries
rm -rf "$drill"
```

`recoverage restore` verifies every member before it writes the first byte, so
a drill on a copy exercises the whole verification path — the same one a real
incident runs. A drill that only lists the archive with `tar -tf` does not.

Record the result: which archive, how long it took, how many documents. That
number is the measured RTO above, and it is the one to compare against when
the archive has grown.

## What is deliberately not covered

* **The parse cache and the in-process memos.** Both are rebuilt from the
  documents on first read. A backed-up cache would restore stale parses of
  documents the backup did not have.
* **The binaries under the project's `bin/`.** They are build output; a regen
  rebuilds them from source, which is a different backup's problem.
* **`rebrew-project.toml`.** It is tracked in the project's own repository.
  If it is not, the restore has documents but no project, and
  `recoverage config` will say so before anything is served.
