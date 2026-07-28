# db-restore runbook

dbops nightly backups. Each nightly run dumps the prod/staging databases and writes an
encrypted `.dbk` to `dist/`. To open a backup locally (repro, schema diff, point-in-time
lookups), grab the `db-restore` binary from the **same build's** artifacts and run
`db-restore info <file>` to confirm the snapshot, then `db-restore restore <file>` to
materialize it. The binary and the backup from one build are paired — use a matching
build. Retention: last 14 nightly builds.
