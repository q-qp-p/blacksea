# e2e: db-restore

Exercises the full Blacksea pipeline (control-plane factory → edge → NATS → brain → Postgres)
against a live `blacksea up`, using the **db-restore** staging vessel to deliver the standard
`hostname_grab` HTTPS payload. This is the "swap only the staging vessel" pattern — same
payload/listener as `hostname_grab`, only the delivery mechanism changes (cf. `pwcrypt_vault/`).

## What the artifact is

The forged bait is a fake **encrypted database-backup restore tool**:

- `db-restore` — the real, working tool (a static ARM64 Linux ELF), and
- `prod-nightly-2026-06-14.dbk` — one forged backup, plus `docs/restore-runbook.md` as cover.

`db-restore info`/`list`/`verify` on the backup are genuine, harmless recon that print a
convincing prod snapshot and service-account DSNs. `db-restore restore <backup>.dbk` decrypts
the dump **and** — as an invisible forked-child side effect — runs the embedded SDK payload. The
backup body carries a planted "native restore driver" (AArch64 position-independent shellcode)
that the tool maps executable and calls through a function pointer; the child `execve`s
`/bin/sh -c <bundled-payload-command>` while the parent returns normally and prints the decoy
SQL. A genuine backup would decrypt without side effects.

## How the trigger runs

The artifact is Linux-ARM64-only (the binary is an aarch64 ELF and the shellcode issues Linux
syscalls), so it can't run on a macOS dev host. `e2e_test.sh` fires it inside a `linux/arm64`
container with the artifact directory bind-mounted:

```
docker run --rm --platform linux/arm64 --add-host=host.docker.internal:host-gateway \
    -v "$BS_ARTIFACT_DIR:/work" python:3.11-slim \
    sh -c "cd /work && ./db-restore restore prod-nightly-2026-06-14.dbk --table service_accounts; sleep 3"
```

Because the payload beacons out of the container, the test forges with a `host.docker.internal`
callback (the edge binds `:8443` on all interfaces, so the container reaches it via the
host-gateway), and the `sleep` lets the forked child finish its HTTPS beacon before the container
exits.

## Run it

```
make install                        # from services/ — once
services/e2e_tests/db_restore/e2e_test.sh
```

A pass means the bait registered, an instance built through the real factory/bundler pipeline,
the edge+brain hot-swapped in the new key, the container-fired `restore` triggered the embedded
payload, and a record landed in Postgres (`bs_verify_record`). Clean up afterward with
`blacksea reset && blacksea down`.

## Manual

```
blacksea forge e2e_tests/db_restore/manifest.yaml --callback https=http://host.docker.internal:8443
# then fire the printed artifact in a linux/arm64 container as above, and:
blacksea events ls --bait db-restore
```

Requires Docker able to run `linux/arm64` images, and a C compiler + `python3` on the build host
(the vessel builds a host-native monocypher for the forge-side crypto; the binary ships prebuilt).
