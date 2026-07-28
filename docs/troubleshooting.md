# Troubleshooting — common issues

Operational problems you may hit running Blacksea, and how to fix them. Each entry is self-contained: a symptom, the cause, and the remediation. New issues are appended as their own section — start from the table of contents.

- [Postgres: `password authentication failed` (credential drift)](#postgres-password-authentication-failed-credential-drift)

## Postgres: `password authentication failed` (credential drift)

**Symptom.** `blacksea status` reports Postgres as down and the brain will not connect, with an error containing `password authentication failed for user "blacksea"`. The NATS side is fine. It can appear right after you re-ran `make init`, moved/regenerated `config/blacksea.env`, or brought the stack up on a machine that already had an old Postgres data volume. `blacksea up` and `make init` may also print a `⚠` note warning that a Postgres data volume already exists but the freshly minted password will not match it.

**Cause.** This only affects docker mode (`BS_INFRA=docker`, where Blacksea runs Postgres itself). The official `postgres` image applies `POSTGRES_PASSWORD` **only once** — at the very first initialization of its data directory, which lives in the `pg_data` Docker volume. On every later start it finds an already-initialized data directory and **ignores `POSTGRES_PASSWORD` entirely**; the accepted password is now the one baked into the role inside that volume. So if the password in `config/blacksea.env` is regenerated (a `make init ARGS="--force"`, or deleting the config and re-initializing, or the config file moving to a new location so init can no longer carry the old password forward) while the original `pg_data` volume is still around, the config file and the database silently diverge: the brain and console read the new password from the config, but the running role still expects the old one. The result is `password authentication failed`. (External mode — `BS_INFRA=external`, where you run your own Postgres — cannot hit this: Blacksea never generates or re-applies those credentials.)

**Confirm it is this.** Check whether the password currently in your config authenticates against the running database. From `services/`:

```bash
PW=$(grep '^POSTGRES_PASSWORD=' config/blacksea.env | cut -d= -f2)
PGPASSWORD="$PW" docker compose --env-file config/blacksea.env exec -T postgres \
  psql -h 127.0.0.1 -U blacksea -d blacksea -c 'select 1'
```

If that fails with `password authentication failed` but the container is otherwise healthy (`docker compose ... ps` shows it up, `docker compose ... logs postgres` shows it accepting connections), you have credential drift. You can also see which data volume is in play with `docker volume ls | grep pg_data` — the live one for this stack is `<project>_pg_data` (by default `services_pg_data`).

**Remediation.** Pick one of the two options below depending on whether you need to keep the data currently in the database.

### Option A — re-sync the role password (non-destructive, keeps your data)

Rewrite the running role's password to match the config, in place. This works even though you do not know the old password, because Blacksea's Postgres accepts local (Unix-socket) connections inside the container with `trust`, so `docker compose exec` can run `ALTER ROLE` without authenticating. From `services/`:

```bash
NEW_PW=$(grep '^POSTGRES_PASSWORD=' config/blacksea.env | cut -d= -f2)
docker compose --env-file config/blacksea.env exec -T postgres \
  psql -U blacksea -d blacksea -c "ALTER ROLE blacksea PASSWORD '$NEW_PW'"
```

(If you set a non-default `POSTGRES_USER`, substitute it for `blacksea` in both places.) Then `blacksea up` and `blacksea status` should show Postgres healthy again, with all existing records, catalog, and health data intact.

### Option B — delete the volume and bring the stack up fresh (destructive, wipes the database)

If you do not need the data in the database — for a dev stack this is usually just test records and the control-plane catalog, which the brain recreates on start — recreate the volume so Postgres re-initializes from scratch with the current config password. This is the cleanest fix; it just throws away everything in the database. From `services/`:

```bash
docker compose --env-file config/blacksea.env down -v   # stops the containers AND deletes the volumes (the -v)
blacksea up                                             # fresh init: Postgres now bakes in the current config password
```

The `-v` is the important part — a plain `docker compose down` (or `blacksea down --infra`) preserves the volume and the drift persists. After `blacksea up`, verify with `blacksea status`; the config password now matches because the volume was initialized from it. (`blacksea reset` is **not** a substitute here: it wipes records/catalog/key-directory state but deliberately leaves the credentials and the containers/volume untouched, so it cannot resolve a password mismatch.)

**Avoiding it.** Keep `config/blacksea.env` in place — it is the source of truth for the credentials the running volume was created with. If you deliberately rotate the Postgres password, rotate the volume with it (Option B), or immediately re-sync the running role (Option A); do not regenerate the config password on its own and leave the old volume behind.
