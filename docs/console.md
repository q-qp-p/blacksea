# The `blacksea` operator console

`blacksea` is the single operator entry point for a running Blacksea deployment. Once the core infra (edge → NATS → brain → Postgres) is up, one command lets you check the health of the running system, register and forge baits, drive the lifecycle of deployed instances, watch events land live, inspect health, and run the OTLP telemetry emitter.

Its shape: **objects are command groups, and the hottest verbs are promoted to the top level** (`blacksea status`, `blacksea forge`); every command speaks `--json` for scripting, and errors go to stderr with meaningful exit codes.

- [Install & run](#install--run)
- [The mental model](#the-mental-model)
- [Global options](#global-options)
- [`init` — choose the infra mode](#init--choose-the-infra-mode)
- [Lifecycle — `up` / `down` / `logs` / `reset`](#lifecycle--up--down--logs--reset)
- [`status` — is the infra up?](#status--is-the-infra-up)
- [Baits & instances (the lifecycle)](#baits--instances-the-lifecycle)
- [`forge` — register → build → approve in one shot](#forge--register--build--approve-in-one-shot)
- [Events, sessions & health](#events-sessions--health)
- [Deploying an artifact](#deploying-an-artifact)
- [OTel telemetry control](#otel-telemetry-control)
- [`config` & `campaigns`](#config--campaigns)
- [JSON output & scripting](#json-output--scripting)
- [Exit codes & errors](#exit-codes--errors)
- [Command reference](#command-reference)

---

## Install & run

The console ships as an installed console-script. `make install` creates the project venv, installs the console (+ everything else), and symlinks the `blacksea` command into `~/.local/bin` so it is on your PATH in any shell — **no venv activation needed**:

```bash
make install                 # from services/ — creates .venv, installs, and links `blacksea` onto PATH
blacksea --help              # works in any shell; no `source .venv/bin/activate`
```

If `~/.local/bin` isn't on your PATH, `make install` prints the one line to add to your shell rc. Point the symlinks elsewhere with `make install BINDIR=/usr/local/bin`, and remove them with `make uninstall` (leaves `.venv` in place).

The venv is built from whatever `python3` resolves to on your PATH. To pin a different interpreter — Blacksea needs **Python 3.11 or newer** — pass `PYTHON=`:

```bash
make install PYTHON=python3.12                  # a specific minor version on your PATH
make install PYTHON=/usr/local/bin/python3.11   # or an explicit interpreter path
```

There are three equivalent ways to invoke it:

| Form | When |
|---|---|
| `blacksea …` | interactive use — on PATH after `make install` |
| `.venv/bin/blacksea …` | the venv script directly, without relying on the PATH symlink |
| `python -m blacksea.console …` | the module form — any environment where the `blacksea` package is importable (e.g. the editable install) |

First run **`make init`** to choose how Blacksea gets Postgres + NATS (see [`init`](#init--choose-the-infra-mode) below); it writes the unified `config/blacksea.env`, which the console (and everything else) reads.

Anything that touches the database (`status`, `events`, `baits`, …) needs a Postgres DSN. The console resolves it in this order: the **`--postgres`** flag, then **`$POSTGRES_DSN`**, then the DSN in **`config/blacksea.env`**. So from a checkout where you've set up your config, a bare `blacksea status` just works — no need to export anything. `blacksea config show` reports the infra mode (`BS_INFRA`), which config file was loaded, and where the DSN came from. For a deployment, set `POSTGRES_DSN` (or pass `--postgres`) and it wins outright. The console is also the **front door for bringing the stack up**: `blacksea up` (docker mode drives `docker compose` for Postgres + NATS and starts the edge + brain; external mode verifies your infra and starts the daemons) plus `down`/`logs`/`reset` (see [Lifecycle](#lifecycle--up--down--logs--reset)). `status` reports whether it is up.

> **A localhost operator tool.** The console has no built-in authentication — the host it runs on is the trust boundary. Run it on your trusted plane (for example, behind your VPN), not on an internet-exposed machine.

---

## The mental model

```
blacksea <noun> <verb> [args] [--json]
blacksea <verb> [args] [--json]          # status / forge / health are promoted to the top level
```

- **Designs** (`baits`) are bait definitions in the catalog. You **register** a bait directory to create one.
- **Instances** (`instances`) are per-deployment children of a design — each with its own key and token. You **build** one (→ `pending`), **approve** it (→ `active`, key published to the brain), and later **burn** / **retire** / **revoke** it.
- **`forge`** collapses register → build → approve into one call from a self-sufficient manifest.
- **Events** (`events`) are the intel Records the brain assembles from hits; **sessions** and **health** are read-time views over them.

---

## Global options

Global options go **before** the command; `--json` also works **after** any command (see [JSON output](#json-output--scripting)). Each resolves from the flag, then its env var, then a default.

| Option | Env | Purpose |
|---|---|---|
| `--postgres` | `POSTGRES_DSN` | catalog + event store DSN (required for anything touching the DB) |
| `--registry` | `BS_REGISTRY` | registry filesystem root (parent of `artifacts/`) |
| `--schema` | `BS_CP_SCHEMA` | control-plane catalog schema (default `control_plane`) |
| `--artifacts-root` | `BS_ARTIFACTS_ROOT` | build-artifact output root |
| `--brain-keydir` | `BS_BRAIN_KEYDIR` | brain key directory (the sole key directory) |
| `--sdk-root` | `BS_SDK_ROOT` | bundler vendor root |
| `--nats` | `NATS_URL` | NATS URL for the `status` probe |
| `--otel-env` | — | otel emitter config file (default `secrets/otel.env`) |
| `--otel-unit` | — | where `otel install-unit` writes (default `secrets/blacksea-otel.service`) |
| `--edge-dns` / `--edge-https` | — | edge addresses for the `status` probe (dev defaults `:15353` / `:8443`) |
| `--edge-separate` | — | the edge runs on a separate network — don't probe it locally |
| `--secrets` | — | path to the secrets env file the DSN falls back to (default `secrets/env`) |
| `--json` | — | emit raw JSON instead of tables |

---

## `init` — choose the infra mode

Run once, before anything else. `init` asks the single question that forks the system — *how should Blacksea get its Postgres + NATS?* — and writes the unified **`config/blacksea.env`** (the one flat `KEY=VALUE` file Make, the Python apps, docker-compose, and `blacksea up` all read). It needs no database, so it works on a fresh checkout. **`make init`** from `services/` is the front door; pass flags through with `ARGS="…"`:

```bash
make init                                   # interactive: pick docker or external
make init ARGS="--docker -y"                # non-interactive: Blacksea runs Postgres + NATS in containers
make init ARGS="--external \
  --postgres-dsn 'host=db.internal port=5432 dbname=blacksea user=bs password=…' \
  --nats-url nats://nats.internal:4222 --nats-user u --nats-pass pw"   # infra you run yourself; validated before saving
```

- **docker** — generates random credentials (or **reuses** ones already on disk, so an existing Postgres data volume keeps working) and writes `BS_INFRA=docker` + the localhost coordinates. This is the quickstart default; `blacksea up` writes the same file if you skip `init`.
- **external** — takes an opaque `POSTGRES_DSN` + `NATS_URL`/creds (+ optional TLS: `--nats-ca` / `--nats-cert` / `--nats-key`), **validates Postgres + NATS reachability before saving** (skip with `--no-validate`), and writes `BS_INFRA=external`. Blacksea connects to those services and never provisions or overwrites the credentials.

`init` refuses to overwrite an existing `config/blacksea.env` unless you pass `--force`. Every prompt is flag-overridable and `-y`/`--json`/non-TTY runs are non-interactive (default docker), so CI never blocks. Run `blacksea config show` afterward to confirm the mode (`BS_INFRA`) and the loaded file (`BS_CONFIG_PATH`).

Unlike every other command on this page, `init` is the one you drive through Make rather than directly — it's the bootstrap step that runs before the console has a config to read, so it doesn't appear in `blacksea --help`. If you installed Blacksea with `pip` rather than from a checkout with the Makefile, `blacksea init` still accepts exactly the flags shown above.

> `init` only writes the config — it does **not** start anything. Bring the stack up with
> [`blacksea up`](#lifecycle--up--down--logs--reset).

---

## Lifecycle — `up` / `down` / `logs` / `reset`

The local stack lifecycle — the single entry point for bringing the local stack up and down. These verbs are **local** (they manage the daemons on *this* host) and read the infra mode from `config/blacksea.env`.

```bash
blacksea up            # bring the whole stack up
blacksea logs          # tail the edge + brain logs together (Ctrl-C to stop)
blacksea down          # stop the daemons; --infra also stops the containers
blacksea reset         # wipe test state (records/catalog/artifacts/keydir/NATS); keeps creds + infra
```

**`blacksea up`** is idempotent — safe to re-run any time (a daemon already running with the same config is left alone; a changed config restarts it).

- **Docker mode** — runs `docker compose up -d` for Postgres + NATS, waits until Postgres is ready, builds the edge binary (`go build`), then starts the edge + brain as detached background daemons under `.dev/`. Auto-writes a docker-mode `config/blacksea.env` if you never ran `init`.

  ```
  mode: docker
    infra  postgres blacksea@blacksea … ready
    infra  nats … up   (docker compose)
  daemon   pid     state
  edge     82773   started (pid 82773)
  brain    82774   started (pid 82774)
    edge     DNS :15353   HTTPS :8443
    next     `blacksea status` to verify health · `blacksea forge <manifest>`
  ```

- **External mode** — never touches your Postgres/NATS: it **verifies** both are reachable and, if either is down, starts **nothing** and fails specifically.

**The edge on a separate network.** The edge is a dead-drop that needs only NATS reachability, so it can run on a different network from the brain. Pass `--edge-separate` (globally) on the **brain host** and `up` manages the brain only — the edge is neither built nor started there. On the **edge host**, `blacksea up --edge-only` builds and starts just the edge, pointed at the remote `NATS_URL` (with any `NATS_CA`/`NATS_TLS_*` from the config passed through for the TLS hop) — no infra, no brain.

**Flags.** `up --infra-only` (bring up just Postgres + NATS, no daemons — the lightweight path for `make test`), `up --no-infra` (assume Postgres + NATS are already up), `up --no-build-edge` (skip the `go build`), `up --edge-only`; `down --infra` (also stop the docker containers, docker mode); `logs --no-follow` (print current logs and exit); `reset --yes` (skip the confirmation — required under `--json`/non-TTY) and `reset --no-purge-nats`.

> `reset` is destructive (it clears all records, the catalog, the material store, the brain key
> directory, and the NATS backlog) but **keeps** the credentials in `config/blacksea.env` and the
> Postgres/NATS containers — so there's no re-provisioning step: just `blacksea up` again. To also
> destroy the Postgres data volume, run `docker compose --env-file config/blacksea.env down -v`.

---

## `status` — is the infra up?

One labeled view of every core component's liveness.

```bash
blacksea status
```

```
                                  infra status
component ┃ status  ┃ source   ┃ detail
━━━━━━━━━━╇━━━━━━━━━╇━━━━━━━━━━╇━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
postgres  │ up      │ direct   │ SELECT 1 ok
brain     │ up      │ direct   │ heartbeat 3s ago, lag=0
nats      │ up      │ inferred │ localhost:4222 — listening (1ms)
edge      │ up      │ inferred │ dns 127.0.0.1:15353 up; https 127.0.0.1:8443 up
otel      │ unknown │ inferred │ no unit installed — run in the foreground with `blacksea otel run`,
          │         │          │ or `blacksea otel install-unit` for always-on
baits=4  instances=12  events=12  last_event_ms=1784199157278
```

The **`source`** column is the point: it tells you how much to trust each green.

- **direct** — authoritative. **Postgres** (`SELECT 1` + the system counts) and the **brain** are known facts. The brain reports via a heartbeat it writes to the database every few seconds, so a brain that has silently stopped consuming shows **`stale`** (heartbeat older than the threshold), never a false green.
- **inferred** — a liveness guess. **NATS** and the co-located **edge** are TCP-reachability checks: a listening port is not proof the service is healthy, only that something is listening.
- **unit** — an OS process-manager's own report (a systemd unit for the otel emitter, if installed).

`status` never fails — a dead component is a red/`unknown` row, not an error.

---

## Baits & instances (the lifecycle)

The manual, step-by-step path from a bait directory to a live instance. (For the one-shot version, see [`forge`](#forge--register--build--approve-in-one-shot).)

```bash
# 1. Register: ingest + validate + golden-test a bait directory, then stage it.
blacksea baits register test_fixtures/baits/hostname_probe

# 2. Build: generate the per-instance key + token, bundle the payload, run the staging vessel.
#    Result is a `pending` instance + a deployable artifact.
#    Omit --comment and you're prompted for a note (empty is fine); it's stored on the instance.
blacksea instances build hostname-probe --campaign C-2026Q2-alpha --callback dns=cb.example.com \
    --comment "target: honeypot-7, field-2026q3"

# 3. Approve: pending → active, and publish the instance key to the brain key directory.
blacksea instances approve <instance_token>
```

Inspect and list:

```bash
blacksea baits ls
blacksea baits show hostname-probe            # catalog row + manifest + instances (w/ comment + artifact path)
blacksea instances ls --bait hostname-probe   # filters: --bait / --campaign / --status; shows the comment
blacksea instances show <instance_token>      # incl. the operator comment + the to_stage/ deployable dir
```

Change instance state (operator-confirmed, never automatic):

```bash
blacksea instances burn   --instance <token> --reason "token seen in the wild"   # key/pool kept
blacksea instances burn   --design   hostname-probe                              # burn the whole design
blacksea instances retire --design   hostname-probe                              # irreversible stand-down
blacksea instances revoke <token>                                                # key weaponized
```

A `burn`/`retire`/`revoke` refreshes the brain key directory's routing, and the brain picks up the change on its next poll — no restart. `retire` is irreversible; a burned design keeps its pool worker so late hits are still recorded (as orphans).

---

## `forge` — register → build → approve in one shot

When a manifest carries a `deploy:` block (campaign + per-channel callbacks — see [`docs/bait-authoring.md`](./bait-authoring.md)), `forge` does the whole chain in one call:

```bash
blacksea forge e2e_tests/agent_fp/manifest.yaml

# Override the manifest's deploy defaults for a local test, or stop before approving:
blacksea forge e2e_tests/agent_fp/manifest.yaml \
    --campaign test --callback https=http://127.0.0.1:8443 --no-approve

# Attach a note recording *why* this instance was built (or omit --comment to be prompted):
blacksea forge e2e_tests/agent_fp/manifest.yaml --comment "campaign alpha, host bravo"
```

**Comment:** every create-a-bait command (`forge` and `instances build`) accepts a `--comment` free-text note. Leave it off in an interactive shell and you'll be **prompted** (press Enter to skip — empty is fine). It's stored on the instance and shown wherever the bait is visualized (`baits show`, `instances show`, `instances ls`, and `--json`). It's purely descriptive — it never affects the build, routing, or attribution. A manifest can also carry a default under `deploy.comment` (§ [`bait-authoring`](./bait-authoring.md)); `--comment` overrides it. Under `--json` or a non-interactive shell the prompt is skipped, so scripts never block.

`forge --json` emits a machine-readable line including the `artifact_path` — the deployable file you ship to a honeypot — and the `comment`.

---

## Events, sessions & health

**List and inspect** the intel Records the brain assembled:

```bash
blacksea events ls                              # newest first
blacksea events ls --bait hostname-beacon --limit 20
blacksea events ls --instance <token> --no-sig-valid    # only bad-signature hits
blacksea events show <record_id>                # full record incl. signals + details
```

**Follow live** — seeds from "now" and streams new records as they land, Ctrl-C to stop:

```bash
blacksea events tail
blacksea events tail --bait hostname-beacon --interval 1
```

**Sessions** — a read-time grouping of records that share an instance + session id:

```bash
blacksea sessions ls
blacksea sessions ls --campaign C-2026Q2-alpha
```

**Health** — hit-rate over time + the caution-level distribution (burn-detection input):

```bash
blacksea health                          # default 1h buckets over all records
blacksea health --bait hostname-beacon --since 24h --bucket 900
```

`--since` takes a duration: `24h`, `90m`, `3600s`, or bare seconds.

> A record's `details` field is attacker-controlled diagnostic data. The console renders it as **data**, never interprets it — treat it accordingly.

---

## Deploying an artifact

`instances build` / `forge` produce a deployable under a timestamped build directory. To find what you actually ship to a honeypot:

```bash
blacksea instances artifact <instance_token>
```

```
╭─ artifact for f92cae98b0d9fa70 ──────────────────────────────────────────────╮
│ instance_token    f92cae98b0d9fa70                                           │
│ bait_id           hostname-beacon                                            │
│ status            active                                                     │
│ primary_file      bait.py                                                    │
│ sha256            fc123c4bb5a84a3c01bb6b5d…                                   │
│ to_stage_dir      …/registry/artifacts/hostname-beacon/20260716-…/to_stage   │
│ output_dir_root   …/registry/artifacts/hostname-beacon/20260716-…            │
│ ready_for_vessel  <the bundler's ready-to-run one-liner>                     │
╰──────────────────────────────────────────────────────────────────────────────╯
```

`to_stage_dir` is the directory operators deploy; `ready_for_vessel` is the bundler's one-liner command string. The paths are absolute **build-host** paths — they don't resolve unchanged on another machine.

---

## OTel telemetry control

The console owns the emitter's config and can run it, but it does **not** background-supervise it — durable "always-on" is the OS's job (see [`docs/otel-export.md`](./otel-export.md) for the full telemetry guide).

**Configure** (writes `secrets/otel.env`, validated against the known `BS_OTEL_*` keys):

```bash
blacksea otel config set BS_OTEL_ENDPOINT=http://localhost:4318 BS_OTEL_PROTOCOL=http/protobuf
blacksea otel config show
```

**Run in the foreground** (loads `secrets/otel.env`, streams logs, Ctrl-C stops):

```bash
blacksea otel run
```

**Emit an OS unit** for always-on running (systemd unit or a compose snippet with `EnvironmentFile=secrets/otel.env`):

```bash
blacksea otel install-unit                 # → secrets/blacksea-otel.service
blacksea otel install-unit --flavor compose
```

> **`config set` never affects a *running* emitter.** The emitter reads `BS_OTEL_*` once at startup;
> `set` applies to the **next** `otel run` / unit start. The command reminds you to restart the
> emitter to apply.

---

## `config` & `campaigns`

```bash
blacksea config show          # effective operational settings, read-only (secrets redacted)
blacksea campaigns ls         # instances aggregated by campaign_id
```

`config show` is read-only: most operational settings are resolved at process start and need a restart to change — the one exception is the otel config above. Secrets (the DSN password, NATS credentials) are masked.

---

## JSON output & scripting

Every command speaks `--json`. **List** commands emit a JSON **array**; **show**/status commands emit a JSON **object** — no envelope wrapper, so `jq` pipelines are clean:

```bash
blacksea events ls --json | jq '.[].source_ip'
blacksea status --json     | jq '.components[] | select(.status!="up")'
blacksea baits ls --json   | jq -r '.[] | .bait_id'
```

`--json` works both as a global flag and trailing on the command, so `blacksea --json events ls` and `blacksea events ls --json` are identical. It disables the rich tables and prints raw JSON to stdout.

---

## Exit codes & errors

The console follows Unix conventions — the error goes to **stderr**, the data to **stdout**, and the exit code tells a script what happened:

| Exit | Meaning |
|---|---|
| `0` | success |
| `1` | operational failure — a well-formed request that couldn't be applied (no such record, illegal transition, DB unreachable, build failed) |
| `2` | usage error — bad input you can fix (missing argument, both `--design` and `--instance`, unknown otel config key) |

A failed read is a **non-zero exit with a message**, never a silently empty table — so `blacksea events ls` failing because Postgres is down is distinguishable from there being no events.

---

## Command reference

```
make init [ARGS="…"]                   choose infra mode + write config/blacksea.env  [--docker|--external --force -y --config] (external: --postgres-dsn --nats-url --nats-user --nats-pass --nats-ca/-cert/-key --no-validate)
blacksea up                            bring the stack up (infra + edge + brain)  [--no-infra --no-build-edge --edge-only --infra-only]
blacksea down                          stop the daemons  [--infra also stops the containers]
blacksea logs                          tail the edge + brain logs together  [--no-follow]
blacksea reset                         wipe test state (keeps creds + infra)  [--yes --no-purge-nats]
blacksea status                        infra status (Postgres/brain/NATS/edge/otel + counts)
blacksea forge <manifest>              register → build → approve  [--campaign --callback k=v --set k=v --comment --no-approve --ack]
blacksea health                        hit-rate + caution distribution  [--bait --since --bucket]

blacksea baits ls
blacksea baits show <bait_id>
blacksea baits register <dir>          [--refresh --ack]

blacksea instances ls                  [--bait --campaign --status]
blacksea instances show <token>
blacksea instances build <bait_id>     --campaign C  [--callback k=v --set k=v --comment --out DIR]
blacksea instances approve <token>
blacksea instances burn                (--design <id> | --instance <token>) [--reason]
blacksea instances retire              (--design <id> | --instance <token>)
blacksea instances revoke <token>
blacksea instances artifact <token>

blacksea events ls                     [--bait --instance --campaign --sig-valid/--no-sig-valid --limit --offset]
blacksea events show <record_id>
blacksea events tail                   [--bait --instance --campaign --interval]

blacksea sessions ls                   [--bait --instance --campaign --limit --offset]
blacksea campaigns ls

blacksea otel run
blacksea otel config show
blacksea otel config set K=V ...
blacksea otel install-unit             [--flavor systemd|compose]

blacksea config show
```

Every command accepts `--json`. Run `blacksea <group> --help` for the full option list of any group.
