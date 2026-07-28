# Blacksea — operator guide

This is the in-depth guide to installing, running, and operating Blacksea. For what Blacksea is and why you'd use it — the lure technique, the vocabulary (bait, beacon, payload, listener, staging vessel, record), and the big picture — start with the [top-level README](../README.md). This guide picks up from there and covers the day-to-day: bringing the stack up, pointing it at your own infrastructure, deploying and managing baits, watching hits land, and streaming the intel to your SIEM.

Everything you operate runs through one command-line tool, `blacksea`. Run `blacksea --help` at any time for the full command tree, and `blacksea <command> --help` for any single command.

## Prerequisites

To install and operate Blacksea itself, your host needs four things:

- **Python 3.11 or newer** — the whole control system (SDK, payload bundler, brain, control plane, record read layer, web observer, SIEM export, console) is a single Python distribution.
- **`make`** — drives install, the config bootstrap, and the test suites.
- **Go 1.22 or newer** — the edge daemon is a Go binary. You don't build it by hand (`blacksea up` does that for you), but Go has to be present on whichever host runs the edge.
- **Docker**, with the **`docker compose`** plugin — Blacksea runs Postgres and NATS in containers by default. If you'd rather point Blacksea at Postgres and NATS you run yourself (**external** mode; see [Configuration](#configuration)), Docker isn't required to operate the stack.

Everything else is a Python package, and `make install` installs all of it into a project-local virtualenv at `services/.venv` — nothing to `pip install` by hand, and nothing touched in your system Python. On the *target* side there's nothing to install at all: a bundled payload is one self-contained file that runs on stock Python 3, with no Blacksea package and no third-party dependency present.

### Choosing which Python builds the virtualenv

`make install` builds the virtualenv with whatever `python3` resolves to on your PATH. When that isn't the interpreter you want — an older system Python, or several versions installed side by side — pass `PYTHON=` and Make uses that one instead:

```bash
make install PYTHON=python3.12                  # a specific minor version on your PATH
make install PYTHON=/usr/local/bin/python3.11   # or an explicit interpreter path
```

The same override works on every target that touches the virtualenv (`make init`, `make test`, `make test-e2e`). The virtualenv is created once and then reused, so to rebuild an existing one against a different interpreter, run `make clean` first.

### Optional extras

None of the following is needed to run Blacksea, catch hits, or read records — reach for one only when you want the thing it enables.

- **Building a compiled staging vessel.** Most baits ship as a plain script and need nothing extra. A vessel that delivers the bait as a *fake native binary* compiles that binary on your build host, so it needs its own toolchain there — see the table below.
- **Running the end-to-end suite in full** (`make test-e2e`). It forges each example bait for real, so on top of Docker it needs, on macOS, the **Xcode Command Line Tools**. Without those, the compiled-vessel example fails while the rest of the suite still runs.
- **Streaming to a SIEM over gRPC** instead of the default HTTP transport. Install the `otlp-grpc` extra: `pip install -e ".[otlp-grpc]"` from `services/`.

Staging-vessel toolchains, per vessel in [the bait catalog](../lure_material/README.md). All of these are *build-host* requirements — the artifact you plant is self-contained, and the target never needs a compiler:

| Staging vessel | Build host needs |
|---|---|
| `identity` | Nothing beyond `python3` — a pure-script vessel, no build step |
| `pwcrypt` | **Docker** for the Linux binaries (built inside Alpine containers, which fetch packages from the network at build time); on macOS, the Xcode Command Line Tools for the macOS binary |
| `db-restore` | A **C compiler** (`cc`; the Xcode Command Line Tools on macOS) to build the host-native crypto helper that forges the backup — the ARM64 binary ships prebuilt, so no Docker or cross-toolchain is needed to *build* the vessel. (Its e2e test additionally needs Docker able to run `linux/arm64` images, since the artifact is Linux-ARM64-only.) |

If you author your own vessel, it declares its own toolchain the same way — see [Authoring a bait](../docs/bait-authoring.md).

## Install and bring up the stack

```bash
cd services
make install    # installs the `blacksea` command onto your PATH
blacksea up     # brings up Postgres + NATS + the edge + brain
blacksea status # is the stack up and healthy?
```

To build the virtualenv with a specific interpreter, pass `PYTHON=` — e.g. `make install PYTHON=python3.12`.

`make install` puts `blacksea` (and the `bs-bundle` helper) on your PATH — no virtualenv to activate — and after it runs, `blacksea` works from **any** directory, not just inside `services/`.

`blacksea up` is safe to run any time and only starts what's missing: it brings up Postgres and NATS (in Docker, unless you've configured your own), builds the edge binary, and starts the edge and brain in the background. Re-running it after a reboot, or after stopping one process, brings back only what isn't already running. The edge listens for beacons on **DNS `:15353`** and **HTTPS `:8443`** — those are the ports a bait calls home to.

```bash
blacksea logs   # tail the edge + brain logs together
blacksea down   # stop the edge + brain (add --infra to also stop the containers)
```

## Configuration

All of Blacksea's operational settings — how it reaches Postgres and NATS, plus credentials, ports, and paths — live in one file, **`config/blacksea.env`**. Every value can be overridden by setting its environment variable, which takes precedence over the file, so you can tweak one setting for a single run (for example `DNS_ADDR=:53 DNS_ZONES=c.example.com blacksea up`) without editing anything.

There are **no default credentials**: nothing starts until that file exists. `blacksea up` writes a working docker-mode file for you on first run, but the front door for choosing how Blacksea gets its backing services is:

```bash
make init       # choose infra mode → writes config/blacksea.env
```

`make init` asks the one question that forks the system — **how should Blacksea get Postgres and NATS?** — and writes the file. There are two modes:

- **docker** (the default) — Blacksea runs Postgres and NATS for you in containers, generating fresh random passwords. Best for a lab or a single-host deployment.
- **external** — connect to Postgres and NATS you run yourself. You supply a DSN / URL and credentials; Blacksea validates that they're reachable and never overwrites them. In this mode `blacksea up` never touches your databases — it only starts the edge and brain.

To rotate the generated credentials, remove the file and re-run `make init`, then recreate the Postgres volume so it re-initializes with the new password:

```bash
rm -f config/blacksea.env
make init
docker compose --env-file config/blacksea.env down -v && blacksea up
```

## Run the edge on a separate network

The edge is a self-contained dead-drop: it holds no keys, decrypts nothing, and needs only network reachability to NATS. That lets you run it on a different — even untrusted — network from the brain: an internet-facing host in a DMZ receives the beacons and forwards them back to your trusted plane, so the machine most exposed to attackers holds none of your secrets. Splitting the stack across two hosts is built in:

- On the **brain host**, run `blacksea up --edge-separate`. `up` manages the brain and infrastructure only — it neither builds nor starts an edge — and `blacksea status` reports the edge as running elsewhere rather than as a failure it can't see.
- On the **edge host**, run `blacksea up --edge-only`. That builds and starts just the edge, pointed at your remote NATS (`NATS_URL`, with any `NATS_CA` / `NATS_TLS_*` from the config carried through for a TLS-protected hop). It needs no Postgres, no brain, and no database credentials.

Point both at the same NATS and a hit flows edge → NATS → brain → Postgres exactly as in the single-host case. Today the edge host needs the Blacksea checkout and Go so `up --edge-only` can build the edge in place; a prebuilt, containerized edge image you can drop onto a host is on the roadmap. See the [operator console guide](../docs/console.md) for the full separate-network walkthrough.

## Reset test state

`blacksea reset` clears everything a test run generates — registered baits, the brain's key directory, the Postgres records, and any backlog sitting in NATS — so you get a blank slate without re-provisioning anything. It keeps your `config/blacksea.env` credentials and the containers; it only wipes the *data*.

```bash
blacksea reset      # prompts for confirmation first
blacksea up         # bring the stack back up clean
```

Pass `-y` / `--yes` to skip the prompt for scripted or CI use. This is distinct from destroying the Postgres volume itself (`docker compose --env-file config/blacksea.env down -v`), which drops the database entirely.

## Deploy a bait

A bait goes from a design on disk to a live, listening trap through three steps — **register → build → approve**:

- **register** validates the bait's manifest and runs its golden tests offline, then stages the design in the catalog.
- **build** mints a new *instance* — its own secret key and token — bundles the payload with your campaign's callback addresses baked in, and runs the staging vessel to produce the deployable artifact you'll plant.
- **approve** flips the instance live. From that moment the brain will recognize and decrypt its beacons.

The one-shot **`forge`** command does all three from a manifest that carries a `deploy:` block:

```bash
blacksea forge e2e_tests/agent_fp/manifest.yaml
# Override the manifest's deploy defaults for a local test, or stop before going live:
blacksea forge e2e_tests/agent_fp/manifest.yaml --campaign test --callback https=http://127.0.0.1:8443 --no-approve
```

Or run the three steps by hand when you want more control:

```bash
blacksea baits register test_fixtures/baits/hostname_probe
blacksea instances build hostname-probe --campaign C-2026Q2-alpha --callback dns=cb.example.com
blacksea instances approve <instance_token>     # the token is printed by `build`
```

An approved bait goes live on its own — the brain re-reads its key directory on a short interval (about ten seconds) and picks up the new instance with **no restart** and nothing to touch on the edge. Inspect state at any time:

```bash
blacksea baits ls           # registered designs
blacksea instances ls       # built instances and their status
blacksea campaigns ls       # campaigns and their instances
blacksea events tail        # follow new hits live
```

When a bait's token turns up somewhere it shouldn't, or a campaign ends, retire it:

```bash
blacksea instances burn   --instance <instance_token> --reason "token seen in the wild"
blacksea instances retire --design   hostname-probe
blacksea instances revoke <instance_token>          # a key you believe is weaponized
```

`blacksea instances artifact <instance_token>` locates the built artifact on disk and prints how to plant and fire it.

## See a hit land

The friendliest end-to-end path — install → bring up → deploy a demo bait → watch the record arrive — is the [deploy-a-bait walkthrough](../docs/setup_a_bait.md). To drive the whole chain automatically (payload beacons over HTTPS → edge → brain → Postgres), the ready-made end-to-end tests double as runnable examples:

```bash
blacksea forge e2e_tests/agent_fp/manifest.yaml   # then fire the printed artifact
# …or run the whole scripted chain end to end:
./e2e_tests/agent_fp/e2e_test.sh
```

Either way, `blacksea events tail` shows the record land, and `blacksea events show <record_id>` opens it in full.

## Watch and query the intel

Every hit becomes a durable **record**. Read them from the console:

```bash
blacksea events ls          # recent records, newest first
blacksea events show <id>   # one record in full
blacksea sessions           # read-time groupings of related hits
blacksea health             # hit-rate over time + caution-level distribution
```

There's also a read-only web view — `blacksea web-ui` serves it at http://127.0.0.1:8000 (run it on demand; it isn't started by `blacksea up`).

## Stream events to your SIEM (OTLP)

Blacksea can push every record straight into your SOC / SIEM or observability stack over **OpenTelemetry (OTLP)**, instead of you polling the console or the web UI. The emitter is a standalone, read-only process, off by default: point it at an OpenTelemetry Collector (or any OTLP endpoint) you control and turn it on.

```bash
blacksea otel config set BS_OTEL_ENABLED=1 BS_OTEL_ENDPOINT=http://localhost:4318
blacksea otel run
```

Filtering (e.g. only high-caution events) and fan-out to specific backends are the Collector's job. The full guide — setup, the complete config surface, a working Grafana Loki integration, and routing to other backends — is in [SIEM export over OTLP](../docs/otel-export.md).

## Authoring a bait

A bait is three parts plus a manifest that ties them together:

- **`payload.py`** — runs on the target host and beacons home over DNS or HTTPS.
- **`listener.py`** — runs in the brain and decodes each beacon into a record. The payload and listener are two halves of one bait and must agree exactly; the golden tests catch any drift.
- **the staging vessel** (`setup.sh`) — wraps the bundled payload into the deliverable artifact you plant (a fake binary, a config file, …).
- **`manifest.yaml`** — references the three by path and carries the deploy settings `forge` uses.

Payloads, listeners, and staging vessels live in the shared catalog under [`../lure_material/`](../lure_material/), referenced by manifests wherever those live. [`test_fixtures/baits/hostname_probe/`](./test_fixtures/baits/hostname_probe/) is a small worked example. The complete, self-contained authoring guide — comms primitives, the listener API and types, golden tests, the manifest schema, the staging-vessel contract, and registration — is in [Authoring a bait](../docs/bait-authoring.md).

## Run the tests

```bash
make test        # all unit suites
make test-e2e    # real end-to-end tests: forge → fire → verify each bait (needs Docker)
```

`make test` runs with or without infrastructure up — the tests that need Postgres skip cleanly when none is reachable (run `blacksea up --infra-only` first for the full set). `make test-e2e` drives a live stack, so it needs Docker; it auto-discovers every example under `e2e_tests/` and fails if any fail. Two of those examples forge a *compiled* bait and so need their vessel's toolchain on the build host: `pwcrypt_vault` needs Docker, plus the Xcode Command Line Tools when you run it on macOS; `db_restore` needs a C compiler (the Xcode Command Line Tools on macOS) and Docker able to run `linux/arm64` images to fire its Linux-only artifact (see [Optional extras](#optional-extras)). Every other example is a pure-script bait with no extra toolchain.

Both targets honour the same `PYTHON=` override as `make install`.

## Command reference

Everything that **operates** the running system is a `blacksea` command; the Makefile covers only install/build/test tooling.

| `blacksea` command | Does |
|---|---|
| `up` / `down` / `status` / `logs` | Start / stop / inspect / tail the stack (`up --infra-only` = just Postgres + NATS; `down --infra` also stops the containers) |
| `reset` | Wipe test-generated data (baits, key directory, records, NATS backlog); creds + containers kept (`-y` skips the prompt) |
| `forge <manifest>` | Register → build → approve a bait from its manifest in one call |
| `baits` / `instances` / `campaigns` | Manage bait designs, per-deployment instances, and campaigns |
| `events` / `sessions` / `health` | Read the intel: list / show / tail records, session groupings, hit-rate and caution stats |
| `otel` | Configure and run the OTLP telemetry emitter (records → your SIEM) |
| `web-ui` | Serve the read-only observer web UI on demand |
| `config` | Show the effective configuration and where each value came from |

Add `--json` to any command for machine-readable output.

| Make target | Does |
|---|---|
| `make install` | Create the environment, install `blacksea`, and put it (and `bs-bundle`) on your PATH |
| `make init` | Choose infra mode (docker / external) and write `config/blacksea.env` |
| `make test` | Run all unit test suites |
| `make test-e2e` | Run every end-to-end example against a live stack (needs Docker) |
| `make uninstall` / `make clean` | Remove the installed commands (and, for `clean`, build artifacts) |

Two Make overrides are worth knowing: **`PYTHON=`** picks the interpreter the virtualenv is built from (`make install PYTHON=python3.12`), and **`BINDIR=`** picks where the `blacksea` command is symlinked (`make install BINDIR=/usr/local/bin`; it defaults to `~/.local/bin`).

Run `make help` for the build targets and `blacksea --help` for the full console tree.

## Where to go next

- [Top-level README](../README.md) — what Blacksea is, the lure technique, and the roadmap.
- [Operator console guide](../docs/console.md) — every `blacksea` command in depth.
- [Deploy your first bait](../docs/setup_a_bait.md) — a friendly, worked walkthrough from install to first hit.
- [Authoring a bait](../docs/bait-authoring.md) — write your own payload, listener, and staging vessel.
- [SIEM export over OTLP](../docs/otel-export.md) — stream records into your SOC / SIEM.
- [Troubleshooting](../docs/troubleshooting.md) — common issues and their fixes.
