# console/ — Operator CLI + the console facade (the well-defined interface)

**Status:** implemented, except the attribution commands — see below.
**Language:** Python 3.11+ (click + rich).

> **What's built.** The facade, packaging, and every command in the tree except the attribution
> group are implemented and exercised against a live stack. The dynamic attribution gate ships
> and registers `actors`/`drafts`/`replay` only once the correlation engine's session/actor
> tables exist; those commands' query bodies are not written yet. User guide: `docs/console.md`.
>
> `design/console.md` (the decision-by-decision log this spec was built
> from) has been **retired** — its substantive content was folded into this file (see
> "Design decisions" and "Implementation-resolved details" below), and the
> `design/` directory no longer exists. Nothing was lost; there is now exactly one place each
> contract lives.

## Scope

The `blacksea` console is the **single operator entrypoint** — a Docker-CLI-shaped terminal tool
for everything an operator does once the core infra (edge → NATS → brain → Postgres + the
control-plane catalog) is running. It provides:

1. **Infra status** — `blacksea status`: one labeled "is it up/healthy" view over Postgres, NATS,
   the brain, the edge, and the otel emitter (the Docker-`ps` analogue).
2. **Bait + instance lifecycle** — register / forge / build / approve / burn / retire / revoke, and
   list/show over the control-plane catalog.
3. **Event + health views** — list/show/**tail** records, read-time session grouping, hit-rate +
   caution distribution (burn-detection input).
4. **Artifact retrieval** — locate/inspect an instance's deployable `to_stage/` output.
5. **OTel telemetry control** — configure (`secrets/otel.env`), foreground-run, and emit an OS unit
   for the push-based OTLP emitter.
6. **Attribution** (when the correlation engine lands) — sessions (now) + actors/drafts/replay
   (not built yet).
7. **Lifecycle** — the full local-lifecycle verb set:
   config init (via **`make init`** — the documented entry; `blacksea init` is its hidden
   implementation, see step 3) plus `up`/`down`/`logs`/`reset`. The Makefile carries only the `init`
   wrapper — no `dev`/`infra-*` targets; everything else operational is a console verb. `up` drives
   `docker compose` for the backing services (docker mode) or
   verifies operator-run infra (external mode), then starts the edge + brain as detached daemons
   under `.dev/` (`--infra-only` brings up just Postgres + NATS with no daemons — the lightweight
   path for `make test`; `--edge-only` brings up just the edge on a separate-network edge host);
   `down` stops the daemons (`--infra` also stops the containers); `logs` tails them together;
   `reset` wipes all test-generated state (records/catalog/material store/keydir/NATS backlog)
   keeping creds + infra.

Everything is implemented **once, behind the console facade** (`service.py`); the CLI is a thin
consumer, and the later observer rework becomes a *second* consumer of the same facade (a web UI
"for the console"). This is the "no logic duplication" principle from the request.

The console is internal-only (behind VPN, inv 10). Today it is a terminal CLI with no auth (the
OS/host is the trust boundary); auth arrives with the future HTTP skin, not now.

## Scope boundary (what this module is NOT)

- **Not the control plane** — lifecycle verbs delegate to `control_plane.operations` /
  `forge.forge_bait`; no lifecycle logic is duplicated here.
- **Not the read engine** — record/session/health queries delegate to `blacksea.correlation.reader`
  (its sync variants); catalog reads to `control_plane.registry.Registry`.
- **Not the brain / edge** — no NATS, no Record assembly, no key handling beyond what
  `operations.py` already does host-local.
- **Not the correlation stateful engine** — the console *reads* its outputs; it never runs it.
- **Not the observer web UI** — deferred; it reworks *into* an HTTP client of this module's facade.
- **Brings up the local stack, but is not a production supervisor.** The `up`/`down`/`logs`/
  `reset` verbs (`console/supervisor.py`) own the *local* dev-loop supervision that
  `scripts/dev-up.sh` used to — they drive `docker compose` (docker mode) and detach the native
  edge + brain daemons under `.dev/`. They are inherently local (only meaningful on the host that
  runs the daemons). In **external** mode a `BS_DAEMONS=supervised` deployment starts **nothing** —
  systemd/containers own the daemons so a honeypot's uptime never depends on a CLI — and `up`
  degrades to a reachability health-check. The shipped systemd units / images per daemon are still
  future work.

## Contracts owned here

The console is a thin frontend, but its design gives it **two contracts of its own** (both new):

1. **The console facade** (`service.py` + the composite dataclasses in `models.py`) — the
   well-defined in-process interface the CLI consumes now and the future HTTP skin / web UI consume
   later. Its shape: **sync** functions/methods; **returns the existing module dataclasses**
   (`correlation.reader`'s `RecordSummary`/`RecordDetail`/`SessionView`/`TimeBucket`/`CautionCount`,
   `operations`' `RegisterResult`/`BuildResult`/…, `Registry`'s `DesignRecord`/`InstanceRecord`),
   plus **new composite dataclasses** only for views that don't exist elsewhere (`InfraStatus`,
   `BaitShow`, `OtelStatus`); **raises typed exceptions** (`operations`' `OperationError`/
   `UsageError`, plus read errors) — never swallows a failure as an empty result; **no Pydantic, no
   click/rich** in the facade (see the purity invariant below).
2. **`blacksea forge --json` output includes `artifact_path`** — the e2e harness
   (`e2e_tests/lib.sh::bs_forge`) parses a `^{`-anchored JSON line for `artifact_path`. When the
   Makefile is repointed at `blacksea forge`, this field must be preserved (mapped from
   `BuildResult`), or `lib.sh` is updated in the same change.

3. **`blacksea init` writes the unified config file.** The *format*
   of `config/blacksea.env` (a flat `KEY=VALUE` file: `BS_INFRA` + Postgres/NATS coordinates or an
   opaque DSN + credentials) and the loader are owned by **`blacksea.config.envload`** (which every
   consumer — the apps, Make's `-include`, compose's `--env-file`, `blacksea up`'s daemon env — reads);
   the console owns the *writer* + the interactive mode choice + external-mode connectivity
   validation. `docker` generates/reuses creds (an existing Postgres volume stays valid) and, after a
   *migrating* write, removes the legacy `secrets/env` so it can't shadow a later rotation; `external`
   validates Postgres + NATS reachability **before saving** and never overwrites operator creds. The
   file is written `0600` (and a dir it creates is `0700`); `init` refuses to overwrite without
   `--force`, and warns if `--config` targets a path outside the gitignored `config/*.env`. Returns
   the new `InitResult` dataclass. It needs **no database** (pure file I/O + an optional connectivity
   pre-check), so it constructs the facade with an empty DSN and never opens the read connection.
   The default write target is **package-anchored**: `Initializer` defaults `config_path` to
   `envload.anchored(CONFIG_RELPATH)` = `<BS_PROJECT_ROOT>/config/blacksea.env` — the *same*
   location the loader reads from — so `blacksea init` writes to the right place, and the
   overwrite guard sees any existing config, from **any** CWD. (This closes a footgun: with the
   old CWD-relative write, `blacksea init` from a stray dir wrote a *new* config there with *fresh*
   credentials that mismatch a running Postgres volume, and the guard never saw the real one.) The
   Makefile's **`make init`** target is therefore just a Make-native convenience
   wrapper (`$(VENV_BIN)/blacksea init $(ARGS)`) offered alongside `make install` — correctness no
   longer depends on the invoking directory. `blacksea init` remains the implementation and is
   still directly usable. **Credential-drift guard:** the *anchored* write closed the
   stray-dir footgun, but a second footgun remained — regenerating the config password (e.g. delete
   config + re-init) while the old `pg_data` volume is still around, because Postgres never re-applies
   `POSTGRES_PASSWORD` to an existing data dir, so the host connection then fails `password
   authentication failed` while the config file looks correct. `init_docker` now guards both sides:
   its best-effort `_docker_pg_volume_present()` probe (injectable via `Initializer(volume_probe=…)`
   for hermetic tests; `docker volume ls` under the hood, any failure → False so a normal fresh init
   stays quiet) makes it **warn** when it is about to mint a *fresh* password while that volume
   exists, and the `--force`/overwrite-guard rotate note now offers the **non-destructive** re-sync
   (`ALTER ROLE <user> PASSWORD '<new>'`, keeps data) alongside the destructive `down -v` recreate.
   The probe is **scoped to this stack's own volume** — `_expected_pg_volume()` derives
   `<project>_pg_data` from `$COMPOSE_PROJECT_NAME` or the compose file's directory basename
   (settings' `BS_COMPOSE_FILE`), so an unrelated compose stack's `*pg_data` volume never triggers a
   false warning. And because `blacksea up` auto-generates a docker config on a fresh checkout,
   `supervisor.py`'s `_bootstrap_docker_config` **surfaces the writer's ⚠ warnings into the `up`
   result notes** (rather than discarding the `InitResult`) — otherwise the drift warning would be
   swallowed on the very path (old volume + freshly-minted config) where it matters most. Locked by
   `tests/console/test_lifecycle.py::test_docker_warns_on_fresh_creds_with_existing_volume` (+ the
   no-volume / creds-carried-forward / `_expected_pg_volume` scoping cases) and
   `tests/console/test_supervisor.py::test_autobootstrap_surfaces_credential_drift_warning`.

4. **`blacksea up`/`down`/`logs`/`reset` — the local lifecycle supervisor**, the Python port of
   `scripts/dev-up.sh`/`dev-down.sh`/`dev-status.sh`/`reset-state.sh`
   (all four have been **removed**). The pure logic is **`console/supervisor.py`** (no
   click/rich — inside the facade-purity boundary); the facade exposes `up`/`down`/`logs`/`reset`,
   the CLI is a thin skin. Contract:
   - **`up`** — docker mode: (auto-generate `config/blacksea.env` if missing, docker-mode) →
     `docker compose -f <BS_COMPOSE_FILE> --env-file config/blacksea.env up -d` → block until
     Postgres is ready → start the daemons. The `-f` makes the compose file
     resolve from any CWD — the supervisor passes `settings.BS_COMPOSE_FILE` (anchored under
     `BS_PROJECT_ROOT`, `<root>/docker-compose.yml`) explicitly rather than relying on `docker
     compose`'s own walk-up-from-CWD lookup, which is why `up` used to work only from inside the
     checkout. The `.dev/`, `edge/`, material-store, and key-directory paths are likewise anchored
     under `BS_PROJECT_ROOT` (see `blacksea/config/context.md`), so `up`/`down`/`reset` are
     location-independent. External mode: **verify** Postgres + NATS reachable and start **nothing** if
     either is down (fail specifically) — except when no Postgres-backed daemon is being brought up
     on this host (`up --edge-only`), in which case a missing `config/blacksea.env` is not fatal:
     the edge only needs NATS coordinates, resolvable from the ambient env / `--nats` alone, so an
     edge-only host is never forced through a Postgres-credential `blacksea init --external` flow it
     will never use. Daemons are started **detached** (`start_new_session=True`) under `BS_DEV_DIR`
     (`.dev/`) with a `<name>.pid`/`<name>.log`/`<name>.cmd` triple (the log is truncated, not
     appended, on every fresh spawn); **idempotent** — a daemon alive with the same launch
     fingerprint (argv + env, incl. `BS_BRAIN_KEYDIR_POLL_S`) is left alone, one whose fingerprint
     changed is stopped + replaced. Immediate-death is caught via the `Popen` handle's `poll()` (not
     `os.kill`, which reports an un-reaped zombie as alive). A PID recorded as running is
     additionally cross-checked (Linux `/proc/<pid>/cmdline`, best-effort — a no-op on platforms
     without `/proc`) against the daemon's own argv to catch a stale pidfile whose PID has since
     been reused by an unrelated process.
   - **Daemon set is host-specific** (the edge may live on a separate network — inv 2/7): co-located
     dev → `[edge, brain]`; a brain host with `--edge-separate` → `[brain]` only (edge neither built
     nor probed here); `up --edge-only` (the edge host) → `[edge]` only, no infra/Postgres/brain,
     pointed at the remote `NATS_URL` with `NATS_CA`/`NATS_TLS_*` passed through for the TLS hop.
     `down`/`status`/`reset` (via `Supervisor._managed_daemons`) restrict themselves the same way —
     a brain host configured `--edge-separate` never manages a stale `.dev/edge.*` left over from an
     earlier co-located run. (`up --edge-only` has no persistent host-identity equivalent, so that
     one shape is enforced only by `up` itself, not by the other verbs.)
   - **`down`** stops whichever daemons this host owns and started; `--infra` also `docker compose
     down` (docker mode only; external refuses); a per-daemon `os.kill`→SIGTERM then a reap-aware
     wait (`os.waitpid(WNOHANG)` when the daemon is a child of this process, else a liveness poll —
     the process may have reparented to init between CLI invocations) → SIGKILL after
     `_STOP_GRACE_S`; a `PermissionError` (a stale PID reused by another user's process) is reported,
     not raised, so later steps still run. Only daemons actually transitioned from running→stopped
     count toward "stopped" in `down`'s/`reset`'s notes — a host with nothing running reports that
     honestly rather than always claiming a stop occurred. **`status`** (as `blacksea status`'s
     `daemons` pane, alongside the infra-probe table) and **`logs`** (`tail -f` over the
     `.dev/*.log` files) are the read-only views. **`reset`** stops the daemons, then two
     independently-reported Postgres steps — `TRUNCATE records, brain_health` and (separately)
     `DROP SCHEMA <cp> CASCADE` via `psycopg.sql.Identifier(validate_schema(...))` (the same
     identifier-quoting `control_plane/schema.py` uses, not raw string interpolation) — reusing the
     facade's connection (skipped-and-reported per-step if either fails, e.g. Postgres down or
     `records` not created yet) + best-effort NATS `BAITS` purge + `rm -rf` the material store +
     brain keydir (the keydir's *parent* is only rmtree'd when `brain_keydir` is the configured
     default location — `settings.BRAIN_KEYDIR`, passed in as `default_brain_keydir` and compared via
     `abspath`; an operator-overridden `--brain-keydir` has only its own file removed, so a custom
     directory it points at — even one named `.../secrets/keys/` — is never bulk-deleted) — **never**
     the creds
     (`config/blacksea.env`) or the infra containers. Confirmed interactively — the exact literal
     `yes` (matching the retired `reset-state.sh`, stricter than a bare `y`) or `--yes`.
   The Makefile no longer carries `dev`/`infra-*`/`reset-state` targets — the console is the sole
   operator entry point, and the e2e harness (`e2e_tests/lib.sh`) drives `blacksea up`/`blacksea
   forge` directly; the `.dev/edge.log` / `.dev/brain.log` layout is preserved for `e2e_tests/lib.sh`.

Lifecycle state machines + ingestion validation rules remain **`control_plane/context.md`**'s;
record/session/health view shapes remain **`correlation/context.md`**'s. The config-file format +
loader are **`blacksea.config.envload`**'s. The console consumes all three.

## Design decisions

1. **In-process facade (Option C).** "The API" is one in-process Python facade; the CLI consumes it
   directly. A FastAPI/HTTP skin + web UI layer over the *same* facade later. No daemon and no auth
   today (no network boundary).
2. **Facade in this package** (`blacksea.console.service`). It calls `control_plane.operations`
   (writes) + `correlation.reader`/`Registry` (reads) + `settings` (config) + otel control. Kept out
   of the privileged control plane.
3. **Facade returns existing dataclasses** (pass-through) + a few new composite ones; sync; errors
   surface; opens its own Postgres connection(s) per invocation.
4. **OTel: config + foreground `run` + emitted OS unit.** `otel config set` edits `secrets/otel.env`
   (validated `BS_OTEL_*` keys); `otel run` loads that file into a freshly-spawned
   `python -m blacksea.otel_export` (streams logs, Ctrl-C stops); `otel install-unit` emits a systemd
   unit / compose snippet with `EnvironmentFile=secrets/otel.env`, written `0600` (it embeds
   `POSTGRES_DSN`, same sensitivity as `secrets/otel.env` itself). **`config set` never affects a
   running emitter** — `settings.py` resolves `BS_OTEL_*` at import and the emitter reads them once at
   startup — so it prints "restart to apply." The console does **not** background-supervise.
5. **Infra status = labeled multi-component view + a brain heartbeat.** Each component reports
   `{status, source: direct|inferred|unit, detail}`; an inferred green is never shown as proof.
   Postgres (`SELECT 1` + counts) and the **brain heartbeat** are authoritative; NATS is TCP
   liveness; edge is TCP-reachability-if-co-located; otel is systemd-unit-status-if-installed.
6. **Noun-verb command tree + top-level aliases** (Docker's model). Full tree below. The top-level
   `blacksea --help` lists commands split into **ordered semantic groups** (`_COMMAND_GROUPS` in
   `cli.py`: *Setup & infra · Baits & instances · Intel & attribution · Telemetry & UI · Config*)
   with a crisp one-liner each, rather than one flat alphabetical list — a `ConsoleGroup.format_commands`
   override. Gated attribution commands render in the Intel group only when present; a
   command not named in a group falls through to an "Other" section so nothing vanishes. Locked by
   `tests/console/test_cli_smoke.py::test_help_groups_commands_semantically` +
   `::test_attribution_commands_appear_under_intel_group_when_gate_open`.
7. **Raw `--json` + Unix exit codes.** `render.py` is the single seam: dataclass → rich table/panel,
   or `json.dumps` under `--json` (rich auto-off). List → JSON array, show → JSON object, no wrapper.
   Errors → stderr; exit codes reuse `operations.py`'s `0` ok / `1` operational / `2` usage.
8. **Attribution commands hidden until their tables exist** (dynamic registration). `actors` /
   `drafts` / `replay` are registered only when the correlation engine's tables
   (`session_records`/`actor_*`/`confirmation_log`) exist — probed at CLI construction — so they
   auto-appear once that engine lands. `sessions ls` is **always** registered (read-time grouping
   now, `session_records` later). *Clean consequence:* the shipped console needs no attribution
   stubs — the gate simply registers nothing until the tables exist; the whole attribution command
   module is separate, later work.
9. **Packaging.** `blacksea` ships as an **installed console-script** (root `services/pyproject.toml` →
   `[project.scripts] blacksea = "blacksea.console.cli:main"`), added to `make install`; also
   `python -m blacksea.console`. The Makefile's operator targets (`control-plane`/`forge`/`dev`/
   `infra-*`/`run-observer`/`run-otel`/`reset-state`/`secrets`) were **removed** — the console is the
   sole operator frontend, and the Makefile keeps only build/test targets (`install`/`test`/
   `test-e2e`/`build-edge`/`clean`). The flat-verb `python -m blacksea.control_plane` CLI (its
   `cli.py` + `__main__.py`) has been **removed** — the console is the sole frontend over
   `operations.py`, so there is one `Ctx` and one `parse_kv`. **Consequence:** the console is a hard
   prerequisite of `make test-e2e` — the e2e harness `e2e_tests/lib.sh` drives `blacksea up` /
   `blacksea forge` directly (no `make` operator target left to wrap).

   **Console-script from the editable install.** The `blacksea` packages now live in one flat
   distribution (`src/blacksea/<mod>/`, root `services/pyproject.toml`); `pip install -e .` (via
   `make install`) makes every `blacksea.*` package importable and installs the `blacksea`
   console-script (`from blacksea.console.cli import main`) into `.venv/bin`. This retires the
   earlier frozen-site launcher (`scripts/install-console-launcher.py`) and the N-root
   `PYTHONPATH` — both existed only while each module was a separate source root.
   To make `blacksea`/`bs-bundle` resolve without `source .venv/bin/activate`, `make install` then
   symlinks both console-scripts into `$(BINDIR)` (default `~/.local/bin`, on PATH by convention on
   Linux and macOS; override with `make install BINDIR=…`). The link is self-contained — the
   console-script carries an absolute shebang into `.venv` — so it works from any shell. `make
   uninstall` removes the symlinks (only if they are symlinks); `make clean` removes them too so
   none dangle when `.venv` goes. The e2e harness (`e2e_tests/lib.sh`) is unaffected: it invokes the
   venv script by absolute path (`.venv/bin/blacksea`), not via the PATH symlink.

### Command tree

```
make init                            lifecycle: choose infra mode (docker|external) + write config/blacksea.env
                                     (Make wrapper; `blacksea init` is the hidden impl — not in `blacksea --help`)
blacksea up      [--no-infra --no-build-edge --edge-only --infra-only]   lifecycle: bring the stack up (infra + edge + brain; --infra-only = DB only)
blacksea down    [--infra]           lifecycle: stop the daemons (+ --infra stops the containers)
blacksea logs    [--no-follow]       lifecycle: tail the edge + brain logs together
blacksea reset   [--yes --no-purge-nats]   lifecycle: wipe test state (keeps creds + infra)
blacksea status                      infra status — top-level "ps" view
blacksea forge <manifest>            register→build→approve — top-level; [--comment]; --json emits artifact_path
blacksea baits    ls | show <bait_id> | register <manifest> [--refresh --ack]
blacksea instances ls [--bait --campaign --status] | show <token>
                   | build <bait_id> [--campaign --callback k=v --set k=v --comment] | approve <token>
                   | burn (--design|--instance) [--reason] | retire (--design|--instance)
                   | revoke <token> | artifact <token>
blacksea campaigns ls
blacksea events   ls [--bait --instance --campaign --sig-valid --limit --offset]
                   | show <record_id> | tail [--bait … --interval]
blacksea health   [--bait --since --bucket]
blacksea otel     run | config show | config set K=V | install-unit
blacksea config   show                effective operational settings (read-only; no general `set`)
blacksea web-ui   [--host --port]     TEMPORARY: foreground observer web UI launcher (Ctrl-C stops)
blacksea sessions ls                  works now (read-time grouping via reader.session_views)
blacksea actors   ls                  }
blacksea drafts   ls | confirm | reject }  registered only when the correlation tables exist
blacksea replay                        }
```

**`web-ui` is a deliberate temporary stopgap.** The observer is not part of `blacksea up`, so this
gives operators one on-demand way to bring the read-only UI up from the `blacksea` front door until
the real web UI (an HTTP client of this facade) replaces both it and the standalone observer module.
It is documented **only** in its own `--help` — intentionally kept out of `docs/console.md` and the
README so nothing advertises a throwaway command. Delete it when the real web UI lands.

### What is built, and what is not

- **Built:** the facade, packaging, and everything in the tree **except**
  `actors`/`drafts`/`replay`. `sessions ls` works (read-time grouping). `health` sources from
  the existing `records` table. Includes the brain-heartbeat cross-module change.
- **Not built (waiting on the correlation engine):** the real query bodies in
  `commands/attribution.py`, against `session_records`/`actor_*`/`confirmation_log`. The dynamic
  gate already ships in `cli.py` and will register them automatically once those tables exist.
  Also the `sessions ls` upgrade from read-time grouping to `session_records`.

Exit criterion for what is built: from a running core, an operator completes
`register → build → approve → forge → status → baits/instances ls → events tail → health →
instances artifact → burn/retire/revoke`, plus `otel config set → otel run → otel install-unit`,
all from `blacksea …`, with `--json` on every command.

**Locked against a live stack for most of the criterion** by
`e2e_tests/console_baits_instances/e2e_test.sh` (register → build → approve → ls/show →
burn/retire/revoke → artifact) and `e2e_tests/console_infra_observability/e2e_test.sh` (status →
events ls/show/tail → health → campaigns → sessions → logs → config show → otel config set/show →
down/up → reset) — real subprocess calls to the installed `blacksea` binary, not `CliRunner`.
`tests/console/` locks the CLI plumbing (help/grouping, `--json`, exit codes, facade purity)
in-process with the DB probe mocked off; these two e2e entries are what exercises the actual
query/mutation behavior against real Postgres/NATS/edge/brain. Not covered by either: `otel run`
and `otel install-unit` (the console commands themselves — `e2e_tests/otel_export/` proves the
underlying `python -m blacksea.otel_export` module end-to-end, including everything `otel run`
would spawn, but doesn't invoke `blacksea otel run` itself, so the command wrapper's own
env-assembly/subprocess-spawn path has no e2e coverage yet); `init` (would touch the shared
`config/blacksea.env` every e2e entry depends on — covered in-process instead by
`tests/console/test_lifecycle.py`); and `web-ui` (a documented TEMPORARY stopgap). See
`e2e_tests/console_infra_observability/README.md` for the full list with reasoning.

## Cross-module impact (this design reaches outside `console/` in a few places)

- **Brain heartbeat**: the brain upserts a health row (`last_poll_at`, optional consumer
  lag) each poll cycle. It **must live in the brain's public schema next to `records`** (which the
  brain already writes) — **not** the `control_plane` schema, where `brain_role` is `SELECT`-only.
  Updates `src/blacksea/brain/context.md` + the brain `schema.sql`.
- **Makefile + e2e**: the Makefile's operator targets were removed (build/test targets
  only); e2e READMEs and `e2e_tests/lib.sh` drive `blacksea …` directly (`blacksea up` /
  `blacksea forge`); `lib.sh`'s `bs_forge` `artifact_path` forge-JSON contract preserved.
- **otel docs**: `docs/otel-export.md`, `src/blacksea/otel_export/context.md`, and the
  `BS_OTEL_*` block in `src/blacksea/config/settings.py` describe config as env-vars-at-launch; they must
  document the new `secrets/otel.env` convention.
- **`observer`**: code untouched, and **not** a supervised daemon — `blacksea up` (like the retired
  `dev-up.sh` before it) brings up only edge + brain, never the observer. The console can
  launch it on demand via the TEMPORARY `web-ui` command (foreground subprocess). On the later
  rework the observer becomes an HTTP client of the console facade — its parallel Pydantic tier
  retired and this `web-ui` stopgap deleted. `observer/context.md` + this file update then.
- **Makefile + scripts** (step 3): `scripts/dev-up.sh`/`dev-down.sh`/`dev-status.sh`/`reset-state.sh`
  are **removed**, and so are the Makefile's operator targets (`dev`/`dev-*`/`infra-*`/`reset-state`/
  `secrets`/`forge`/`control-plane`/`run-observer`/`run-otel`) — `blacksea up`/`status`/`logs`/`down`/
  `reset` (plus `init`/`forge`/`web-ui`/`otel`) are the entry points; the Makefile keeps only
  build/test targets. `settings.py` gains the edge-runtime
  coordinates + supervisor knobs (`EDGE_ID`/`DNS_ADDR`/`HTTPS_ADDR`/`EDGE_BIN`/`BS_DEV_DIR`/`BS_DAEMONS`),
  mirrored in `edge/config.go` (the two-language note there).

## Dependencies

- `control_plane.operations` — the lifecycle verbs (register/build/approve/burn/retire/revoke +
  `list_campaigns`), returning result dataclasses / raising `OperationError`/`UsageError`.
- `control_plane.forge.forge_bait` — the one-shot `forge` command.
- `control_plane.registry.Registry` + `DesignRecord`/`InstanceRecord` — catalog reads (sync).
- `blacksea.correlation.reader` (+ `models`, `RecordFilter`, `RecordCursor`) — record/session/health
  views via the **sync** variants (`list_records`/`get_record`/`records_after`/`session_views`/
  `hit_rate`/`caution_distribution`); one source of truth shared with the observer.
- `blacksea.config.settings` — operational config (DSN, paths, `BS_INFRA`, the `BS_OTEL_*` block);
  read-only source for `config show`.
- `blacksea.config.envload` — owns the `config/blacksea.env` format + loader (`parse_env_file`,
  `dsn_from_coords`, `CONFIG_RELPATH`/`LEGACY_SECRETS_RELPATH`, the coordinate defaults). `lifecycle`
  (the `init` writer) reuses these so writer and reader agree byte-for-byte on the one file.
- `blacksea.otel_export` — **spawned as a subprocess** by `otel run` (`python -m blacksea.otel_export`
  with `secrets/otel.env` loaded into its env). Not imported in-process (isolation preserved).
- `blacksea.observer` — **spawned as a subprocess** by the TEMPORARY `web-ui` command
  (`python -m blacksea.observer --host --port`, with the console's `POSTGRES_DSN`/`BS_REGISTRY`
  injected). Same isolation as the otel spawn; not imported in-process.
- **`console/supervisor.py`** (step 3) shells out via `subprocess` to `docker compose`
  (up/down/ps/exec — docker mode infra), `go build` (edge binary), and `tail -f` (`logs`); starts
  the edge binary + `python -m blacksea.brain.pool` as **detached** daemons; imports `nats` **lazily**
  in `reset` (best-effort backlog purge); and resolves backing-service coordinates via
  `blacksea.config.envload` (`parse_env_file`/`dsn_from_coords`). `blacksea.brain.pool` /
  `edge/bin/edge` run as fresh processes that re-read `config/blacksea.env` themselves — never imported.
- `psycopg[binary]` — the facade's own sync connections (health/events/status/attribution + the
  brain-heartbeat read); `Registry` opens its own (see the connection-debt note).
- `click` (CLI framework), `rich` (rendering) — **only** in `cli.py`/`commands/*`/`render.py`, never
  in the facade.
- **Attribution commands only (not built yet):** the correlation engine's tables
  (`session_records`/`actor_*`/`confirmation_log`), read via the facade once that engine creates
  them.

## Invariants enforced here

- **Facade purity:** `service.py` + `models.py` + `probes.py` + `otel_ctl.py` +
  `lifecycle.py` + `supervisor.py` import **no click/rich** (only `cli.py`/`commands/*`/`render.py`
  do), and the facade takes its config as explicit constructor args (never reads click) — so the
  future web UI imports the facade clean. Locked by `tests/console/test_purity.py`, which asserts
  `click`/`rich` are absent from `sys.modules` after importing `service` (which pulls in `supervisor`).
- **Errors surface, never swallowed:** a read failure (e.g. Postgres down) is a
  non-zero exit with a stderr message, never an empty table — unlike `ObserverService` today.
- **inv 10:** console is internal-only (VPN). Today: localhost, no auth (OS is the trust boundary);
  access control arrives with the HTTP skin.
- **inv 12:** a record's `details` is rendered as **data, never as an LLM prompt** — attacker-
  controlled diagnostic markers, not intel and not instructions (see `brain/context.md`'s `details`
  rules).
- **Lifecycle safety (delegated, `control_plane/context.md`):** `burn`/`retire`/`revoke` are
  operator-confirmed, never automatic; `retire` is irreversible; a burned design keeps its pool
  worker and late hits are still stored (orphan). The console surfaces these; it does not weaken them.
- **Resolver-linkage flag (for the unbuilt attribution commands; `correlation/context.md`):**
  `actors`/`drafts` must explicitly flag
  linkages resting solely on a shared resolver IP — such a merge needs JA3/fingerprint corroboration
  and must not read as confirmable on its own.

## Connection-debt note

`Registry` opens its **own** non-injectable connection while `correlation.reader` takes an injected
one, so the facade holds ~2 sync connections per invocation. Fine for a CLI (once per invocation);
at the future HTTP edge this is per-request churn (the observer's known defect). **Debt for the HTTP
skin:** add pooling, and make `Registry`'s connection injectable then. Not fixed today.

## Implementation-resolved details (the retired `design/console.md`'s "remaining to pin down" items)

- **Composite dataclasses** (`models.py`, all frozen, no click/rich/Pydantic):
  - `ComponentStatus(name, status, source, detail)` + `InfraStatus(components, bait_count,
    instance_count, event_count, last_event_ms, daemons)` — `status ∈ up|down|stale|unknown`,
    `source ∈ direct|inferred|unit`; `daemons` is the per-daemon PID/log view (step 3,
    `Supervisor.status()`), empty on a host that has never run `blacksea up`.
  - `BaitShow(bait_id, version, status, assurance_tier, deploy_class, default_channel, test,
    listener_hash, bait_dir, registered_at, staged_at, burned_at, retired_at, manifest, instances,
    artifacts_dir)`.
  - `ArtifactLocation(instance_token, bait_id, status, filename, sha256, to_stage_dir,
    output_dir_root, ready_for_vessel, files)` — unwraps the instance's stored `{artifact_type,
    descriptor}` envelope; `ready_for_vessel` reads `<output_dir_root>/bundling_outputs/
    ready_for_vessel.txt`.
  - `OtelStatus(env_path, exists, config, unit_installed, unit_detail)`;
    `ConfigItem(key, value, secret)`.
- **Brain-health table** (the one cross-module change): `brain_health(id smallint PK =1,
  last_poll_at timestamptz, consumer_lag bigint)` in the brain's **public** schema (next to
  `records`). Cadence `BS_BRAIN_HEARTBEAT_S` (10s); the console's staleness window
  `BS_BRAIN_HEARTBEAT_STALE_S` (30s). DDL + upsert live in `src/blacksea/brain/{schema.sql,storage.py}`;
  the loop in `brain/pool.py`. See `src/blacksea/brain/context.md`.
- **`secrets/otel.env`** — systemd-`EnvironmentFile` syntax (`KEY=VALUE`, `#` comments, no
  `export`), written `0600`; only the `BS_OTEL_*` keys are settable (unknown key → `UsageError`).
  `otel install-unit` writes `secrets/blacksea-otel.service` (systemd, default) or a compose snippet;
  the systemd unit carries `EnvironmentFile=<otel.env>` + an embedded `POSTGRES_DSN` (not a
  `BS_OTEL_*` key). `otel run` injects `POSTGRES_DSN` and defaults `BS_OTEL_ENABLED=1` into the
  child env.
- **`blacksea forge --json`** emits the unchanged `ForgeResult` fields — `bait_id`,
  `instance_token`, `campaign`, `status`, **`artifact_path`**, `output_dir`, `comment`,
  `warnings` — preserving the `artifact_path` the e2e harness (`e2e_tests/lib.sh::bs_forge`)
  parses via `grep '^{' | tail -1` (the LAST `{`-line).
- **`forge`/`instances build` auto-show the full `instances artifact <token>` detail** in human
  mode — every file actually staged, not just the primary one (a vessel like
  `pwcrypt` stages several equally-valid per-arch binaries, which `artifact_path`/
  `artifact_filename` alone silently hid). `render.artifact_detail` (`render.py`) is the shared
  renderer behind `instances artifact`, `forge`, and `instances build` — one lookup
  (`svc.instance_artifact`), one rendering. Both `forge` and `instances build` skip the lookup
  and the render entirely under `--json`: printing a second JSON object would be the LAST
  `{`-line by the harness's `tail -1` rule above, silently replacing the `ForgeResult` object it
  expects (`ArtifactLocation` has no `artifact_path` key) — so the JSON contract stays exactly
  one object, unchanged from before this note.
  `commands/_common.show_artifact_after(app, svc, instance_token)` is the
  shared call site for this: it wraps the `instance_artifact()` lookup + render in a broad
  `try/except`, since `forge()`/`build()` have already fully committed (register/build/approve,
  key written to the brain key directory) by the time it runs — a failure in this purely
  cosmetic follow-up must never make an already-successful operation report as failed. On
  failure it prints a `render.note()` pointing at `instances artifact <token>` instead of
  raising; the primary success message (built from `result`, not from the lookup) is always
  printed first, so it can never be suppressed by this call.
- **Operator comment (create-a-bait note).** `forge` and `instances build` take a `--comment`
  free-text flag (descriptive metadata only — never on the ingest/routing/attribution path). When
  it is omitted **and** the shell is interactive (a TTY, not `--json`), the command **prompts** for
  one via `commands/_common.resolve_comment` — empty is fine (stored NULL). Under `--json` or a
  non-TTY (scriptable runs, the e2e harness, tests) it never prompts, so automation never blocks.
  The note flows `svc.forge/build(comment=…)` → `control_plane` → the instance's `comment` column,
  and is surfaced everywhere an instance is visualized: `baits show` (per-instance table), `instances
  show`/`instances ls`, and `--json`. `instances show`/`baits show` also surface the derived
  `InstanceRecord.artifact_dir` (the vessel's whole `to_stage/` deployable directory — not a single
  file, since a build may stage several; `instances artifact <token>` enumerates the files).
- **Universal `--json`** is accepted both globally (`blacksea --json …`) and **trailing** on every
  leaf command (`blacksea events ls --json`) via a shared `render.json_flag` decorator that flips the
  `RenderContext` — so `jq` pipelines and the e2e harness's trailing `--json` both work.

## File list

The importable package lives at `src/blacksea/console/`, part of the single `blacksea` distribution;
the root `services/pyproject.toml` declares the `blacksea` console-script and consolidates the deps
(`click`, `rich`, `psycopg[binary]`). Rows marked **(not built)** wait on the correlation engine.

| File | Description |
|---|---|
| `__init__.py` | package marker; re-exports the facade's public dataclasses (pass-through + composite) as the single import surface |
| `__main__.py` | `python -m blacksea.console` → `cli.main` (fallback to the `blacksea` console-script) |
| `service.py` | **the console facade**: sync read/write/config/otel/status/init ops; returns existing + composite dataclasses; raises typed exceptions; opens its own connections; **no click/rich, no Pydantic**. `init()` needs no DB (pure file I/O via `lifecycle`). Also `observer_serve` — the TEMPORARY foreground observer launcher (spawns `python -m blacksea.observer`, mirrors the otel-run isolation) |
| `models.py` | the **new composite dataclasses** only — `InfraStatus`/`ComponentStatus`, `BaitShow` (the `baits show` roll-up), `ArtifactLocation` (the `instances artifact` locator), `OtelStatus`, `ConfigItem` (`config show` rows), `InitResult` (the `init` outcome), and the step-3 lifecycle results `DaemonStatus`/`UpResult`/`DownResult`/`ResetResult`; re-exports (does not redefine) the pass-through dataclasses |
| `probes.py` | infra-status probes: Postgres, NATS TCP, brain-heartbeat read, edge TCP, otel unit → labeled `InfraStatus`; no click/rich |
| `lifecycle.py` | [startup-ux step 2] `blacksea init` logic (pure, no click/rich): generate/reuse credentials, write `config/blacksea.env` (`0600`) in docker or external mode, external-mode connectivity validation before saving, `--force` overwrite guard; raises `InitError`. The config-file *format* + loader are `blacksea.config.envload`'s |
| `supervisor.py` | [startup-ux step 3] the local lifecycle supervisor (pure, no click/rich): the `dev-up.sh`/`dev-down.sh`/`dev-status.sh`/`reset-state.sh` port. Detached daemon start/stop/status under `.dev/` (PID/log/cmd fingerprint, idempotent restart-on-config-change), `docker compose` up/down + Postgres-ready wait (docker mode), external-infra reachability verify, host-specific daemon set (edge-separate/edge-only), and the `reset` wipe; raises `SupervisorError`. Backing-service coordinates resolve via `blacksea.config.envload` |
| `otel_ctl.py` | otel control: read/write `secrets/otel.env`; foreground `run` (load env → exec subprocess); `install_unit` (systemd/compose template); no click/rich |
| `envfile.py` | dev DSN resolver: `--postgres` > `$POSTGRES_DSN` > `secrets/env` (dotenv parse + dev-DSN assembly), so a bare `blacksea` from a checkout works without exporting `POSTGRES_DSN`; inert in prod (only fires when nothing else provides a DSN); no click/rich |
| `render.py` | the single rendering seam: result dataclass → rich table/panel, or `json.dumps` under `--json`; the top-level typed-exception → stderr + `exit_code` handler |
| `cli.py` | click root group + `main()` (the `blacksea` entry point); global flags (`--postgres`/`--registry`/`--brain-keydir`/`--artifacts-root`/`--sdk-root`/`--json`); builds the facade config; registers command groups; **dynamically registers the attribution commands iff the correlation engine's tables exist**; renders the ASCII `banner.txt` atop the root `--help` (root group only); **groups the root `--help` command list into ordered semantic sections** via `_COMMAND_GROUPS` + a `ConsoleGroup.format_commands` override |
| `banner.txt` | the ASCII logo (art by Cracken) shown above `blacksea --help`; loaded defensively by `cli.py` and shipped as package-data |
| `commands/__init__.py` | package marker |
| `commands/_common.py` | shared command helpers: `KEY=VALUE` parsing (→ `UsageError`) + `RecordFilter` builder from the common event/health/session flags |
| `commands/init.py` | [startup-ux step 2] `init` — the interactive docker/external mode choice + prompts; resolves values and delegates to the facade's `init()` (→ `lifecycle`). The only click here; the file-writing/validation is pure |
| `commands/up.py` | [startup-ux step 3] `up` — bring the stack up (`--no-infra`/`--no-build-edge`/`--edge-only`); delegates to `service.up` (→ `supervisor`) |
| `commands/down.py` | [startup-ux step 3] `down` — stop the daemons (`--infra` also stops the containers); → `service.down` |
| `commands/logs.py` | [startup-ux step 3] `logs` — tail the `.dev/*.log` files together (`--no-follow`); → `service.logs` |
| `commands/reset.py` | [startup-ux step 3] `reset` — wipe test state, confirmed (`--yes`/`--no-purge-nats`); → `service.reset` |
| `commands/status.py` | `status` — the infra-status view (via `probes`) |
| `commands/baits.py` | `baits ls | show | register` |
| `commands/instances.py` | `instances ls | show | build | approve | burn | retire | revoke | artifact` |
| `commands/forge.py` | `forge` (wraps `forge_bait`; `--json` preserves `artifact_path`) |
| `commands/campaigns.py` | `campaigns ls` |
| `commands/events.py` | `events ls | show | tail` (tail via `reader.records_after`) |
| `commands/health.py` | `health` — hit-rate + caution distribution over `records` |
| `commands/otel.py` | `otel run | config show | config set | install-unit` (delegates to `otel_ctl`) |
| `commands/config.py` | `config show` — effective settings, read-only |
| `commands/webui.py` | **TEMPORARY** `web-ui` — foreground launcher for the read-only observer web UI (delegates to `service.observer_serve`); a stopgap until the real web UI (over the facade) replaces both this command and the standalone observer. Deliberately absent from `docs/console.md`/README — documented only in the command's `--help` |
| `commands/sessions.py` | `sessions ls` — always registered; read-time grouping now, `session_records` once the correlation engine lands |
| `commands/attribution.py` | **(not built)** `actors ls`, `drafts ls|confirm|reject`, `replay` — registered only when the correlation engine's tables exist; the real query bodies land with that engine |
| `tests/console/` | pytest suite: facade-purity (no click/rich in `service`), render/exit-code mapping, dynamic-registration gate, command smoke tests (skip cleanly with no DB) |
