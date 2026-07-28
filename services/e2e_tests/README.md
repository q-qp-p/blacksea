# e2e_tests/ — real end-to-end tests

Real end-to-end tests for the Blacksea pipeline. Each entry forges a bait from its manifest,
fires it the way an attacker would, and asserts a record lands in Postgres — exercising the
whole stack (control-plane factory → edge → NATS → brain → Postgres) against a live `blacksea up`.

Every entry doubles as a runnable usage example and as an automated test picked up by
`make test-e2e`.

**Two entries deviate from that framing:** `console_baits_instances/` and
`console_infra_observability/` aren't demonstrating a bait or delivery technique — they use a
minimal fixture bait (reusing `hostname_grab`'s payload/listener/vessel) purely as the means to
drive the `blacksea` console CLI itself end-to-end against a live stack (real subprocess calls,
not `CliRunner`), split by concern: bait/instance CRUD + the burn/retire/revoke state machine vs.
infra lifecycle (`status`/`up`/`down`/`reset`) + observability (`events`/`health`/`campaigns`/
`sessions`/`logs`/`otel config`). Together they lock most of
`../src/blacksea/console/context.md`'s M5a "Exit criterion" (`otel run`/`otel install-unit` aren't
covered by either — see that file's Exit-criterion note for what's still open). They follow
this page's directory/discovery conventions (auto-discovered, `../lib.sh`, `manifest.yaml` +
`e2e_test.sh` + `README.md`) but **not** the "Adding a new entry" §2 shape below, where the only
entry-specific content is meant to sit between `bs_wait_hotswap` and `bs_verify_record` — these
two entries' whole point is running console-command assertions well outside that window.

## Layout

```
e2e_tests/
├── README.md            # this file
├── lib.sh               # shared shell helpers every entry sources (forge/hot-swap/verify)
└── <entry>/             # one directory per bait under test
    ├── manifest.yaml    # the bait design (self-sufficient: has a `deploy:` block for forge)
    ├── e2e_test.sh      # automated test: forge → fire → verify a record; exit non-zero on failure
    └── README.md        # (optional) narrative walk-through of this entry's pipeline
```

`make test-e2e` (see `../Makefile`) auto-discovers `e2e_tests/*/e2e_test.sh` — there is **no
hardcoded list of entries**. Add a directory and it is run; no Makefile edit needed.

## Adding a new entry

Create `e2e_tests/<name>/` with these files:

### 1. `manifest.yaml`

A normal bait manifest (see `../../docs/bait-authoring.md`) that is **self-sufficient for forging** —
it must carry a `deploy:` block so `blacksea forge` can register → build → approve in one call. Every
entry here is a test/example bait, so set `test: true` at the top level (see
`../../docs/bait-authoring.md` §6) — it flags the design and every record it produces as non-real
intel, shown as a `TEST` badge in the observer UI:

```yaml
deploy:
  campaign: example-<name>              # default campaign (tests override with --campaign)
  callbacks:
    https: http://127.0.0.1:8443        # one address per declared channel
```

`payload_file` / `listener_class` / `staging_vessel` may point into `../../../lure_material/`
via `../`-relative paths (the factory, ingestion, and brain pool all resolve them with
`os.path.join(bait_dir, ...)`); every entry here lives at `e2e_tests/<name>/`, so the catalog
paths carry over unchanged from one entry to the next.

**DNS-channel entries** (`channels: {dns: {}}`) need one more piece: the local dev edge's zone
isn't really DNS-delegated, so the payload can't rely on the OS resolver reaching it. Add a
`deploy.build_vars._DNS_SERVER` targeting the dev edge's `DNS_ADDR` directly, and use `CHANNEL=dns`
when calling `bs_forge` in `e2e_test.sh` (see `hostname_grab_dns/`):

```yaml
deploy:
  campaign: example-<name>
  callbacks:
    dns: cb.example.com             # zone name — matches the edge's DNS_ZONES
  build_vars:
    _DNS_SERVER: "127.0.0.1:15353"  # matches the edge's default DNS_ADDR; empty for a real deploy
```

There is no per-entry manual-test script: to poke an entry by hand, forge it through the console
(`blacksea forge e2e_tests/<name>/manifest.yaml`), fire the artifact `forge` prints, then read the
record back with `blacksea events ls --bait <bait_id>` — see the entry READMEs for the exact
console flow.

### 2. `e2e_test.sh` — automated testing

The full fire-and-verify flow. Source `../lib.sh` and call the helpers in order; the only
entry-specific part is **how the bait is triggered** between `bs_wait_hotswap` and
`bs_verify_record`:

```bash
set -euo pipefail
source "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/../lib.sh"
bs_require_venv
bs_dev_up                              # idempotent; brings up edge+brain+infra @ e2e_tests/
bs_forge "${1:-http://127.0.0.1:8443}" # sets BS_TOKEN / BS_ARTIFACT_PATH / BS_ARTIFACT_DIR
bs_wait_hotswap                        # block until edge+brain have the new snapshot/key

# ── entry-specific trigger goes here ──
"$VENV_PYTHON" "$BS_ARTIFACT_PATH"     # e.g. run the artifact; or `( cd "$BS_ARTIFACT_DIR" && ./run )`

if bs_verify_record; then              # polls Postgres for a record from BS_TOKEN
    echo "record stored: $BS_RECORD"
else
    echo "no record for $BS_TOKEN" >&2; exit 1
fi
```

Print the trigger command and the paths it uses (`$BS_ARTIFACT_PATH` / `$BS_ARTIFACT_DIR`) before
running it, so a failing run shows exactly what fired and against which artifact.

## `lib.sh` contract

Source it as the first thing after `set -euo pipefail`. It derives every path from the sourcing
script's own location (nothing hardcoded) and exposes:

| Symbol | Meaning |
|---|---|
| `$CODE_DIR` | absolute path to `services/` |
| `$ENTRY_DIR` / `$ENTRY_REL` | this entry, absolute / relative to `services/` (for `blacksea forge`) |
| `$VENV_PYTHON` | the shared project venv interpreter |
| `bs_require_venv` | abort unless `make install` has run |
| `bs_dev_up` | idempotently bring up the dev stack @ `e2e_tests/`; record log positions for the wait |
| `bs_forge [ADDR]` | forge this entry (campaign `$CAMPAIGN`, default `e2e-test`; deploy.callbacks channel `$CHANNEL`, default `https`); sets `BS_TOKEN` / `BS_ARTIFACT_PATH` / `BS_ARTIFACT_DIR` — e.g. `CHANNEL=dns bs_forge cb.example.com` for a DNS-channel entry |
| `bs_wait_hotswap` | block until the edge + brain hot-swap in the new snapshot/key |
| `bs_verify_record` | poll Postgres for a record from `BS_TOKEN`; sets `BS_RECORD`, non-zero if none |

## Running

```
make install                 # from services/ — once; creates .venv + deps
make test-e2e                # from services/ — run every entry's e2e_test.sh (needs Docker for infra)
```

Individual entry, automated:  `e2e_tests/<name>/e2e_test.sh [CALLBACK_URL]`
Individual entry, manual:     `blacksea forge e2e_tests/<name>/manifest.yaml`, fire the printed
artifact, then `blacksea events ls --bait <bait_id>` (see the entry's README).

Override the campaign with `CAMPAIGN=my-campaign`; override the callback with the first arg.
After testing, `blacksea reset` clears registry/keydirs/records and `blacksea down` stops the
dev-managed processes.
