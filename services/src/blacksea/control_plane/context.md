# control_plane/ — Registry, lifecycle, factory, brain key-directory writer

**Status:** implemented.
**Language:** Python 3.11+
**Contracts:** this file is self-sufficient. The manifest schema, both lifecycle state machines
(design-level and instance-level), the ingestion validation rules, the **catalog storage model**
(Postgres — the `control_plane` schema + its transaction API), the **listener freeze + hash**
contract, and the brain key directory's write side (the **sole** directory now — the dead-drop
edge holds none) are all locked and inlined in the "Contracts" section below — no external design
doc is required. The design +
decision log that drove the flat-file→Postgres registry migration (D1–D7, O1–O11) was folded into
this file when the migration landed, and the working `REGISTRY_DB_{DESIGN,PLAN}.md` docs were
retired, per the repo's "one place per contract" rule.

> **On the `§5.x` citations** in this module's and the brain's code: they are stable internal
> cross-reference labels inherited from a plan document that has since been retired, its content
> folded into this file. Read them as pointers to the matching material below — `§5.3` the
> validity window, `§5.7` the instance lifecycle / revocation gating, `§5.9` the edge-side drop
> rules, `§5.11` the brain key directory. There is no longer any external document to look them
> up in.

## Contracts

These are the locked data formats and state machines this module implements. A frozen field may
never change in place — changing it requires a new `bait_id`, not an edit. Additive fields may be
added via ordinary PR review.

### Three-level record model

| Level | Owner | Created | Lives in | Mutable? |
|---|---|---|---|---|
| `manifest.yaml` | bait author | design time | `baits/<bait_id>/manifest.yaml` (git) | PR only |
| design record | control plane | on ingestion | catalog: `control_plane.design` (Postgres) | lifecycle transitions only |
| instance record | factory / build() | per deployment | catalog: `control_plane.instance` (child of design) | instance lifecycle transitions only |

The manifest is source of truth for design-level fields; the full parsed manifest is stored
verbatim as the design row's `manifest jsonb` (O1 — DB-authoritative, so the brain reads one
source, not git + DB). The design record adds lifecycle state + timestamps; it never overrides
manifest fields. The instance record adds per-deployment fields (token, key_ref, campaign,
callback addresses). The brain key directory (below) is a further read-only projection of
instance records — it adds no new data. **Two stores joined by ID (D7):** the **catalog**
(Postgres) holds this structured, queryable, transactional metadata; the **material**
(`registry/artifacts/`) holds the file *bytes* (frozen listener code, payload bundles,
deployables) — an artifact's location is *derived* from IDs (`<artifacts-root>/<bait_id>/
<version>/…`), never a stored path (O9), so the coupling survives a cross-host move.
The manifest is frozen at PR-merge: changing a frozen field (`bait_id`, `assurance_tier`,
`deploy_class`) requires a NEW `bait_id`, not an edit. Additive changes (new optional fields,
version bump, channel config tweak) are permitted via PR.

### `manifest.yaml` field set (frozen)

All fields required unless marked (optional).

| Field | Type | Frozen? | Purpose |
|---|---|---|---|
| `bait_id` | kebab-case string | yes — never change | routing key (the brain resolves it from `tok` and selects the listener by it); artifacts directory name |
| `version` | semver M.m.p | additive | hot-rewire granularity; pool loads vN alongside vN-1 |
| `description` | string | — | human-readable summary; primary GitOps review surface |
| `assurance_tier` | enum 0\|1\|2 | yes | signal-only/authenticated-signal/full-payload; registered expected tier; downgrade flagged |
| `deploy_class` | enum | yes | pivot-risk classifier; drives control-plane staging logic |
| `isolation_class` | enum | — | analyzer substrate; default `in_process` |
| `channels` | map | — | channel menu + per-channel config; determines hot-wire eligibility |
| `envelope_version` | uint | — | which `ev` the payload emits; must be a known version |
| `provenance` | sub-object | — | required citation; registration fails without it (no generic bait) |
| `retention_days` | int | — | telemetry retention window for this bait |
| `build` | sub-object | — | toolchain + target arch; consumed by factory `build()` |
| `isolation` | sub-object (optional) | — | required only when `isolation_class: sandboxed` |
| `test` | bool (optional, default `false`) | additive | marks a test/example/reference bait — not real intel. Read into `DesignRecord.test`, propagated by the brain into every record it produces (`records.test`, see `src/blacksea/brain/context.md`), and surfaced in the observer UI (a `TEST` badge) — see `src/blacksea/observer/context.md` |

`deploy_class` enum values (frozen — pivot-risk classifier):

| Value | Meaning | Control-plane implication |
|---|---|---|
| `portable_artifact` | binary/script that runs on the attacker's machine | standard factory build; no host required |
| `host_resident` | inert file/canary placed on a real host | requires a target host; no code-exec risk |
| `interactive_service` | service running on our segmented honeypot host | triggers segmentation enforcement; needs host orchestration + microVM/gVisor; requires operator approval |

`isolation_class` enum values:

| Value | Meaning | When to use |
|---|---|---|
| `in_process` | analyzer loaded in-process in the shared pool (default) | all standard baits |
| `subprocess` | analyzer runs in a pool child process | body parser with unusual memory/CPU footprint |
| `sandboxed` | WASM module or container; requires an `isolation` sub-object | genuinely adversarial input; rare |

### `channels` field

```yaml
channels:
  https: {}
  dns:
    max_chunks: 10       # cap for DNS sequence mode; default 10
```

At least one channel is required. `dns`-only → tier-0 by definition. `https` (or `tcp`) may be
tier 0/1/2. `dns.max_chunks` caps the DNS sequence burst, default 10; values above 50 need an
explicit override comment (detection + canary-zone DoS risk). Unknown channel names → ingestion
gate error, never a silent failure. Channel config is additive-only.

### `provenance` sub-object (required)

```yaml
provenance:
  behavior: >
    LLM agent reads files in /dev/ and /etc/ during filesystem recon and
    executes discovered binaries without sandboxing.
  source: workspaces/DarkMoon/working_dir/findings/VERIFIED_PRIMITIVES.md
  observed_date: "2026-05-14"
```

All three sub-fields (`behavior`, `source`, `observed_date`) are required and validated non-empty
by the control plane — this is the enforcement point for "no generic bait." The content itself is
not validated — that's the human reviewer's job at PR time.

### `build` sub-object

```yaml
build:
  toolchain: python3.11
  target_arch:
    - x86_64-linux
    - aarch64-linux
```

For compiled native payloads, `toolchain` can be a list (e.g. `[go1.22, python3.11]`).
`toolchain` values resolve to pinned hermetic toolchain images (the exact pinning mechanism is a
deferred detail) — the manifest declares WHAT is needed, the sandbox decides HOW to provision it.

### `isolation` sub-object (only for `isolation_class: sandboxed`)

```yaml
isolation_class: sandboxed
isolation:
  sandbox_type: wasm        # wasm | container
```

Baits using `in_process` or `subprocess` must NOT include an `isolation` block (validation
error).

### Registry record (runtime extension)

Manifest fields plus:

| Added field | Type | Set by | Purpose |
|---|---|---|---|
| `status` | enum | control plane | design-level lifecycle state |
| `registered_at` | ISO-8601 | control plane | when the PR was reconciled |
| `staged_at` | ISO-8601 | control plane | when pool module was loaded |
| `burned_at` | ISO-8601\|null | operator/burn-detection | when design was marked burned |
| `retired_at` | ISO-8601\|null | operator | when design was retired |
| `listener_hash` | sha256 hex\|null | control plane (register, O11) | digest of the frozen listener closure for this `(bait_id, version)`; drives version-immutability + the brain's pre-import verification |

Instances are a **relational child table** (`control_plane.instance`, FK → `design.bait_id`), not
an embedded list; query them with `list_instances(bait_id=…)`.

### Lifecycle state machines

**Design-level:** `draft → staged → deployed → burned → retired` (burned keeps the pool worker
running; late hits = intel).

| State | Meaning | Pool worker? | Accepts new instances? |
|---|---|---|---|
| draft | manifest merged; control plane not yet reconciled | no | no |
| staged | pool module loaded; no live instances yet | yes | yes |
| deployed | ≥1 active instance | yes | yes |
| burned | design pattern recognized across instances; retire design | yes | no — hot-wire a new `bait_id` |
| retired | pool worker stopped; hits become tagged orphans | no | no |

Transitions: `draft → staged` automatic after merge (or manual trigger); `staged → deployed` on
first instance active; `deployed → burned` by operator command OR burn-detection signal (never
automatic-only); `burned|deployed → retired` explicit operator decision, irreversible; retired
hits are stored + tagged `{orphan: true, design_status: retired}`, never dropped. `staged` can also
go directly to `burned` or `retired` (operator command) — abandoning a design that staged but never
got an active instance, without first faking a `deployed` state.

**Instance-level:** `pending → active → burned → retired` (the key stays in the brain key
directory even burned/retired; late hits = intel).

| State | Meaning | Key in directory? | Accepts hits? |
|---|---|---|---|
| pending | `build()` called; artifact staged; awaiting human approval | no | no |
| active | approved; artifact deployed; key in the brain key directory | yes | yes |
| burned | token recognized; replacement being prepared via hot-deploy | yes | yes — late hits stored + tagged |
| retired | instance stood down; not replaced | yes — kept for late hits | yes — tagged orphan |
| revoked | key weaponized (DoS/poisoning replay); special | yes, marked revoked | verify-to-identify + heavy-sample + alert |

`burned → retired` is the operator's explicit call after a hot-deploy replacement is active.
`revoked` is set only by operator command, never automation.

### Instance record fields (factory-created, per-deployment)

| Field | Type | Source | Purpose |
|---|---|---|---|
| `instance_token` | 8B hex (16 chars) | factory: random | master key for this deployment; goes into the artifact |
| `key_ref` | opaque ref | factory | pointer to where `_KEY` is injected into the artifact; never stored in the registry |
| `campaign_id` | string | operator at deploy time | compartment scope; campaign-scoped callback addresses |
| `callback_addresses` | map channel→URL/domain | operator at deploy time | campaign-scoped endpoints injected into the artifact |
| `status` | enum | factory/operator | instance lifecycle state |
| `built_at` | ISO-8601 | factory | when `build()` ran |
| `approved_at` | ISO-8601\|null | operator | when human approved deployment |
| `burned_at` | ISO-8601\|null | operator | when instance was marked burned |
| `retired_at` | ISO-8601\|null | operator | when instance was retired |
| `listener_hash` | sha256 hex\|null | factory (build, O11 #2) | the design's `listener_hash` pinned onto the instance at build — survives any later edit to the design row |
| `comment` | text\|null | operator at forge/build time | free-text note (why this instance was built: campaign context, target, an ops caveat). Purely descriptive metadata — empty is fine (stored NULL); **never** on the ingest/routing/attribution path. Surfaced in `baits show`, `instances show/ls`, and the `--json` output |

`InstanceRecord.artifact_dir` is a derived **property** (not a stored column): the vessel's whole
`to_stage/` output directory (the stored `artifact` descriptor's `output_dir`,
`<artifacts-root>/<bait_id>/<timestamp>/to_stage/`), or `None` until the instance is built. It is the
*directory* an operator ships — not a single file — because a build may stage more than the primary
file (supporting files, a loader, etc.); `instances artifact <token>` still enumerates the individual
`files`. The path is not a new stored field (O9 — locations are derived from IDs, never a stored
path); this property just surfaces it for the detail views. Same build-host relocation caveat as
`bait_dir`. (Distinct from `ForgeResult.artifact_path`, which stays the *primary file* — the e2e
harness fires it and takes `dirname` of it.) `ForgeResult`/`BuildResult` are otherwise unchanged
by this — for multi-binary vessels (e.g. `pwcrypt`'s per-`target_arch` binaries), the console
layer (not this module) covers the "which other files got staged" gap by having `forge`/
`instances build` call `instances artifact <token>`'s own lookup and print its full file list
right after the summary, instead of adding a field here — see `console/context.md`.

`key_ref` is a reference (e.g. a file path in the build sandbox), never the key material itself —
the catalog is not a secrets store. `_KEY` lives inside the built artifact and in the brain's key
directory — the only two places it exists; never persisted in the registry, never reaches the
edge.

### Ingestion validation rules

Any failure blocks reconciliation, returns a structured error, never a silent pass.

| Rule | Failure action |
|---|---|
| `bait_id` unique in the registry | block: "bait_id already registered; use a new id or bump version" |
| all three `provenance` sub-fields non-empty | block: "provenance required — cite the attacker behavior (no generic bait)" |
| all channels in `channels` map have registered edge receivers | block if unknown: "channel `<x>` has no edge receiver — deliberate surface change required" |
| `assurance_tier: 0` paired with channels containing only dns/icmp | pass |
| `assurance_tier: 1\|2` paired with channels containing only dns | warn: "tier ≥1 requires a fat channel for signature delivery; DNS is tier-0 only by default" |
| `deploy_class: interactive_service` | warn + require explicit operator acknowledgement: "interactive service — segmentation required" |
| `isolation_class: sandboxed` without an `isolation` sub-object | block: "sandboxed isolation_class requires an isolation block" |
| `isolation_class: in_process\|subprocess` WITH an `isolation` sub-object | block: "isolation block only valid for sandboxed class" |
| `dns.max_chunks > 50` | warn: "high DNS burst — detection + canary-zone DoS risk; add explicit justification comment" |
| `envelope_version` not a known `ev` | block: "unknown envelope version" |
| Python class in bait dir implements the Listener ABC | block if ABC check fails: "class does not implement required interface" |
| `golden_cases()` passes offline | block if any golden test fails: "golden test failure — fix before registering" |

### Publish flow (on any lifecycle change)

There is **no edge-facing directory anymore** — the edge is a dumb dead-drop that holds none, so
the control plane writes **only** the brain key directory (see "Brain key directory — write side"
below). On every lifecycle change (instance burned/retired/revoked, design retired):

1. The factory already wrote `_KEY` directly to the brain's key directory at `build()` time; the
   registry instance record holds only `key_ref`.
2. After the lifecycle transaction commits, a `publish` callback refreshes the brain key
   directory's routing/status fields for every instance via `brain_keydir.sync_routing_fields()`
   (it never touches `key`). That is the whole publish flow — no signed snapshot, no `seq`, no
   distribution point, no `dirsign` key. The brain picks up the change on its own key-directory
   poll.

The brain key directory is written server-to-server (both the control plane and the brain are
trusted, internal-only) and never crosses the edge-facing diode.

### Brain key directory — write side

The factory writes `_KEY` directly into the brain's key directory at `build()` time (not at
`approve()` — the brain must be able to identify a pending-approval instance's traffic for
debugging even before it's active; access-gating by status happens at lookup/consumption time, in
the brain). The registry never sees the key bytes, only `key_ref`.

File format (dev-grade): a flat JSON array, one object per instance:

```
{instance_token, key, status, bait_id, campaign_id, assurance_tier, default_channel,
 valid_from, valid_until}
```

— identical to what a routing entry used to be, plus one field, `key` (64-char hex). This is the
**sole** key directory in the system (the dead-drop edge holds none) and never crosses the
edge-facing diode, so it needs no signing/anti-rollback — ordinary server-side access control
suffices.

### Catalog storage — Postgres `control_plane` schema (D1/D2)

The registry is the `control_plane` schema in the brain's Postgres (`schema.py`), not flat files.
This is a **correctness** change, not a scale one — the DB's unique contribution is
**transactions** (the old flat-file store had no cross-record atomicity and no concurrent-writer
serialization). Tables:

- **`design`** — `bait_id` PK, `version`, `manifest jsonb` (O1, authoritative), `bait_dir`
  (build-time source anchor, control-plane host only — O9), `listener_hash` (O11), `status`, and
  the four lifecycle timestamps. One row per `bait_id` = the *current* version; version
  coexistence lives in the material tree (frozen listener per `(bait_id, version)`) + the instance
  rows (each pins its `bait_version` + `listener_hash`).
- **`instance`** — `instance_token` PK, FK → `design(bait_id)`, `bait_version`, `key_ref` (pointer
  only, never `_KEY` — inv 16/D3), `listener_hash` (pinned at build), `campaign_id`,
  `callback_addresses jsonb`, `artifact jsonb` (descriptor), `status`, lifecycle timestamps, and
  `comment text` (nullable — the free-text operator note, descriptive metadata only). `comment` was
  added additively; `ensure_catalog()` carries an `ALTER TABLE … ADD COLUMN IF NOT EXISTS comment`
  so catalogs created before it pick it up idempotently.

There are only these two tables now. The old `snapshot_state` single-row `seq` counter (O8) was
**removed** with the dead-drop change — there is no edge snapshot to sequence anymore, so nothing
allocates a monotonic publish `seq`.

Lifecycle timestamps are `text` (ISO-8601 strings), not `timestamptz`, so the `str | None` record
contract round-trips verbatim (`fromisoformat` parses `approved_at`).

**Transaction API (O3).** `Registry.transaction()` yields a row-locking view: `get_design` /
`get_instance` take `SELECT … FOR UPDATE`, all inside one Postgres transaction. Every multi-record
lifecycle transition (e.g. `approve` promotes the design *and* activates the instance) runs in one,
so a crash mid-transition rolls back to **neither** write and racing `approve`/`burn` **serialize**.
The brain key directory is refreshed *after* commit via the `publish` callback. O3 is independent
of the deleted O8 seq counter — the row-locking atomicity is still needed for correct lifecycle
transitions even though there is no publish `seq` to allocate anymore. This kills the motivating
bug (approve's two-write window).

**Roles + grants (O6, inv 10 mitigation).** The catalog is isolated by DB grant, not convention:
`cp_role` owns/DML; `brain_role` gets `SELECT` on `design`/`instance` only — and **no** write
anywhere in the schema. So a brain compromise gets read-only lifecycle visibility, never write (it
cannot revive a revoked instance or forge a status). In dev
everything connects as one superuser DSN, so the split is *provable* (via `SET ROLE`, see
`test_schema.py`) rather than enforced; enforcing it in production means giving the brain a DSN
that is a member of only `brain_role`. `ensure_catalog()` (tables, no privilege needed) runs
lazily on first use; `ensure_roles_and_grants()` (superuser) is a separate bootstrap step.

**Secrets stay off the DB (D3, inv 16).** Only non-secret state is in the catalog. `_KEY` goes to
the brain key directory (a filesystem file, never the DB). There is no `dirsign.key` anymore (the
directory-signing key was eliminated with the dead-drop change), so `Registry` is no longer a
hybrid facade spanning Postgres + a `dirsign/` secret — the only filesystem thing left alongside
the Postgres catalog is the material store (`artifacts/`), which holds bytes, not secrets.
Authoring now hard-depends on a running Postgres (`POSTGRES_DSN`, O7 — accepted, no offline
fallback).

### Listener freeze + hash (O10/O11) — the brain's code source

At `register`, the listener's dependency **closure** is frozen into the material store at
`<artifacts-root>/<bait_id>/<version>/listener/` and its sha256 recorded as the design's
`listener_hash` (`listeners.py`). This is the brain's code source (O9/O10): the brain imports the
*frozen* listener from there, not from git. Three guards:

1. **Version-immutability at `register`** — re-ingesting a `(bait_id, version)` whose source
   listener hashes differently than the recorded `listener_hash` → error ("listener for X vN
   changed — bump the version"). A version's listener is immutable.
2. **Pin on the instance at `build`** — the factory copies the design's `listener_hash` onto the
   instance row, so the instance carries the exact listener digest it expects.
3. **Verify before the brain imports** — the brain re-hashes the frozen bytes and compares to the
   pinned digest before `importlib`; mismatch → refuse to load (dead-letter + alert).

**Closure scope.** Blacksea listeners import only the SDK + stdlib, plus — for a listener that
ships its own sibling data file (e.g. a YAML knowledge base loaded via
`Path(__file__).parent / "..."`, see `agent_fp`'s `signatures.yaml`) — any filenames the manifest
lists under the optional `listener_data_files` field (paths relative to the listener module's own
directory). The hash is over a `{relpath: bytes}` map covering the module *and* every declared
data file, so `register`'s version-immutability check and the brain's pre-import verification both
catch drift in either one; a listener with no `listener_data_files` behaves exactly as the
historical single-file case (`listeners.py`'s `_collect_closure`/`load_frozen_listener`).
**Hash ≠ signature:** the stored hash catches accidental drift + enforces version discipline, but
is not a defense against an attacker who can write both the material and the catalog row; a
*signed* delivery channel to the brain host is the still-open O10 sub-item (deferred, multi-host
prod / production-hardening territory — dev assumes co-located artifacts on one filesystem).

## Scope

The control plane is the internal-only (behind VPN, inv 10) management layer. It:

1. **Ingests** bait manifests (parses, validates, runs the ingestion validation rules above,
   loads the `BoobyBait` class, runs `golden_cases()` offline), then **freezes the listener** into
   the material store + records its `listener_hash` on the design (O10/O11, version-immutability).
2. **Manages the catalog** (design + instance rows in the `control_plane` Postgres schema;
   lifecycle state transitions inside row-locking transactions, O3 — the O8 snapshot seq counter
   is gone with the dead-drop change).
3. **Runs the factory**: generates a per-instance HMAC-SHA256 master key `_KEY` + random
   `instance_token` at `build`, resolves the manifest's `build_vars` from the instance config,
   and drives the three-component build (the locked staging-vessel contract: a single structured
   `context.json` arg in, an `artifact.json` output declaring every produced file) — bundle
   `payload_file` (via the bundler, with the injected constants) then run
   `staging_vessel/setup.sh <context.json>` — validating the vessel's `artifact.json` declaration
   and recording the artifact descriptor in the instance record. `primary` comes from the
   vessel's declaration (no longer alphabetically sorted). `_KEY` is written **directly to the
   brain's key directory** (see "Brain key directory — write side" above), never to the registry.
   (There is no `bait.build()` method in the current `Listener` model; the factory owns the build
   pipeline.) The factory also enforces one **operator-doc placement rule**: a vessel
   may write `<output_dir_root>/how_to_stage.md` (short, per-build staging/trigger instructions for
   a human operator — see `docs/bait-authoring.md` §5's "Output: `how_to_stage.md`" subsection) —
   recommended but advisory (its absence only appends to `BuildOutcome.warnings`, never fails
   the build), so existing vessels can adopt it gradually. `warnings` flows
   through the same `BuildResult`/`ForgeResult.warnings` → `render.note()` pipeline every other
   build/register warning already uses — not a Python `logging` call, which the console never
   configures a handler for and would have been effectively invisible to an operator. What *is*
   hard-enforced: declaring `how_to_stage.md` in `artifact.json`'s `files` map (i.e. staging it
   into `to_stage/`, which is what ships to the honeypot) is a `BuildError` — an operator-only
   doc must never reach the attacker.
4. **Writes the brain key directory** (the **sole** directory now — see "Brain key directory —
   write side" above): it carries `_KEY`, is written directly by the factory at `build()` time,
   and its routing/status fields are refreshed on every lifecycle transition (via the post-commit
   `publish` callback). It is never distributed to the edge — the dead-drop edge holds no
   directory at all, so there is no edge routing directory or signed snapshot anymore.
5. **Enforces the human approval gate** (`pending → active` requires explicit operator `approve`
   command).

## Scope boundary (what this module is NOT)

- Not a sensor: never deploys payloads to live targets.
- Not the brain: does not consume from NATS, does not interpret telemetry.
- Not Tier-2: does not manage sessions or the actor graph.
- The catalog is the *source of truth*; the key directory is a *read-only projection* of it.

## Plan

The registry is the `control_plane` Postgres schema (D1/D2). GitOps
PR-as-approval-gate can be layered in later without changing the schema. Since the system was not
yet live, there was **no flat-file→DB backfill** — a fresh `forge` populates the catalog.

Module roles:

1. `schema.py` — the catalog DDL (`ensure_catalog`) + role/grant bootstrap
   (`ensure_roles_and_grants`, superuser). Idempotent, schema-name parametrised (per-test
   isolation).
2. `registry.py` — DB-backed `Registry` (same `get_/put_/list_` interface, D6) + the `transaction()`
   row-locking view (O3, `FOR UPDATE`); the `DesignRecord`/`InstanceRecord` dataclasses. Postgres
   for `design`/`instance` (no `snapshot_state` table, no `dirsign/` FS secret — both removed with
   the dead-drop change); the only non-DB state is the material store `artifacts/`.
3. `listeners.py` — freeze the listener closure to the material store + hash it (O10), the
   register-time immutability check (O11 #1), and the brain-side hash-verified load (O11 #3).
4. `ingestion.py` — full validation rules (see "Ingestion validation rules" above): parse
   manifest.yaml, check bait_id uniqueness, verify provenance fields non-empty, check channel
   receivers exist, run ABC check, run `golden_cases()` offline. Returns structured errors, never
   silent passes.
5. `factory.py` — per-instance HMAC-SHA256 master-key generation (stdlib `secrets.token_bytes`),
   `BuildContext` construction, hermetic build sandbox invocation (today: subprocess with controlled
   env), artifact recording, **and pinning the design's `listener_hash` onto the instance** (O11
   #2). `BuildOutcome.key_hex` transiently carries `_KEY` back to the caller so it can be written
   to the brain's key directory — the only window in which the key exists outside the built
   artifact (inv 16). Outputs are organized into
   `<artifacts-root>/<bait_id>/<timestamp>/bundling_outputs/` (bundler intermediates) and
   `.../to_stage/` (vessel-produced deployment-ready files); `artifact.json` and the optional
   `how_to_stage.md` (see the operator-doc placement rule under "Scope" above) live in the parent
   `<bait_id>/<timestamp>/` directory, alongside those two, never inside `to_stage/`.
6. `lifecycle.py` — state transition functions for both state machines (see "Lifecycle state
   machines" above). Each transition runs its mutation(s) inside one `Registry.transaction()` (O3):
   read `FOR UPDATE`, validate, write; then (if a `publish` callback is given) refresh the brain
   key directory *after* commit. No publish `seq`, no snapshot files anymore (dead-drop edge).
7. `brain_keydir.py` — writes the brain's key directory, the **sole** directory now (see "Brain
   key directory — write side" above). `upsert_key_entry()` is called once by the factory at
   `build()` time (the only place `_KEY` bytes exist transiently); `sync_routing_fields()` refreshes
   status/routing fields on every lifecycle transition, merging against existing entries (the
   catalog never stores `key`).
8. `forge.py` — a one-shot `register → build → approve` over a self-sufficient manifest
   (`deploy:` block). The orchestration lives in the CLI-agnostic `forge_bait()` function so the
   `blacksea` operator console can wrap it without re-implementing the chain; it takes an
   `operations.Ctx` and is the sole forge entry point (there is no argparse forge script).
9. `operations.py` — the CLI-agnostic lifecycle operations shared library (D2/console PLAN): each
   verb as a plain function returning a result dataclass / raising a typed error, consumed by the
   `blacksea` console frontend. (The flat-verb argparse CLI that was the second frontend —
   `cli.py` + `__main__.py`, `python -m blacksea.control_plane` — has been **removed**; the
   console is the sole frontend now, so there is exactly one `Ctx` and one `parse_kv`.)

Record dataclasses (`DesignRecord` — see "Registry record (runtime extension)" above,
`InstanceRecord` — see "Instance record fields" above) live in `registry.py`.

Exit criterion: start from a blank registry; run `register → build → approve`; the brain's key
directory (`brain_keydir.json`) contains the matching entry with `_KEY`; fire the payload; the
edge forwards it opaquely to `bait._ingest` and the brain resolves routing from `tok` and decrypts
it. There is no edge routing directory or snapshot to check — the dead-drop edge holds none.

## Dependencies

- `sdk/` — `BoobyBait`, `BuildContext`, `Artifact`, `GoldenCase`, SDK types
- The per-instance `_KEY` is stdlib `secrets.token_bytes` (the HMAC-SHA256 master key), no longer
  AES-256-GCM or an Ed25519 keypair. **No crypto library is used anymore:** the `cryptography`
  (Ed25519 directory-signing) and `cbor2` (deterministic signed span) dependencies became dead when
  the edge snapshot / `dirsign` key were deleted — nothing under `control_plane/` imports either
  now (any vestigial entry in the consolidated `services/pyproject.toml` can be pruned).
- `PyYAML` — manifest.yaml parsing
- `psycopg[binary]` — **required** now (D1/D2): the catalog is Postgres. `register`/`build`/
  `approve`/`forge` hard-depend on `POSTGRES_DSN` (O7). Uses `psycopg.sql` for injection-safe
  schema-qualified DDL/queries and `psycopg.types.json.Jsonb` for the `manifest`/`callback_addresses`/
  `artifact` columns.
- `blacksea.config` (settings) — operational defaults: `POSTGRES_DSN`, `BS_CP_SCHEMA`, registry/
  brain-keydir/artifacts/sdk-root paths (the `blacksea` console's global-flag defaults, carried
  into `operations.Ctx`), and the staging-vessel subprocess timeout in `factory.py`
- No dependency on `brain/` or `correlation/` — `brain_keydir.py` writes a file the brain reads,
  and `listeners.load_frozen_listener` is *imported by* the brain (a pure stdlib helper — no DB, no
  brain code); the control plane still imports nothing from `brain/`

## Invariants enforced here

- inv 8: factory produces immutable artifacts; no live management of sensors.
- inv 10: control plane is internal-only (behind VPN); the CLI must never be exposed publicly.
  **Under D2 it now shares a DB with the internet-facing brain** — mitigation moved from "different
  store" to "same store, isolated by role grant" (O6: `brain_role` is `SELECT`-only on the
  control tables, with no write anywhere in the schema; proven by `test_schema.py`). The *edge*
  still never touches Postgres.
- inv 15: `campaign_id` + `callback_addresses` are per-instance; campaign scoping is enforced
  here at `build()` time.
- inv 16: **held under D3.** `_KEY` is injected into the artifact and the brain's key directory,
  never persisted in the catalog; only `key_ref` (a pointer) is stored there. Unifying into the
  brain's DB re-opened this (the registry no longer had a "never holds keys by construction"
  firewall), and the decision was to **hold the line** — no secret enters the DB; `_KEY` stays on
  the filesystem (in the brain key directory). There is no `dirsign.key` anymore — the
  directory-signing key was eliminated with the dead-drop change, so `_KEY` is now the only key
  material the control plane handles. Locked by `test_registry.test_key_never_stored_in_db`.
- **Cross-record atomicity + writer serialization** (O3, a primary reason this migration exists):
  multi-record lifecycle transitions run in one `Registry.transaction()` (`FOR UPDATE` locks).
  Locked by `test_registry`'s transaction/concurrency tests. (The former O8 monotonic-seq counter
  was removed with the dead-drop change — there is no publish `seq` anymore.)
- inv 18 (trivial now): the edge holds **no** directory, so the control plane distributes nothing
  to it — there is no static distribution point and no edge poll. The brain key directory is
  written directly (server-to-server, both trusted, internal-only) and never crosses the
  edge-facing diode.
- Provenance gate (see "Ingestion validation rules" above): registration fails if any provenance
  sub-field is empty.

## File list

The package lives at `src/blacksea/control_plane/`, part of the single `blacksea` distribution
(root `services/pyproject.toml`, `pip install -e .` via `make install` — same layout as `sdk`
and `brain`, no per-module packaging or `PYTHONPATH`).

| File | Description |
|---|---|
| `__init__.py` | Package marker (imported, not run — the flat-verb `python -m blacksea.control_plane` CLI, `cli.py` + `__main__.py`, has been **removed**; the `blacksea` console is the sole operator frontend over `operations.py`) |
| `forge.py` | One-shot `register → build → approve` from a self-sufficient manifest, driven by `blacksea forge`. Reads the manifest's `deploy:` block (`campaign`, `callbacks`, optional `build_vars`, `approve`) via `load_deploy_config()` (console flags `--campaign`/`--callback`/`--set`/`--no-approve` override it), then runs the chain in the CLI-agnostic `forge_bait()` library function (takes an `operations.Ctx`) — reusing `ingest` → `factory.build_instance` → `brain_keydir.upsert_key_entry` → `lifecycle.approve_instance` (whose `publish` callback runs `brain_keydir.sync_routing_fields`) (no logic duplicated). `forge_bait()` is what the `blacksea` console `forge` command wraps (its only caller besides the tests); there is no argparse forge script anymore. The optional operator note is sourced by `load_deploy_config()` from a `--comment` console flag (wins) or a `deploy.comment` manifest field, carried on `DeployConfig.comment` → `factory.build_instance(comment=…)` → the instance's `comment` column. `BuildResult`/`ForgeResult` echo `comment`; `BuildResult.artifact_dir` carries the staged `to_stage/` directory (while `ForgeResult.artifact_path` stays the primary file for the e2e harness). |
| `schema.py` | Catalog DDL runner: `ensure_catalog()` (schema + `design`/`instance` tables — no `snapshot_state` anymore, idempotent, no privilege needed) and `ensure_roles_and_grants()` (the O6 `cp_role`/`brain_role` grant matrix, superuser). Schema-name parametrised + validated (per-test isolation) |
| `registry.py` | `DesignRecord` + `InstanceRecord` dataclasses (now with `listener_hash`); **Postgres-backed** `Registry` (same `get_/put_/list_` interface, D6) using `psycopg.sql` + `Jsonb`; the `transaction()` `FOR UPDATE` row-locking view (O3). No `next_seq()`/`snapshot_state` and no `dirsign_dir` FS secret — both removed with the dead-drop change; the only non-DB state is the material store `artifacts/`. `DesignRecord.test`/`.version`/`.assurance_tier`/… are manifest-derived properties |
| `listeners.py` | Freeze the listener closure → `<artifacts-root>/<bait_id>/<version>/listener/` + sha256 it (O10); `freeze_and_check()` (register-time version-immutability, O11 #1); `load_frozen_listener()` (brain-side hash-verified import, O11 #3). Pure stdlib — imported by the brain |
| `ingestion.py` | Validation rules (see "Ingestion validation rules" above): parse manifest.yaml, provenance gate, channel check, isolation/tier rules, envelope-version, `test` flag type check, ABC check, golden-test gate; returns structured `Issue`s (error/warn) |
| `factory.py` | Per-instance HMAC-SHA256 master key `_KEY` + token; `LocalBuildContext` (bundle + staging vessel with separated `bundling_outputs/` and `to_stage/` directories); `build_vars` resolution; artifact recording; **pins the design's `listener_hash` onto the instance** (O11 #2); key never persisted in the catalog (inv 16) — `BuildOutcome.key_hex` is transient, for the caller to write to the brain's key directory |
| `lifecycle.py` | Transition functions for both state machines (see "Lifecycle state machines" above); each runs its mutation(s) inside one `Registry.transaction()` (O3, `FOR UPDATE`), then (if given a `publish` callback) refreshes the brain key directory after commit — no publish `seq`, no snapshot files |
| `brain_keydir.py` | Brain's key directory, the **sole** directory now (see "Brain key directory — write side" above): `upsert_key_entry()` (factory writes `_KEY` at build time) + `sync_routing_fields()` (lifecycle transitions refresh status/routing, never touching `key`) |
| `operations.py` | CLI-agnostic lifecycle-operations shared library (D2/console PLAN): each verb as a plain function returning a result dataclass / raising a typed error; wires a `Ctx` from a DSN + schema. The `blacksea` console owns all formatting |
| `tests/control_plane/` | pytest suite (Postgres-backed, per-test throwaway schema — skips cleanly with no DB): `test_schema.py` (DDL idempotency + O6 grant isolation), `test_registry.py` (round-trips, inv-16 no-key-in-DB, O3 transaction atomicity + concurrency), `test_listeners.py` (freeze/hash/immutability/verify), `test_lifecycle.py` (transitions), `test_brain_keydir.py` (the sole key directory), `test_factory.py` (build), `test_ingestion.py` (the validation gate), `test_operations.py` (the CLI-agnostic verb layer), and `test_forge.py` |
