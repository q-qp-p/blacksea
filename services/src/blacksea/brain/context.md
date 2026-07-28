# brain/ — Analyzer pool + framework record assembly + storage

**Status:** implemented.  
**Language:** Python 3.11+  
**Contracts:** This file is self-contained. It locks: the record model produced by
`interpret(envelope, body) → Record` — the frozen common field set, the `record_id` format, the
`event_type` enum, the `signals` sub-object, and the `details` blob rules (see "Record field
set" below); the guarantees the framework makes around calling `interpret()` (same section); the
assembly model — framework-set fields taken from the verified envelope always win over
analyzer-returned fields, so an analyzer that tries to set `instance_token`/`campaign_id`/
`sig_valid` has those values silently overwritten; and the fact that the brain is the sole
cryptographic authority that authenticates + decrypts `enc` (HMAC-SHA256 AEAD — this revises the
prior Ed25519 re-verify and, later, AES-256-GCM constructions) against its own key directory —
now the **sole** key directory in the system, since the dead-drop edge holds none (see "Package
layout" below).

> **On the `§3.x` citations** in this module's code, `schema.sql`, and tests: they are stable
> internal cross-reference labels inherited from a plan document that has since been retired, its
> content folded into this file. Read them as pointers to the matching material below — `§3.0`
> the assembly model, `§3.1` the record field set, `§3.2` the `record_id` format, `§3.4` the
> `signals` sub-object, `§3.5` the `details` blob + size cap. `§1.x` belongs to `edge/context.md`,
> `§5.x` to `control_plane/context.md`, and `§6.x` to `correlation/context.md`, each of which
> carries the same note. There is no longer any external document to look them up in.

## Scope

The brain sits behind the NATS queue (inv 2, inv 3). It:

1. Consumes the NATS `bait.>` firehose — the dead-drop edge publishes every hit to one subject,
   `bait._ingest`, carrying only `tok` + the opaque `enc`/tier-0 fields + the `edge` stamp (no
   routing facts). The brain is the sole router.
2. Resolves `bait_id` from the outer `tok` against its own key directory (`verifier.resolve_entry`,
   read as `entry.bait_id`) — an unknown/malformed `tok` maps to `""` → dead-letter — and uses it to
   pick the listener.
3. Authenticates + decrypts `enc` (HMAC-SHA256 AEAD, `tok` bound into the tag) against its own
   key directory — the brain is now the **sole** cryptographic authority; the edge never decrypts
   (inv 13 revised). Tier-0 vs tier≥1 is decided from the **channel** (DNS = the sole tier-0
   channel), not an edge-supplied `assurance_tier`; the record's authoritative `assurance_tier`
   comes from the keydir entry. The directory is hot-reloaded: a background poller re-reads
   `brain_keydir.json` on an interval and atomically swaps the live directory, so `build`/
   `approve`/`burn`/`retire`/`revoke` become visible to an already-running pool without a restart
   (`keydir_poller.py`).
4. Lazy-imports the correct `Interpretable` module for the `(bait_id, version)`.
5. Calls `interpret(envelope, body)` under timeout + memory cap.
6. Assembles the full `Record` (see "Record field set" below) by merging the verified envelope
   fields with the `AnalyzerOutput` — the assembly model ensures analyzers cannot override
   framework fields. `orphan` is brain-derived here: `instance_status ∈ {burned, retired}` from
   the keydir (`instance_status_for`), since the edge no longer supplies it.
7. Writes the assembled record to Postgres.

The brain also provides the **verifier** (HMAC-SHA256 AEAD decrypt, inv 13) and the **Postgres
storage client** (schema + read/write). Session records and actor graph (Tier-2) share the
same Postgres instance but are written by `correlation/`, not here.

## Scope boundary (what this module is NOT)

- Not the edge: never reachable from the internet (inv 2).
- Not Tier-2: the brain writes Records; it does not build sessions or the actor graph.
- Not the control plane: no registry access, no lifecycle commands, no factory.
- Analyzers (`Interpretable`) are loaded here at runtime, but authored in `baits/`.

## Record field set

The record is the output of `interpret(envelope, body) → Record` and is both the input to
storage and the input the correlation engine reads. It has three parts:

```
interpret(envelope, body)
        │
        ▼
COMMON FIELDS  (frozen waist)                   ← correlation reads these
SIGNALS        (optional, correlation-readable) ← analyzer may promote key signals
DETAILS        (opaque body)                    ← correlation passes through; console/observer reads
```

Correlation reads common fields + `signals`; it never parses `details`. Storage persists the
whole record.

### Assembly model — who sets what

`interpret()` returns only the bait-specific part: `{event_type, signals?, details}`. The
framework assembles the full record by merging the verified envelope fields into it. The
analyzer never writes identity/routing/trust fields — those are trust-locked by the framework
from the brain-verified envelope. Hard contract: an analyzer that tries to set
`instance_token`/`campaign_id`/`sig_valid` has those values silently overwritten by the
framework.

```
Full record = framework_fields(verified_envelope) ∪ analyzer_output(event_type, signals?, details)
```

### Common field set (frozen)

All fields below are set by the FRAMEWORK from the verified envelope unless marked (analyzer).

Identity / routing:

| Field | Type | Source | Purpose |
|---|---|---|---|
| `record_id` | string 38 chars | framework | deterministic compound key; enables idempotent replay |
| `bait_id` | string | framework ← signed.bait_id | which bait produced this record |
| `bait_version` | semver string | framework ← registry | which version of the analyzer ran |
| `instance_token` | 16-char hex (8B) | framework ← signed.instance_token | master key; joins to instance record + key directory |
| `campaign_id` | string | framework ← directory derivation | compartment scope |
| `assurance_tier` | uint8 0/1/2 | framework ← keydir entry (tier-0 vs tier≥1 decided from `channel`) | trust level of this record |
| `deploy_class` | enum | framework ← registry | denormalized for idle-gap logic; avoids registry lookup per record |

Session correlation:

| Field | Type | Source | Purpose |
|---|---|---|---|
| `session_id` | 16-char hex (8B) | framework ← signed.session_id | groups events from one interaction |
| `seq_no` | uint16 | framework ← signed.seq_no | event order within session; 0 = single-shot |
| `event_type` | enum string | analyzer | classification of this event |

Timestamps:

| Field | Type | Source | Trust tier | Purpose |
|---|---|---|---|---|
| `edge_recv_time` | uint64 ms | framework ← edge.edge_recv_time | observed | authoritative time for attribution/timelines |
| `sensor_time` | uint64 ms | framework ← signed.sensor_time | claimed | sensor-asserted time; intra-session ordering only, never cross-session attribution |

Observed source:

| Field | Type | Source | Trust tier | Purpose |
|---|---|---|---|---|
| `observed_source.ip` | string | framework ← edge.observed_source.ip | observed | edge-stamped source IP |
| `observed_source.ja3` | string\|null | framework ← edge.observed_source.ja3 | observed | TLS fingerprint; null for DNS/non-TLS |
| `observed_source.source_type` | enum client\|resolver | framework ← channel | observed | client=direct IP (HTTPS/TCP, strong); resolver=recursive DNS (weaker) |

Integrity / provenance:

| Field | Type | Source | Purpose |
|---|---|---|---|
| `sig_valid` | bool | framework | brain's authoritative decrypt+auth result; false = details especially suspect |
| `channel` | enum string | framework ← QueuedEnvelope.channel (edge-stamped) | which physical channel delivered this hit; drives the tier-0/tier≥1 decision |
| `edge_id` | string | framework ← edge.edge_id | which edge node received |

Status flags:

| Field | Type | Source | Purpose |
|---|---|---|---|
| `orphan` | bool | framework ← keydir (`instance_status ∈ {burned, retired}`) | true if instance was burned/retired at receive time (late hit = intel, never dropped); brain-derived — the edge no longer supplies it |
| `instance_status` | enum | framework ← brain key directory (`instance_status_for`) | instance lifecycle state at receive time (active\|burned\|retired\|revoked) |
| `design_status` | enum | framework ← catalog (live, per hit) | design lifecycle state at receive time (deployed\|burned\|retired), read live from the control-plane catalog — no longer hardcoded (O2) |
| `test` | bool | framework ← manifest `test` field (default false) | marks a hit from a test/example/reference bait — not real attacker telemetry; surfaced in the observer UI |

### `record_id` format

```
record_id = <instance_token_hex(16)>-<session_id_hex(16)>-<seq_no(4-char 0-padded hex)>
```

Example: `9f86d081884c7d65-a3f2b1c4e5d6f708-0003`. Deterministic → re-ingesting the same event on
crash-recovery replay yields the same `record_id` → storage upserts are idempotent. Unique per
legitimate event (same triple can't appear twice from an uncompromised sensor); a replayed
identical record dedups by `record_id` and is flagged as a replay signal.

### `event_type` enum — locked core values

| Value | Session cardinality | Tier | Meaning |
|---|---|---|---|
| `tripwire_fire` | 1 | 0-2 | honeytoken/tripwire touched; seq_no always 0 |
| `payload_exec_collect` | 1 (or few for chunked DNS) | 1-2 | portable artifact executed and reported |
| `honeypot_access` | first of N | 0-2 | interactive service: initial contact/TCP connect |
| `honeypot_auth` | middle of N | 1-2 | interactive service: authentication attempt |
| `honeypot_command` | middle of N | 1-2 | interactive service: command executed |
| `honeypot_fileop` | middle of N | 1-2 | interactive service: file read/write/delete |
| `honeypot_disconnect` | last of N | 0-2 | interactive service: session ended — explicit close signal |
| `signal_only` | 1 | 0 | tier-0 generic signal; DNS hit with no further classification |

Additive-only: new values may be added; an unknown `event_type` is stored tagged
`{unknown_event_type: true}`, never crashes.

### `signals` sub-object — optional, correlation-readable

| Signal field | Type | Purpose |
|---|---|---|
| `fingerprint_hash` | string (hex digest) | strong actor-graph node — hash of harness fingerprint content; claimed-tier (forgeable on a popped box) but heavily weighted when corroborated |
| `caution_level` | enum none\|low\|medium\|high | burn-detection input — how cautiously the agent handled the lure |
| `explicit_session_end` | bool | set by the analyzer on a disconnect event to tell correlation this session is definitively closed (vs idle-gap timeout) |

Additive-only; correlation ignores unknown fields. An analyzer must never set a signal it can't
honestly compute — a fake `caution_level: high` poisons burn-detection. `signals` is
null/omitted for tier-0 `tripwire_fire`/`signal_only` events with empty body.

### `details` blob — opaque body

JSON object written entirely by the analyzer; bait-specific intel. Rules: JSON object only; size
cap declared per-bait in `manifest.yaml`, enforced by the framework before accepting
`interpret()`'s return — default cap 256 KB, oversize → truncated + `details_truncated: true`
flag added by the framework; correlation NEVER parses it (promote to `signals` instead);
`details` is attacker-influenced content — any LLM ever in the analysis loop must treat it as
inert data, never instructions; may be null for tier-0 `signal_only`/`tripwire_fire` events.

### Framework guarantees around `interpret()`

Before `interpret(envelope, body)` is called:

1. The brain has decrypted `enc` against its authoritative key directory → `envelope.sig_valid` is set.
2. `envelope.bait_id` is derived from the outer `tok` against the brain key directory
   (`resolve_entry` → `entry.bait_id`); if `tok` is unknown/malformed (→ `""`) or the resolved
   bait_id is not in the catalog / its frozen listener is unavailable, the hit dead-letters and
   `interpret()` is never called.
3. `body` size is checked against the per-bait cap (the `manifest.yaml` details size cap) —
   an oversize body is truncated before the call; `details_truncated: true` is appended after.
4. The call is wrapped in a wall-clock timeout (`asyncio.wait_for`, `BS_INTERPRET_TIMEOUT`). A
   CPU-time limit and a memory cap are not yet enforced — deferred to production hardening
   (inv 11 partial; see "Implementation notes" below).
5. If `interpret()` raises any uncaught exception → dead-letter + alert; the pool process
   continues (crash containment).

After `interpret()` returns:

1. `event_type` is validated as a non-empty string; an unknown value is logged and stored as-is.
2. `details` size is capped; `details_truncated: true` is appended if over.
3. The framework assembles the full `Record` by merging envelope fields + `AnalyzerOutput`.
   Analyzer-returned values CANNOT override framework-set fields (`sig_valid`,
   `instance_token`, `campaign_id`, etc — the assembly rule above).
4. The record is written to storage.

On lifecycle hooks (`on_register`/`on_deploy`/`on_burn`/`on_retire`): called synchronously by
the pool process, under the same timeout + no-ambient-authority constraints as `interpret()`; a
hook that raises is logged and ignored — it does not affect pool health.

## Plan

Build order:

1. `verifier.py` — HMAC-SHA256 AEAD decrypt (inv 13); consumes the raw `enc` bytes from the
   queued envelope; reads `_KEY` from an in-memory key snapshot loaded from the brain's own
   key directory file — now the sole key directory in the system (the dead-drop edge holds none).
   Also owns the routing derivation the edge no longer does: `resolve_entry()` maps `tok`→the
   directory entry (`entry.bait_id`, unknown/malformed token → `None` → bait_id `""`),
   `instance_status_for()` maps `tok`→instance_status, and `verify()` picks tier-0 vs tier≥1 from
   the `channel` (DNS is the sole tier-0 channel). `verify_with_entry()` takes an already-resolved
   entry so the pool looks a hit up exactly once (`resolve_entry`, then decryption, then the status
   stamp all share that one entry); `verify()` is a thin `resolve_entry` + `verify_with_entry`
   wrapper kept for callers (tests, standalone use) that haven't already resolved the entry.
2. `assembly.py` — builds a full `Record` dict from `(verified_envelope, AnalyzerOutput)`;
   enforces the assembly model above (framework fields win over analyzer fields).
3. `storage.py` — Postgres client: `write_record()`, `read_record()`, `list_records()`, and
   `heartbeat()` (see the brain-health heartbeat below). Schema matches the common field set above
   exactly (regular columns for common fields; jsonb for `details`).
4. `schema.sql` — Postgres DDL for the `records` table **and** the `brain_health` heartbeat table
   (below).
5. `pool.py` — the analyzer worker pool: consumes from NATS JetStream, dispatches to
   `interpret()`, catches exceptions, dead-letters on failure, writes records. It also runs the
   liveness heartbeat loop (below). Today a single worker process is sufficient.
6. `keydir_poller.py` — hot-reload for the brain's key directory: a `KeyDirectoryHolder`
   whose `.current` is swapped wholesale by a background poll loop; `pool.run()` reads
   `holder.current` per message instead of a `KeyDirectory` captured once at startup.

### BAITS stream provisioning + disk caps

`pool.py`'s `_ensure_stream` provisions the shared `BAITS` JetStream stream (subjects `bait.>`)
using the config built by **`_baits_stream_config()`** (split out so the limit fields are
unit-tested by `tests/brain/test_stream_config.py` without a live NATS). The stream carries a disk
cap **`max_bytes`** (`settings.NATS_MAX_BYTES`, default 1 GiB) and an age cap **`max_age`**
(`settings.NATS_MAX_AGE_S`, default 604800s = 7 days), with `discard=OLD`; retention stays
`LimitsPolicy`, storage `FileStorage`. Without a cap, `LimitsPolicy` never evicts an acked message,
so the stream grows into an append-only log of every hit an unauthenticated party can publish
through the edge's beacon endpoints — an unbounded disk-exhaustion DoS. `0` for either dimension is
the "unbounded" sentinel (the builder maps it to NATS's `None`); it reopens the gap.

`_ensure_stream` calls `add_stream` (creates a fresh stream) and, if the stream already exists,
falls back to `update_stream` so a stream an older unbounded build created is **tightened** to the
current caps on the next brain start (retention/storage are unchanged, so update never touches an
immutable field). These defaults MUST equal the edge's `baitsStreamConfig` in `edge/queue.go` —
both provision the same stream and the edge's `CreateOrUpdateStream` re-applies its caps on every
edge start, so a mismatch lets whichever side runs last silently re-widen the stream. The
server-level `max_file_store` backstop lives in `scripts/nats-server.conf`.

### Brain-health heartbeat (a console cross-module change)

The brain upserts a single-row `brain_health` table (`last_poll_at timestamptz`, optional
`consumer_lag`) every `BS_BRAIN_HEARTBEAT_S` seconds (default 10) on its own dedicated autocommit
connection — `storage.heartbeat()`, driven by `pool._heartbeat_loop`, seeded once at startup. This
is the one authoritative liveness signal for the brain: `blacksea status` reads the row against
`BS_BRAIN_HEARTBEAT_STALE_S` (default 30), so a brain that has silently stopped consuming shows
`stale`, never a false green (see `src/blacksea/console/context.md`'s infra-status contract).

`brain_health` lives in the brain's **own (public) schema next to `records`** — which the brain
already writes — **not** the `control_plane` schema, where `brain_role` is `SELECT`-only and could
not write it. A heartbeat failure is logged and never crashes the worker (inv 11) —
the row simply goes stale, which is exactly the "brain stopped" signal the console reports.

Exit criterion: fire the first registered bait against the local edge + NATS + pool.
A `Record` appears in Postgres with `sig_valid: true`, `event_type` set, and `signals`
populated per the bait's `interpret()` output.

## Dependencies

- `sdk/` — `Envelope`, `AnalyzerOutput`, `Interpretable`, `TypedEvent` (for the projection
  the brain builds before forwarding to Tier-2)
- `nats-py` — NATS JetStream consumer
- `psycopg[binary]` — Postgres client
- No third-party crypto dependency — the HMAC-SHA256 AEAD (`verifier.py`) uses only stdlib
  `hmac`/`hashlib` (revises the prior `cryptography` `AESGCM` use, itself a revision of the
  original `Ed25519PublicKey` use)
- `blacksea.config` (settings) — operational defaults: interpret timeout, NATS stream/
  consumer + subject filter, the BAITS-stream disk caps (`NATS_MAX_BYTES`/`NATS_MAX_AGE_S`, issue
  #19 — must match the edge), and keydir path in `pool.py`; the details size cap (see "`details`
  blob — opaque body" above) in `assembly.py`
- No dependency on `control_plane/` or `correlation/` (brain only writes; `correlation` reads
  from the same Postgres instance independently)

## Invariants enforced here

- inv 2/3: brain is internal-only, not internet-reachable. The pool consumes from NATS; it
  does not have an inbound listener.
- inv 11: pool processes are separate from control logic; analyzers run under timeout + memory
  cap; crash in `interpret()` → dead-letter + alert, pool continues.
- inv 12: `details` is stored as opaque jsonb; the brain never interprets its content.
- inv 13: brain authenticates + decrypts `enc` against its own authoritative key directory —
  the sole place decryption ever happens now. A compromised or malicious edge cannot forge or
  read plaintext: it never holds `_KEY` (this revises the prior "edge cheap rejection + brain
  re-verify" dual-check model, under which the edge held a key of its own to reject obviously
  bad hits cheaply before forwarding). The directory is hot-reloaded (`keydir_poller.py`, poll
  interval `BS_BRAIN_KEYDIR_POLL_S`): every write to `brain_keydir.json` (`build`, `approve`,
  and the status refresh from `burn`/`retire`/`revoke`) reaches an already-running pool within
  one poll interval instead of only on the next restart — locked by
  `tests/brain/test_keydir_poller.py`. `verify()` itself does not *drop* on `entry.status` yet, but
  the pool now stamps each record's `instance_status` from the brain-authoritative directory
  (`instance_status_for()`) — and derives `orphan` = `instance_status ∈ {burned, retired}` from
  it, since the dead-drop edge no longer supplies either — so revoked/burned/retired hits are
  flagged in the store per the status-flags fields above (drop/gate remains a separate,
  not-yet-scoped concern); the hot-reload keeps that status fresh. `verify()` additionally logs
  (does not drop) a tier≥1 hit that falls outside its validity window (defense in depth). No
  signing/anti-rollback is applied to this file: it never crosses the edge-facing diode (the edge
  holds no directory at all now — there is no edge-side snapshot), so it is not exposed to the
  rollback/tamper threat that signing on an edge-distributed directory would defend against.
- Assembly model (see "Record field set" above): framework-set fields (`sig_valid`,
  `instance_token`, `campaign_id`, `bait_id`, `edge_recv_time`, etc.) are set from the verified
  envelope and cannot be overridden by the `AnalyzerOutput` return value.

## Package layout

Files live in `src/blacksea/brain/`, part of the single `blacksea` distribution (root
`services/pyproject.toml`). `import blacksea.brain.*` resolves because that distribution is
installed editable (`pip install -e .` via `make install`) — there is no `PYTHONPATH` export
and no per-module install. The Python deps are consolidated in `services/pyproject.toml`;
`make install` installs the one distribution.

Run the pool: `blacksea up` (starts it in the background with the local infra) or directly via
`python -m blacksea.brain.pool [--nats ...] [--postgres ...] [--keydir ...] [--artifacts-root ...] [--schema ...]`
— `--keydir` (default `secrets/keys/brain_keydir.json`, under the `0700` secrets tree) is the
brain's own key directory — now the **sole** key directory in the system (the dead-drop edge holds
none). The keydir poll interval is set via
`BS_BRAIN_KEYDIR_POLL_S` (default 10s) — not a CLI flag, since it's rarely tuned outside of
dev/e2e iteration.

**Bait loading — from the control-plane catalog, not a git dir (O2/O9/O10/O11).** The
old `--baits-dir` git scan (and the hardcoded `design_status="deployed"`) are **gone**. The pool
reads the design manifest + *live* lifecycle from the shared control-plane catalog
(`control_plane` schema, `SELECT`-only per O6 — `--schema`, default `control_plane`) and imports
the **frozen listener** from the material store at `--artifacts-root`/`<bait_id>`/`<version>`/
`listener/` (default `<registry>/artifacts`), **verifying the frozen bytes against the catalog's
pinned `listener_hash` before `importlib`** (O11 — mismatch ⇒ dead-letter, never import untrusted
code). Baits load lazily on first hit (so a bait forged after the brain started is picked up — the
e2e stack brings the brain up before forging) with a best-effort startup pre-load; `design_status`
is read live per hit (O2 — a burn is reflected without a restart). In dev the control-plane and
brain share one filesystem, so the frozen listener is co-located; a *signed* distribution channel
to a separate brain host is the still-open O10 sub-item (deferred). The catalog-read path lives in
`pool._ensure_bait` / `_fetch_design` / `_design_status` / `load_baits`, locked by
`tests/brain/test_pool_catalog.py`; the vertical slice through it is `tests/brain/test_e2e.py`.

## Authentication

The brain connects to **NATS** with a username/password (`NATS_USER` / `NATS_PASS`, both required —
`pool.main()` exits if either is unset) and to **Postgres** with a password DSN (`POSTGRES_DSN`,
required — no hardcoded default; the old `host=localhost ... password=blacksea` fallback was
removed from `pool.py` and `tests/brain/conftest.py`). NATS credentials are passed as separate kwargs, not
embedded in the NATS URL, so they never reach the `nats=...` line the pool logs. Locally all of these
come from `config/blacksea.env` (`make init`) and are wired by `blacksea up`; DB-backed tests skip
cleanly when `POSTGRES_DSN` is unset. Per-role NATS lockdown (edge publish-only) is deferred to
production hardening —
see `edge/context.md`.

## Implementation notes (judgment calls)

- **No separate pyproject.toml / installable package for the brain.** The brain is a service, not a library another module imports. Its files are part of the single `blacksea` distribution (root `services/pyproject.toml`, `pip install -e .` via `make install`) — no per-module packaging.
- **Body extraction for tier 0**: `obs_body` (base64, standard encoding — the DNS payload; DNS
  is the only tier-0 channel) is extracted in the pool after verifier returns; verifier returns
  `body=b""` for tier 0. For tier≥1 body comes from the decrypted fixed binary encrypted-core.
- **Fixed binary encrypted-core layout**: `ev(1B) ‖ session_id(8B) ‖ seq_no(4B) ‖
  sensor_time(8B) ‖ body(rest)` — no CBOR, no field names, fixed byte offsets. `bait_id`,
  `instance_token`, `campaign_id`, `channel`, `assurance_tier` are **not in the encrypted core**
  — derived from the key directory using the outer `tok` field.
- **bait_version** is not in the encrypted core; the pool patches it from the manifest via `dataclasses.replace()` after verifier returns.
- **HMAC-SHA256 AEAD security rationale** (`verifier.py`'s `open` / `payload/envelope.py`'s
  `seal`): HMAC-SHA256 keyed with the per-instance `_KEY` is a PRF, used two ways —
  `ke = HMAC(_KEY, b"bs-env-v2-enc")` drives a CTR-mode keystream (`HMAC(ke, nonce ‖
  counter_be4)` per 32-byte block) for confidentiality, and `ka = HMAC(_KEY, b"bs-env-v2-mac")`
  produces the tag (`HMAC(ka, nonce ‖ tok ‖ ev ‖ ct)[:16]`) for integrity — composed
  encrypt-then-MAC, `hmac.compare_digest` verified **before** any keystream XOR
  (verify-before-decrypt). Security reduces to "HMAC-SHA256 is a PRF," a standard assumption;
  the construction itself is non-standard (no library decrypts it — this is the whole ~12-line
  `open` and the payload's ~15-line `seal`), an accepted trade for a fully stdlib, CBOR-free
  envelope (see the *payload-import-minimality* invariant, `src/blacksea/sdk/context.md`).
  Nonce reuse under one `_KEY` repeats the keystream (a confidentiality loss — the classic
  two-time-pad problem) but does **not** leak `ka` or enable forgery, since HMAC is not a
  one-time authenticator the way a Poly1305/GHASH tag is — a genuine advantage over AES-GCM/
  ChaCha20-Poly1305 here, though a fresh 96-bit random nonce is still generated per message as
  defense in depth. The pure-Python XOR loop is not constant-time except for
  `hmac.compare_digest` itself; acceptable for a one-shot network beacon with no decryption
  oracle exposed on the target — this is not a side-channel-resistant implementation and should
  never be marketed as one.
- **interpret() isolation**: runs in a `ThreadPoolExecutor(max_workers=1)` thread with `asyncio.wait_for` timeout. Memory cap is deferred hardening (inv 11 partial).
- **Dead-letter**: on any failure the message is acked (to avoid requeue) and the error is logged. There is no dedicated dead-letter queue yet; add one when operational monitoring needs it.

## File list

| File | Description |
|---|---|
| `src/blacksea/brain/__init__.py` | Empty namespace package marker |
| `src/blacksea/brain/pool.py` | Analyzer worker pool: asyncio consumer of the `bait.>` firehose (the dead-drop edge's single `bait._ingest` subject), demux — resolves `bait_id` from `tok` via `resolve_entry()` (unknown/malformed → dead-letter), bait lazy-load from the catalog (including the manifest's `test` flag), `interpret()` under timeout, dead-letter on exception, write to Postgres; stamps the record's brain-authoritative `instance_status` via `instance_status_for()` and derives `orphan` from it; provisions the `BAITS` stream via `_baits_stream_config()` with `max_bytes`/`max_age` disk caps + `update_stream` fallback to tighten an existing unbounded stream; timeouts/NATS/subject/keydir defaults from `blacksea.config` |
| `src/blacksea/brain/assembly.py` | Framework record assembly: merges verified-envelope fields + `AnalyzerOutput` → full `Record` dict; enforces the assembly model (framework fields win over analyzer fields); applies the details size cap; sets `test` from the bait's manifest flag |
| `src/blacksea/brain/verifier.py` | HMAC-SHA256 AEAD decrypt (inv 13): key directory lookup, verify the tag with `tok` bound in (`hmac.compare_digest`, verify-before-decrypt), slice the fixed binary encrypted-core, `(Envelope, body, sig_valid)` return. Also owns the routing the dead-drop edge no longer does: `resolve_entry()` (`tok`→directory entry, unknown/malformed → `None`) and `instance_status_for()` (`tok`→`instance_status`, see "Status flags" in Record field set); `verify()` decides tier-0 vs tier≥1 from the `channel` (DNS = sole tier-0 channel) and takes the authoritative `assurance_tier` from the keydir entry; it also logs (does not drop) tier≥1 hits outside the validity window |
| `src/blacksea/brain/keydir_poller.py` | Hot-reload for `brain_keydir.json`: `KeyDirectoryHolder` + `poll_keydir()` background loop, atomic full-replace, never-fail-open on parse errors |
| `src/blacksea/brain/storage.py` | Async Postgres client (psycopg3): `write_record()`, `read_record()`, `list_records()`, `iter_typed_events()` |
| `src/blacksea/brain/schema.sql` | Postgres DDL for `records` table (common field set columns; `signals` + `details` as jsonb) |
| `tests/brain/_helpers.py` | Test fixtures: edge-shaped tier-0 / encrypted tier≥1 QueuedEnvelope builders (the encrypted builder calls the production SDK seal, `blacksea.sdk.payload.envelope.build_encrypted_envelope`), `FakeMsg` NATS stand-in |
| `tests/brain/conftest.py` | `pg_dsn` fixture — skips DB-backed tests when no Postgres is reachable (async tests drive their own loop via `asyncio.run`; no pytest-asyncio dep) |
| `tests/brain/test_verifier.py` | inv-13 decrypt: tier-0 unencrypted, valid/tampered-ciphertext/wrong-key tier≥1 decryption, structural errors, keydir load; HMAC-SHA256 AEAD regression locks (empty/large-body round-trip, nonce/tag tamper, verify-before-decrypt) |
| `tests/brain/test_keydir_poller.py` | Hot-reload: a rewritten `brain_keydir.json` becomes decryptable via `verify()` without recreating anything; a malformed rewrite keeps the last-good directory |
| `tests/brain/test_assembly.py` | Assembly framework-fields-win rule, `record_id` format, `signals` filtering, `details` cap |
| `tests/brain/test_storage.py` | Postgres round-trip, `record_id`-based idempotent upsert, list filters, TypedEvent projection strips `sensor_time`/`details` (integration; rolls back) |
| `tests/brain/test_pool_catalog.py` | Catalog-backed bait loading (O2/O9/O10/O11): lazy load + caching, hash-mismatch refusal, live `design_status`, `load_baits()` pre-load |
| `tests/brain/test_e2e.py` | Full vertical slice via `pool._handle`: hostname-probe fires → Record in Postgres; dead-letter paths ack without crashing (inv 11) |
| `tests/brain/test_stream_config.py` | Locks `_baits_stream_config()`: BAITS stream has positive `max_bytes`/`max_age` + `discard=OLD`, `0`→unbounded sentinel maps to `None`, and a **cross-language parity** test that parses `edge/config.go`'s `defaultNATSMaxBytes`/`defaultNATSMaxAgeS` and asserts the Python settings equal them (catches one-sided default drift a same-language literal can't; disk-cap regression guard; pure unit, no NATS) |

## Testing

`make test` runs the brain suite (among the others); for this suite alone run
`.venv/bin/pytest tests/brain -q`. The verifier/assembly tests are pure units; the
storage/e2e tests need Postgres (`blacksea up --infra-only`) and **skip cleanly** when none is
reachable. The full NATS→pool→Postgres path has been verified live against the
reference `hostname-probe` bait.
