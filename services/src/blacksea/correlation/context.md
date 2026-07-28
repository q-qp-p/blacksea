# correlation/ — the read/correlation layer over the record store

**Status:** the read-only view layer is implemented; the stateful session/actor engine
specified below is not built. (The module was renamed from `tier2/` — that name collided with
the payload's `assurance_tier` 0/1/2 concept and with the Tier-1/Tier-2 pipeline-stage
language.)
**Language:** Python 3.11+
**Contracts (future engine):** the full design spec for the not-yet-built stateful
correlation/attribution engine is authored **in this file** — see "Future — the stateful
correlation/attribution engine (planned, not built)" below. It was folded in from an earlier
plan document that has since been retired from the repo; this file is now the sole source of
truth for that engine's design, and nothing remains to migrate.
**The MVP below implements none of the stateful engine yet** — it is
the read-only view slice this module starts from and will grow into the engine described
below.

## Scope

`correlation` is the layer that turns the brain-written `records` log into
operator-facing views and (eventually) attribution.

### MVP — a shared, read-only view library (this is what exists today)

A single set of **read-only** query builders + row mappers over the Postgres
`records` table, so operator-facing consumers — the read-only web **observer** and
the future terminal **console** — render event, session, and health views from *one*
source of truth instead of each re-implementing the SQL. It:

1. Defines a composable `RecordFilter` and a set of frozen view value types
   (`RecordSummary`, `RecordDetail`, `SessionView`, `TimeBucket`, `CautionCount`).
2. Builds all view SQL from one `where_clause` primitive (`queries.py`) — the single
   place to add a filter dimension.
3. Exposes reader functions, each as a **sync + async pair** (`foo`/`afoo`) that share
   the exact same SQL builder and mapper — so the sync console and the async observer
   reuse one query definition. Views: `list_records`, `get_record`, `count_records`,
   `records_after`, `hit_rate`, `caution_distribution`, `session_views`.
   - `records_after(conn, cursor, filt=None, *, limit)` is the **keyset tail reader**
     added for `otel_export`: every record strictly after a
     `RecordCursor(edge_recv_time, record_id)`, ordered `(edge_recv_time, record_id)`
     ascending, capped at `limit`. It returns full `RecordDetail` views (observer
     parity — the emitter renders the *same* value object the observer displays). It
     exists because `RecordFilter.since_ms` alone is a *non-unique* `edge_recv_time`
     predicate: two hits in the same millisecond could be skipped or double-read across
     polls. The row-value comparison `(edge_recv_time, record_id) > (t, id)` (both
     columns `NOT NULL`) is the gap-free, duplicate-free page primitive. The cursor is a
     new value type (`RecordCursor` in `models.py`); the view value objects are
     unchanged. Locked by `test_queries.py::test_records_after_*` (builder) and
     `test_reader.py::test_records_after_*` (Postgres, incl. the same-ms tie case).
4. `session_views` groups records by `(instance_token, session_id)` at read time and
   keys on the §6.3 `session_record_id` form (`<itoken_hex>-<sid_hex>`) — a best-effort
   approximation (no idle-gap, no state machine) that the future engine described below
   will supersede behind the same shape.
5. Passes through the brain's `records.test` column (see `src/blacksea/brain/context.md`'s
   Record field set) on `RecordSummary`/`RecordDetail`/`SessionView` (the session variant is
   `bool_or(test)` over the grouped records) — display-only, so the observer/console can flag
   hits from a test/example/reference bait. Not a `RecordFilter` dimension (nothing filters on
   it yet); add one if a consumer needs it.

**It never writes to any table.** The `records` table is the brain's, append-only and
read-only from here.

### Future — the stateful correlation/attribution engine (planned, not built)

> **Terminology note:** the original design (drafted in the since-retired plan document)
> called this engine "Tier-2" — a pipeline-stage name, unrelated to and easily confused
> with the payload's numeric `assurance_tier` 0/1/2 field. That confusion is exactly why
> the module itself was renamed `tier2/` → `correlation/` (see the Status note above).
> The prose below uses "the engine" / "correlation" instead of "Tier-2" except where a
> field or table name is being quoted verbatim. The `§6.x` numbers are preserved from the
> original design purely as stable internal cross-reference labels for the subsections
> below — they no longer point outside this file.

This section is the **complete, self-contained build spec** for the stateful session
state machine and actor graph engine. It supersedes the retired plan document as the
authoritative design — an implementer should be able to build directly from what follows
with no other document.

#### §6.0 The read model the engine consumes

The engine reads a strictly narrowed projection of the full `Record` assembled by the
brain (see `brain/context.md`) — only what it needs for correlation. Two fields are
**structurally excluded**:

- **`details`** — hard rule: attacker-influenced content. Any correlation logic reading
  it makes the actor graph prompt-injectable. If a `details` field is needed for
  attribution it must first be promoted to `signals` by the bait's analyzer.
- **`sensor_time`** — the engine builds all timelines on `edge_recv_time` only. Exposing
  `sensor_time` would let an attacker fake session timing on a popped sensor.

These exclusions are structural: the framework hands the engine a typed `TypedEvent`
struct (below) that has **no `details` or `sensor_time` field** — a missing field is a
compile-time constraint, not a runtime check.

Fields the engine reads (the typed-event projection):

| Group | Fields | Why the engine needs it |
|---|---|---|
| Identity | record_id, bait_id, instance_token, campaign_id, deploy_class, assurance_tier | session keying, scope, trust weighting |
| Session | session_id, seq_no, event_type | session state machine + dispatch |
| Timestamp | edge_recv_time | trusted timeline; sole authoritative time for all session timestamps |
| Observed source | observed_source.ip, .ja3, .source_type | actor graph node extraction |
| Signals | signals.fingerprint_hash, .caution_level, .explicit_session_end | actor graph node; burn-detection input; explicit close trigger |
| Status | sig_valid, orphan, instance_status | trust gating; late-hit and revoked-source handling |

##### §6.0.1 Typed-event projection — ALREADY IMPLEMENTED

The `TypedEvent` struct itself is **already built**, not future work — it lives today at
`src/blacksea/sdk/framework/types.py`. Everything from §6.1 onward (the
session state machine, session records, actor graph, weight rules, counter-deception
enforcement, crash recovery) is the actual future build target; `TypedEvent` is the
foundation it will be built on.

```python
@dataclass(frozen=True)
class TypedEvent:
    record_id: str
    bait_id: str
    instance_token: bytes
    campaign_id: str
    deploy_class: str
    assurance_tier: int
    session_id: bytes
    seq_no: int
    event_type: str
    edge_recv_time: int
    source_ip: str
    source_ja3: str | None
    source_type: str
    fingerprint_hash: str | None
    caution_level: str | None
    explicit_session_end: bool
    sig_valid: bool
    orphan: bool
    instance_status: str
```

The framework constructs a `TypedEvent` from every `Record` before handing it to the
engine. `details` is never accessed; `sensor_time` is never copied in — these are absent
from the type, not just unused.

#### §6.1 event_type → session-role dispatch table

| event_type | Session role | Idle-gap class | Notes |
|---|---|---|---|
| tripwire_fire | single-shot | deploy_class default | seq_no=0 always; opens + schedules idle-gap close immediately; no explicit close expected |
| payload_exec_collect | single-shot | deploy_class default | may arrive as 1 event or a short DNS chunk sequence; last chunk resets the gap; closes on idle-gap |
| signal_only | single-shot | deploy_class default | standalone tier-0 hit; session of one |
| honeypot_access | session-open | interactive_service | first event of an interactive session; opens the session if not already open |
| honeypot_auth | session-middle | interactive_service | requires an open session; resets the idle-gap timer |
| honeypot_command | session-middle | interactive_service | same |
| honeypot_fileop | session-middle | interactive_service | same |
| honeypot_disconnect | session-close | n/a | triggers immediate session close; explicit_session_end should be true |
| (unknown value) | session-middle | deploy_class default | stored with {unknown_event_type:true}; does not crash the engine; extends any open session or opens a single-shot session |

Single-shot vs interactive: a single-shot event opens a session, marks
`session_type:single_shot`, arms the idle-gap timer. Further events for the same
`(instance_token, session_id)` — e.g. DNS chunks — reset the timer without changing
session type; the session closes at the gap, not on last-chunk arrival (gap absorbs
reassembly jitter). A session-open event arriving for an already-open session is treated
as session-middle (idempotent; doesn't reset `opened_at`).

#### §6.2 Session state machine

A session is an entry in the engine's stateful session table keyed by
`(instance_token, session_id)` — globally unique (`instance_token` scopes to one
deployment; `session_id` is sensor-minted per interaction; the dedup tuple ensures no
cross-sensor collision).

```
first TypedEvent
for (itoken, sid) ──▶  OPEN ──── idle-gap expires ──────────────────────▶ CLOSED
                          │  ▲                                                  ▲
                          │  │ any non-close event resets the timer             │
                          │  └──────────────────────────────────────────────────┤
                          │                                                     │
                          └── honeypot_disconnect + explicit_session_end=true ──┘
```

##### §6.2.1 Session open

Triggered by the FIRST `TypedEvent` for a given `(instance_token, session_id)`. The
engine initializes:

```
session_key       = (instance_token, session_id)
session_type      = single_shot | interactive     ← from first event's session role
opened_at         = edge_recv_time                 ← trusted clock, observed-tier
idle_gap_ms       = idle_gap_for(deploy_class)      ← §6.2.3
idle_gap_deadline = opened_at + idle_gap_ms
events            = [first_event]
identifiers       = extract_identifiers(first_event) ← §6.4
```

- **Late-arriving first event** (`orphan=true`): opens a late session tagged
  `{late_session:true}`; never dropped.
- **Revoked-source first event** (`instance_status=revoked`): opens a session tagged
  `{revoked_source:true}`; processed for attribution (we want to know who is wielding the
  weaponized sensor) but **excluded** from burn-detection hit-rate metrics — these are
  attacker-injected hits, not organic interactions.

##### §6.2.2 Session extend

Any non-close `TypedEvent` for an open session:
1. appends the event to the session's event list;
2. resets the idle-gap deadline = `edge_recv_time + idle_gap_ms`;
3. merges new identifiers into the session's identifier set;
4. updates signal aggregates (§6.3 rules).

##### §6.2.3 Session close + idle-gap defaults

- **Trigger A — explicit close:** a `honeypot_disconnect` event with
  `explicit_session_end=true`. Closes immediately; `close_reason="explicit"`.
- **Trigger B — idle-gap:** no new event within the idle-gap window.
  `close_reason="idle_gap"`.

Idle-gap defaults per `deploy_class`:

| deploy_class | Default idle-gap | Rationale |
|---|---|---|
| portable_artifact | 5 min | Payload fires and terminates; DNS chunk burst completes in <30s; 5 min absorbs retry/network jitter |
| host_resident | 15 min | Honeytoken may be read multiple times in a short burst before going quiet |
| interactive_service | 4 h | SSH/service sessions realistically idle for hours; closing too early splits one dwell into multiple sessions |

These are engine defaults, still open pending first campaign field data (see §6.9). A
future optional `session_idle_gap_seconds` field in `manifest.yaml` may override per bait
(additive; does not break the manifest schema).

On close, the engine emits a session record (§6.3) to storage and triggers an actor graph
update (§6.4).

##### §6.2.4 Edge cases

| Situation | Handling |
|---|---|
| Event arrives for a closed session (late hit) | Append to closed session's event list; tag {late_event:true}; re-run actor graph update with the event's identifiers; do NOT reopen the session |
| DNS chunk sequence has gaps in seq_no | Accept and store what arrived; do not block close on missing chunks; tag {seq_gaps:[missing]} on the session record |
| Duplicate (instance_token, session_id, seq_no) | Second copy is a replay; record_id dedup drops it from the event list; the replay attempt itself is counted as a replay signal on the session record |
| honeypot_access arrives for an already-open session | Treated as session-middle; does not reset opened_at; resets idle-gap timer |
| honeypot_disconnect arrives for a closed session | Tagged {late_event:true}; linked to the closed session; no further state change |
| seq_no wraps past 65535 in a very long interactive session | Tag {seq_no_wrapped:true}; order events past the wrap by edge_recv_time |

#### §6.3 Session record schema

Emitted to storage when a session closes. A first-class storage entity, separate from
per-hit records — the primary unit the operator console surfaces; sessions (not
individual hits) are what an analyst attributes to an actor.

`session_record_id = <instance_token_hex(16)>-<session_id_hex(16)>` (deterministic,
unique, stable across replay).

##### §6.3.1 Core fields

| Field | Type | Source | Purpose |
|---|---|---|---|
| session_record_id | string 33 chars | engine | deterministic key; joins to per-hit records |
| bait_id | string | from events | |
| instance_token | 16-char hex | from events | |
| campaign_id | string | from events | |
| deploy_class | string | from events | |
| session_type | enum single_shot\|interactive | first event's role | |
| opened_at | uint64 ms | edge_recv_time of first event | trusted timeline |
| last_event_at | uint64 ms | edge_recv_time of last event | |
| closed_at | uint64 ms | explicit: last event's edge_recv_time; idle-gap: last_event_at+idle_gap_ms | |
| close_reason | enum explicit\|idle_gap | engine | |
| event_count | int | count of events (excl. deduped replays) | |
| event_types | list[string] | distinct types seen | |
| replay_count | int | count of replayed duplicate records | replay signal |
| late_event_count | int | events tagged late_event | |
| late_session | bool | true if first event was orphan=true | |
| revoked_source | bool | true if instance_status=revoked on any event | excludes from burn-detection |
| orphan | bool | orphan=true on any event | design or instance burned/retired |
| assurance_tier | uint8 | max across events | highest-trust evidence seen in session |

##### §6.3.2 Signal aggregates (feed burn-detection + actor graph)

| Field | Type | Aggregation rule |
|---|---|---|
| caution_level | enum | max over events (none < low < medium < high) |
| explicit_session_end | bool | OR over events |
| sig_valid_all | bool | AND over events — false if any event had an invalid signature |

##### §6.3.3 Identifier snapshot (input to actor graph §6.4)

| Field | Type | Notes |
|---|---|---|
| source_ips | list[{ip, source_type}] | distinct (ip, source_type) pairs seen |
| tls_ja3s | list[string] | distinct JA3 fingerprints seen (null entries excluded) |
| fingerprint_hashes | list[string] | distinct fingerprint_hash values from signals |

#### §6.4 Actor graph entity schema

A tier-weighted linkage graph, built incrementally as sessions close. Sessions from
different campaigns/baits/time periods all feed the SAME global graph — cross-campaign
linkage is a primary attribution signal.

##### §6.4.1 Node types

| Node type | Key | Trust tier |
|---|---|---|
| ip_address | IPv4 or IPv6 string | observed when source_type=client; observed-weak when source_type=resolver |
| tls_ja3 | JA3 hash string | observed (edge-stamped) |
| harness_fp | fingerprint hash string | claimed (analyzer-extracted from signed body; forgeable on a popped sensor) |

Node keys are **GLOBAL** (the same source IP seen in two campaigns is one node with two
session links — that cross-campaign co-occurrence IS the signal). New node types are
additive: adding a new `signals` field + a corresponding node type here is the extension
point.

##### §6.4.2 Co-occurrence edge model

An edge represents co-occurrence: two identifier nodes appeared in the same session.
Created/strengthened when a session closes, using the session's identifier snapshot
(§6.3.3). For each closed session:
1. resolve or create a node for each identifier in the snapshot;
2. for every PAIR of distinct nodes in the snapshot, create or update a `co_session` edge
   between them;
3. assign the edge a weight class (§6.5);
4. record a session→node link (provenance).

The graph is **UNDIRECTED**. Edge weight metadata is per-edge; the bridge decision in
actor resolution uses the STRONGEST weight class seen across all sessions for a given node
pair. Late events extending a closed session re-run this logic for the late event's
identifiers.

##### §6.4.3 Actor resolution

An actor is a **CONNECTED COMPONENT** of the actor graph under a weight-class threshold.
Resolution rule:
1. Edges of weight class A (strong) bridge components unconditionally.
2. Edges of weight class B (medium) bridge components but produce a **DRAFT** actor
   pending analyst confirmation (§6.4.4).
3. Edges of weight class C (weak) do NOT bridge; attached to the graph as flagged hints
   for analyst review but leave components separate.

Actor identity: each actor has a stable `actor_id` = deterministic UUID derived from
`(node_type, node_key)` of the FOUNDING node (the first-seen identifier in the component
by `edge_recv_time` of the first session containing it). On component merge (two
previously separate components joined by a new bridging edge): the actor whose founding
node was seen earlier (by `opened_at`) is canonical; the other's `actor_id` becomes an
alias. Both IDs remain in the system — queries on either return the same actor.

##### §6.4.4 Draft actor merges

A class-B bridge produces a DRAFT actor (or draft merge of two existing actors). The
system does NOT auto-confirm it. The operator console surfaces drafts as a queue for
analyst review; the analyst confirms or rejects. Confirmation is a WRITE to the actor
graph — not part of the event stream; it is not replayed on crash recovery (§6.7). On
replay, draft state is reconstructed from the bridge edges; confirmed/rejected states are
stored SEPARATELY and re-applied after replay completes. This is the human-in-the-loop
backstop against false co-occurrence attacks.

#### §6.5 Edge weight rules (confidence model)

The weight class of an edge is determined by the MINIMUM weight class of its two endpoint
nodes in the context of the session that created the edge.

Node weight by context:

| Identifier type | Context | Weight class |
|---|---|---|
| ip_address | source_type=client, sig_valid=true, assurance_tier≥1 | A — strong |
| tls_ja3 | sig_valid=true, assurance_tier≥1 | A — strong |
| ip_address | source_type=client, but sig_valid=false or assurance_tier=0 | B — medium |
| ip_address | source_type=resolver (DNS channel) | B — medium |
| harness_fp | corroborated: ≥1 class-A or class-B ip_address or tls_ja3 in the SAME session | B — medium |
| harness_fp | uncorroborated: no other identifier in the same session | C — weak |

Edge weight = `min(class of node A, class of node B)` for that session. The bridge
decision uses the STRONGEST edge (max weight class) across all sessions for a given node
pair — so if a pair appeared together in two sessions, once corroborated (B) and once not,
the pair's effective bridge class is B.

##### §6.5.1 Assurance tier interaction

`sig_valid=false` → all identifiers from that event cap at class B (no signature-based
attribution; only edge-observation). `assurance_tier=0` (signal-only, unsigned) →
`harness_fp` is always class C (fingerprint is claimed-tier; without a signature it's
doubly uncorroborated); `ip_address` and `tls_ja3` may still reach class B (observed-tier
from the edge). This directly implements: "linkage edges weighted by assurance tier —
observed-tier strong, claimed-tier weak+flagged."

##### §6.5.2 DNS resolver caveat

A DNS-sourced IP (`source_type=resolver`) reaches class B, not A. Multiple actors behind
the same corporate recursive resolver share one IP node → one potential false-merge path.
The console must flag resolver-sourced linkages explicitly. An analyst should NOT confirm
an actor merge based solely on a shared resolver IP — it requires corroboration with a JA3
or fingerprint identifier in the same session.

#### §6.6 Counter-deception constraints

The actor graph is stateful and attacker-influenced. Enforcement rules that defend it:

| Rule | Enforcement |
|---|---|
| details never reaches the engine | TypedEvent has no details field; the framework strips it before constructing the projection. Violation is a type error, not a runtime check. |
| sensor_time never anchors attribution timelines | TypedEvent has no sensor_time. All session open/close timestamps use edge_recv_time. |
| Uncorroborated harness fingerprint never sole-anchors an actor merge | §6.5 weight rule: uncorroborated harness_fp → class C → does not bridge components. Auto-bridge requires class A or B. |
| Class-B bridges require analyst confirmation before final | §6.4.4: automated class-B merges produce a draft, not a confirmed actor. |
| Honeypot-recorded content (commands, file paths) never reaches the engine | details is stripped (first rule). Honeypot-observed facts only reach the engine via explicitly promoted signals fields — written by the analyzer, GitOps-reviewed. |
| Revoked-source sessions excluded from burn-detection metrics | revoked_source=true on a session record means the engine excludes it from hit-rate decay calculations. Attacker-replayed signals cannot fake organic interaction rate. |
| Actor graph is bounded by retention | Session records and actor graph entities expire per the per-bait retention_days. No indefinite accumulation. |
| Graph is fully rebuildable by replay | Actor state is a materialization (§6.7). Confirmed/rejected actor merge decisions are stored separately and re-applied after replay. |

#### §6.7 Crash recovery

Engine state is a **MATERIALIZATION** — entirely derivable from the record stream in
storage.

Recovery procedure:
1. replay all `TypedEvent` records from storage within the retention window, in
   `edge_recv_time` order;
2. re-run the session state machine (§6.2) for each event — sessions open at crash time
   are re-opened; if their idle-gap has elapsed by "now" they close normally during
   replay;
3. re-run the actor graph update (§6.4) for each session close encountered during replay
   — node keys, edge weights, and `session_record_id` are deterministic, so replay
   produces the same topology;
4. after replay completes, re-apply stored confirmed/rejected actor merge decisions from
   the separate confirmation log.

Key properties:
- `record_id` is the dedup key — replaying a record that already contributed to a closed
  session just increments `late_event_count` and is a no-op for actor resolution;
- `session_record_id` is deterministic — re-emitting a session record on replay is an
  idempotent upsert;
- `actor_id` is deterministic (derived from the founding node's `(type, key)`) — graph
  topology is stable across replays;
- human confirmation decisions are NOT part of the event stream — stored separately and
  re-applied after the replay pass; draft state re-emerges automatically, confirmations
  must be re-applied explicitly.

Substrate-agnostic: this recovery model works identically for a bespoke stateful service
or a stream processor (Flink/Kafka-Streams/Materialize) — substrate choice is still open
(§6.9).

#### §6.8 Refutations (load-bearing design rationale, not filler — keep these)

- **(a) Attacker forges harness fingerprint to frame another actor** (sets
  `signals.fingerprint_hash` to match a known previous actor's hash) → an uncorroborated
  `harness_fp` is class C, doesn't auto-bridge; a corroborated forge would require ALSO
  spoofing the edge-observed client IP or JA3 in the same session, not possible if the
  attacker is on a different network; even a successful class-B forge only produces a
  draft merge requiring analyst confirmation.
- **(b) Attacker suppresses caution signals to evade burn-detection** (always acts
  "naturally" so `caution_level` stays `none`) → burn-detection also uses hit-rate decay
  per design, a time-series signal the attacker can't suppress without actually reducing
  interaction rate; `caution_level` is a corroborating signal, never the sole input.
- **(c) Shared corporate DNS resolver collapses many actors into one IP node** → resolver
  IPs are class B; auto-bridging class-B edges produces only a draft merge requiring
  analyst confirmation; the console explicitly flags resolver-sourced linkages; an analyst
  can confirm or reject based on corroborating evidence.
- **(d) Compromised honeypot injects fabricated commands into event bodies** → `details`
  never reaches the engine (hard rule); even on a fully compromised honeypot, the only
  engine inputs are `signals` fields explicitly promoted by the bait's analyzer (reviewed
  code, not raw body content); fabricated body content that is not promoted has zero
  impact on the engine.
- **(e) Mass triggering creates an unbounded open-session table** → sessions are keyed by
  `(instance_token, session_id)`, `session_id` is sensor-minted per interaction; a single
  payload firing creates one session; concurrent open-session count is bounded by
  concurrent attacker interactions, modest for a honeypot fleet; edge-level rate limiting
  additionally bounds hit volume per instance.
- **(f) Replay of the event stream reconfirms a stale actor merge the analyst already
  rejected** → replay re-derives draft state from the bridge edges; confirmed/rejected
  decisions are in the separate confirmation log; after replay, the re-application step
  re-applies the rejection — it just surfaces as a pending draft again until re-applied;
  the confirmation log is the authoritative override.

#### §6.9 Frozen vs still-open

**FROZEN** (this is the locked design; build to this): the `TypedEvent` struct and the
structural exclusion of `details`/`sensor_time`/raw wire fields; the `event_type`→
session-role dispatch table including unknown-type handling; the session state machine
(keying, open/extend/close triggers, idle-gap mechanism, explicit-close semantics, all
edge-case rules); the session record schema, all field definitions, signal aggregation
rules; the three actor graph node types and their key fields; the co-occurrence edge model
and the actor resolution rule (connected components, class-A bridge, class-B draft,
class-C no-bridge); draft actor merge semantics and the confirmation log as a separate
store; the three weight classes and all rules assigning a class by identifier
type/source_type/sig_valid/assurance_tier/corroboration; the assurance-tier interaction
rules; the DNS resolver caveat; all counter-deception rules and `TypedEvent` as their
structural enforcement; crash-recovery as deterministic materialization-by-replay
including the confirmation-log re-apply step.

**STILL OPEN** (implementor must decide, confirm, or design before/while building):
- Exact idle-gap values per deploy_class (proposed: 5 min / 15 min / 4h; confirm against
  first campaign run).
- Optional `session_idle_gap_seconds` in `manifest.yaml` — per-bait override; additive
  optional field.
- Actor confirmation UX — what the console shows for draft vs confirmed merges; how
  multi-level evidence is presented; escalation path for uncertain merges.
- Engine substrate — bespoke stateful service vs stream processor
  (Flink/Kafka-Streams/Materialize). The §6.0–6.7 contract is substrate-agnostic.
- Online vs batch split — which computations are per-session-close (online) vs nightly
  batch (bulk actor re-resolution, confidence score refreshes).
- Numeric confidence scores — this spec defines weight CLASSES; a 0-1 confidence score on
  actor records/edges is a later UX refinement.
- Actor merge conflict resolution policy — what the operator does when a new bridge merges
  two actors previously attributed to different humans (shared VPN exit, CDN egress) —
  system surfaces the draft, policy is a human judgment call.
- Confirmation log storage — format and location of the separate store for
  confirmed/rejected decisions; must survive restarts independently of the event store.

When built, this engine will *write* its own tables (`session_records`, `actor_*`,
`confirmation_log`) — a separate namespace from the `records` input; it never mutates
`records`. The MVP read views above are shaped toward it so consumers migrate with minimal
churn.

## Scope boundary (what this module is NOT)

- **Not a writer.** The MVP performs zero DB writes. (The future engine will write its
  *own* attribution tables, never the `records` log.)
- **Not the brain.** It reads the brain-written `records` table; it does not consume from
  NATS or assemble records.
- **Not a UI.** It returns value objects; the observer/console render them.
- **Not the control plane.** No registry access, no bait lifecycle.

### inv 12 / inv 17 note

The MVP read layer is a **UI read surface**, distinct from the future attribution
engine's input (see "Future" above). `RecordDetail` deliberately surfaces `details` and
`sensor_time` for human display (exactly as the observer showed them before this module
existed). Those two fields must never feed *attribution logic* — the future engine
consumes the narrowed `TypedEvent` projection (`sdk/framework/types.py`), which
structurally excludes them (inv 12/17). Do not route `RecordDetail` into anything that
makes linkage decisions.

## Plan / build order

- **MVP (done):** `models.py` → `queries.py` → `reader.py`, wired into the observer
  (`service.py` now calls `reader`; new `/api/v1/sessions` + `/api/v1/health` endpoints
  and a **Sessions** UI tab). Pure builder tests + Postgres-backed reader tests.
- **Next (future engine):** `session.py` (state machine, §6.2 above), `weight.py` (§6.5
  above), `actor_graph.py` (§6.4 above), `schema.sql` + a writer storage layer,
  `engine.py` (replay-based materialization = crash recovery, §6.7 above). These add the
  *write* side; the read views here become thin queries over the engine's own tables.

## Dependencies

- `blacksea.brain.storage` — reuses the brain's `records` `schema.sql` (via the module
  path) in tests; the MVP reader queries the same table the brain writes.
- `psycopg[binary]` — Postgres client (async for the observer, sync for the console).
- `blacksea.config` (settings) — `queries.py`/`reader.py` source the `records` table name +
  default limit/offset/order + hit-rate bucket width from `settings` (previously duplicated
  literals).
- Consumed by: `blacksea/observer/` (now), `blacksea/otel_export/` (the
  keyset tail reader `records_after` + `RecordDetail`), and `blacksea/console/`.
- No dependency on `control_plane/`.

## File list

| File | Description |
|---|---|
| `src/blacksea/correlation/__init__.py` | Public surface: value types + `reader` functions (sync `foo` / async `afoo` pairs). Documents MVP-vs-future. |
| `src/blacksea/correlation/models.py` | `RecordFilter` + `RecordCursor` (keyset position) + frozen view value types (`RecordSummary`, `RecordDetail`, `SessionView`, `TimeBucket`, `CautionCount`) with `from_row` mappers. Caution-level ordering constants. |
| `src/blacksea/correlation/queries.py` | Pure `(sql, params)` builders over `records` (table name + paging/order defaults from `blacksea.config`); the shared `where_clause` primitive + the `records_after_sql` keyset predicate. I/O-free. |
| `src/blacksea/correlation/reader.py` | Public read API: `list_records`/`get_record`/`count_records`/`records_after`/`hit_rate`/`caution_distribution`/`session_views`, each with a sync + async variant sharing one builder + mapper. Read-only; caller owns the connection. |
| `tests/correlation/conftest.py` | `pg_dsn` skip-fixture + a namespaced `records` seed fixture (creates the table from the brain's DDL; deletes rows on teardown). |
| `tests/correlation/test_queries.py` | Pure builder tests (no DB): filter composition, order-injection guard, aggregate SQL shape. |
| `tests/correlation/test_reader.py` | Postgres-backed reader tests: list/count/get, session grouping aggregates, hit-rate buckets, caution distribution, async-parity. |

## Invariants enforced here

- **Read-only (MVP):** no function writes to the database; the `records` log is never
  mutated. Locked structurally (the reader only ever issues `SELECT`).
- **Single query source:** every view derives its `WHERE` from `queries.where_clause`;
  filter values are always bound as parameters (order direction is the only literal, and
  it is validated to `ASC`/`DESC`). Locked by `test_queries.py`.
- **inv 12 / inv 17 (future engine):** attribution logic consumes `TypedEvent` (no
  `details`, no `sensor_time`); the read layer's `RecordDetail` is display-only, per the
  note above.
