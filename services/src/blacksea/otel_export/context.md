# context.md — blacksea/otel_export/

**Status:** implemented. **Language:** Python 3.11+.

The living spec for the OTLP telemetry emitter, and the sole source of truth for this module.
When a contract here and the code disagree, that is a bug — fix both in one change.

> **On the `§N` citations** in this module's code and `ops/` samples: they are stable internal
> cross-reference labels inherited from the module's pre-build design doc, which was retired
> once its content had been folded in here. `§3` is "Plan / architecture", `§5` the
> field mapping, `§6` the `details` gate, `§8` delivery & failure semantics, `§9` the config
> surface — each carries its number in the heading below. Two have no section of their own:
> `§4` was read-sharing (one `correlation` read layer, thin per-consumer renderers — see
> "Dependencies" and D8), and `§7` was topology (emit to a URL, filtering/fan-out is the
> Collector's job, not a knob here — see D5). There is no external document to look them up in.

**End-user / operator guide:** [`docs/otel-export.md`](../../../../docs/otel-export.md) — setup, the
config surface, and a complete working Grafana Loki integration. This `context.md` is the
implementer-facing spec; that guide is the operator-facing one.

## Scope

`otel_export` pushes every assembled `Record` out as an OpenTelemetry (OTLP) **log**
stream so an operator can feed Blacksea into their existing SOC/SIEM or observability
stack (Splunk, Elastic, Sentinel, Chronicle, Grafana, Datadog, …) instead of scraping the
observer REST API or reading Postgres. A honeypot hit is essentially false-positive-free
alert material; this is the standard, push-based feed for it.

**In scope:** a read-only consumer that maps each assembled `Record` (as the display
`RecordDetail`) to one OTLP LogRecord and pushes it to an endpoint the operator controls,
off the ingest hot path.

**Scope boundary — what this module is NOT:**
- **Not a Collector.** We *emit* OTLP to one endpoint; the operator runs a Collector (or a
  SIEM's OTLP receiver) and owns routing/fan-out/filtering/redaction (§7). We ship a sample
  Collector config as ops material (`ops/collector-config.example.yaml`), not a Collector.
- **Not attribution.** It emits for human/SOC display. It reads the display `RecordDetail`,
  never the `TypedEvent` projection, and never feeds `correlation` (inv 12/17).
- **Not a query API.** The observer/console stay as-is; this is a third peer consumer.
- **Not inline on ingest, and holds no state.** It reads the durable `records` table, not
  the NATS stream, and persists nothing (no checkpoint table).
- **Not a key-holder.** It is a separate process precisely so a compromise yields
  Postgres-read + SIEM creds but never the brain's decryption keys.

## Contracts

### Field mapping — Record → OTLP LogRecord (`mapping.py`, §5)

OTLP separates **Resource** (emitter identity, set once) from the per-event **LogRecord**.
Attribute names use an OTel standard convention where one exists (`client.address`) and the
`blacksea.*` namespace otherwise (there is no OTel honeypot convention).

**Resource (once per deployment):**

| OTLP field | Value |
|---|---|
| `service.name` | `blacksea-brain` |
| `service.namespace` | `blacksea` |
| `blacksea.deployment_id` | `BS_OTEL_DEPLOYMENT_ID` (distinguishes deployments in one SIEM) |

**LogRecord (per hit):**

| OTLP field | `RecordDetail` source | Notes |
|---|---|---|
| `timeUnixNano` | `edge_recv_time` (ms→ns) | **trusted** clock — never `sensor_time` |
| `observedTimeUnixNano` | emitter wall-clock | stamped by `emitter.py` at emit time |
| `severityNumber`/`severityText` | from `signals.caution_level` | map below |
| `body` | `"<event_type> on <bait_id> from <ip>"` | human one-liner |
| `traceId`/`spanId` | empty (0) | reserved for the future session→trace layer |
| attr `blacksea.record_id` | `record_id` | **dedup key** (deterministic, replay-stable) |
| attr `blacksea.bait_id`/`.bait_version` | `bait_id`/`bait_version` | |
| attr `blacksea.instance_token` | `instance_token` | |
| attr `blacksea.campaign_id` | `campaign_id` | |
| attr `blacksea.assurance_tier` | `assurance_tier` | int |
| attr `blacksea.deploy_class` | `deploy_class` | |
| attr `blacksea.session_id`/`.seq_no` | `session_id`/`seq_no` | |
| attr `blacksea.event_type` | `event_type` | |
| attr `client.address` | `source_ip` | OTel standard attr name |
| attr `blacksea.source.ja3` | `source_ja3` | omitted when null |
| attr `blacksea.source.type` | `source_type` | client\|resolver |
| attr `blacksea.channel` | `channel` | |
| attr `blacksea.edge_id` | `edge_id` | |
| attr `blacksea.sig_valid` | `sig_valid` | **prominent** — trustworthy vs forgeable |
| attr `blacksea.orphan` | `orphan` | late hit from a burned/retired instance |
| attr `blacksea.instance_status` | `instance_status` | `revoked` = someone wielding a burned sensor |
| attr `blacksea.design_status` | `design_status` | |
| attr `blacksea.test` | `test` | flags hits from test/example baits |
| attr `blacksea.sensor_time` | `sensor_time` | sensor-claimed clock — **secondary only** (never the primary timestamp) |
| attr `blacksea.caution_level` | `signals.caution_level` | promoted top-level |
| attr `blacksea.signals.<k>` | other `signals.*` | the rest of `signals`, namespaced |
| attr `blacksea.details.<k>` | `details.<k>` | **gated — §6** (also `blacksea.details.truncated` when the record was capped) |

**Severity map** (`caution_level` → `SeverityNumber`): none/∅ → INFO(9), low → WARN(13),
medium → ERROR(17), high → FATAL(21); **floored at WARN when `sig_valid=false`**.

**Attribute value coercion:** a value is a primitive (str/bool/int/float) or a *homogeneous*
array of primitives; a dict / nested / heterogeneous value is serialised to one compact JSON
string so attacker-influenced content stays inside a single typed field (§6 safety argument) —
it can never be dropped or split into a forged field. `None` → attribute omitted.

### `details` on the wire — emit, default on, gated (§6)

`details` is attacker-influenced, but this is *export for human/SOC display* (same category
as the observer's `RecordDetail`), not attribution. Emitted as structured OTLP attributes
behind `BS_OTEL_EMIT_DETAILS` (default **on**), always paired with `blacksea.sig_valid`.
Rails: primary timestamp is always `edge_recv_time`; any sensor-claimed time rides only as
the labelled secondary `blacksea.sensor_time`; `BS_OTEL_EMIT_DETAILS=false` → metadata-only
feed.

### Config surface (the operator's entire "subscription", §9)

Owned by `blacksea.config.settings` (the `BS_OTEL_*` block, env-overridable):

| Setting | Meaning |
|---|---|
| `BS_OTEL_ENABLED` | master on/off (default off) |
| `BS_OTEL_ENDPOINT` | OTLP endpoint URL (their Collector, or a SIEM's OTLP receiver) |
| `BS_OTEL_PROTOCOL` | `http/protobuf` (default) \| `grpc` |
| `BS_OTEL_HEADERS` | auth headers, comma-sep `k=v` (e.g. `Authorization=Bearer …`) |
| `BS_OTEL_TLS_CA`/`_TLS_CERT`/`_TLS_KEY` | CA / client cert for mTLS across an untrusted hop |
| `BS_OTEL_DEPLOYMENT_ID` | Resource `blacksea.deployment_id` |
| `BS_OTEL_EMIT_DETAILS` | include `details` attributes (default on) |
| `BS_OTEL_POLL_INTERVAL` | poll cadence (default ~2s) |
| `BS_OTEL_START_TIME` | optional ms-epoch cursor seed (default: now — a past value backfills) |
| `BS_OTEL_BATCH_LIMIT` | max records fetched per keyset page (default 500) |

For HTTP, `BS_OTEL_ENDPOINT` may be the base Collector URL (`http://host:4318`) — the emitter
appends the `/v1/logs` signal path — or a full logs URL.

**Console-managed config.** The `blacksea` operator console persists these
`BS_OTEL_*` keys in a dedicated env file `secrets/otel.env` (`blacksea otel config set K=V`) and
launches the emitter from it — `blacksea otel run` loads the file into a *fresh subprocess* (whose
`settings.py` then resolves from the injected env) and streams logs; `blacksea otel install-unit`
emits an OS unit with `EnvironmentFile=secrets/otel.env`. This is the **same** env-var contract —
`settings.py` still resolves `BS_OTEL_*` at import and the emitter still reads them once at startup —
so `otel config set` affects only the **next** run/unit start, never a running emitter (the console
prints "restart to apply"). `blacksea otel run` and a hand-exported environment keep working unchanged.
See `docs/console.md` + the `BS_OTEL_*` block note in `src/blacksea/config/settings.py`.

### Delivery & failure semantics (§8)

- **Transport:** OTLP over HTTP/protobuf (default); gRPC selectable via `BS_OTEL_PROTOCOL`.
- **Batching/retry:** the OTel SDK `BatchLogRecordProcessor` (bounded queue + background
  export + retry) absorbs transient SIEM blips.
- **Delivery:** at-least-once under normal operation → **dedup downstream on the
  deterministic `blacksea.record_id`**; best-effort under a long outage (queue overflow
  drops from the push; events remain in Postgres).
- **Isolation:** a separate process reading the durable `records` table — ingest is never
  blocked; on any downtime it resumes from "now" (no persisted cursor) and new events flow.
- **Ordering:** best-effort by `edge_recv_time`; SIEMs sort by timestamp anyway.

## Plan / architecture (§3)

A standalone `python -m blacksea.otel_export` process:

1. polls the `records` table through the `correlation` keyset reader for records after an
   **in-memory** `RecordCursor(edge_recv_time, record_id)` (seeded from "now", or
   `BS_OTEL_START_TIME`);
2. maps each `RecordDetail` → OTLP LogRecord (`mapping.py`);
3. pushes over OTLP via the SDK batch processor (`emitter.py`);
4. advances the in-memory cursor past the last row (`runner.py`).

It **persists nothing** — Postgres + the observer are the durable backstop. A persistent
checkpoint (true at-least-once with catch-up) is a purely additive upgrade, deferred.

## File list

| File | Description |
|---|---|
| `src/blacksea/otel_export/__init__.py` | Public surface. Eager pure mapper; `OtelEmitter`/`OtelRunner` imported lazily (keeps the SDK off the import path for pure-mapper consumers). |
| `src/blacksea/otel_export/mapping.py` | Pure, **SDK-free** `RecordDetail` → `MappedLog` mapper (the §5 field/severity contract; I/O-free, golden-tested). |
| `src/blacksea/otel_export/emitter.py` | The only SDK-touching file: `LoggerProvider`+`BatchLogRecordProcessor`+OTLP exporter setup, header/TLS parsing, `emit`/`force_flush`/`shutdown`. Constructor takes an injected processor/exporter (the test seam). |
| `src/blacksea/otel_export/runner.py` | The poll→map→emit→advance loop over the in-memory `RecordCursor`; drains a burst past one page; interruptible `run_forever` with SIGINT/SIGTERM flush-on-stop. Optional coarse scope `filt` (production tails everything). |
| `src/blacksea/otel_export/__main__.py` | `python -m blacksea.otel_export`: config guards (enabled / endpoint / DSN) → build emitter+runner → run. |
| `ops/collector-config.example.yaml` | Sample OTel Collector config (D5/D7 ops material) — debug exporter + commented Splunk/Elastic/Loki/OTLP sinks. |
| `ops/loki-demo/` | A self-contained, tested Grafana **Loki** integration: `docker-compose.yml` (Loki + Collector + Grafana), `otel-collector.yaml` (OTLP → `otlphttp/loki`), `grafana-datasource.yaml` (provisioned Loki datasource). Driven by `docs/otel-export.md`. |
| `tests/otel_export/conftest.py` | `make_detail` (in-memory `RecordDetail`), `emitter_and_sink` (in-memory OTLP sink), and the Postgres `records` seed fixtures (skip cleanly with no DB). |
| `tests/otel_export/test_mapping.py` | Golden mapping tests (fields → attributes; `details` gate; severity map; attacker-content-stays-in-a-field). |
| `tests/otel_export/test_runner.py` | Poll→emit loop against a Postgres `records` fixture + the in-memory sink (cursor advance, idempotent tail, same-ms hits, from-now seed, drain-past-a-page, wire shape, resource identity). |
| `context.md` | This file. |

## Dependencies

- `blacksea.correlation` — the read layer: `RecordDetail` + the keyset tail reader
  `records_after` / `RecordCursor` (added for this module; see `correlation/context.md`).
- `blacksea.config` (settings) — the `BS_OTEL_*` config surface (§9).
- `opentelemetry-sdk` + `opentelemetry-exporter-otlp-proto-http` — the OTLP wire.
- `psycopg[binary]` — the sync connection the runner tails on.
- Depends on the brain (records) + the `correlation` read layer; **independent of the console** — a peer
  consumer. Verified end-to-end by `e2e_tests/otel_export/`.

## Invariants enforced here

- **Writes nothing.** No `records` write, no state of its own (D3). Structural: the runner
  only ever calls the read-only `records_after` reader.
- **Off the hot path.** No edge/brain ingest path waits on OTLP export — it reads the
  durable `records` table, not the NATS stream; a dead SIEM only makes it fall behind.
- **`timeUnixNano` = `edge_recv_time`, never `sensor_time`.** Sensor-claimed time is only
  ever the labelled secondary `blacksea.sensor_time`. Locked by
  `test_mapping.py::test_primary_timestamp_is_edge_recv_time_never_sensor`.
- **No attribution.** Reads the display `RecordDetail`, never the `TypedEvent` projection;
  does not feed `correlation` (inv 12/17).
- **Observer parity.** Emits the *same* `RecordDetail` the observer displays (a testable
  property — one value object feeds both renderers).
- **`sig_valid` always emitted, paired with `details`.** Locked by
  `test_mapping.py::test_details_suppressed_when_gate_off`.

## Decisions (chosen, and what lost)

- **D1 — Primary use = SOC/SIEM alert stream.** Rejected: dashboards-first (a SIEM derives
  rate/trend from the log stream), investigation-first (needs the Post-MVP `correlation` engine).
  Consequence: signal = logs; durability > latency; seconds-latency fine.
- **D2 — Signal = OTel logs only.** Rejected: traces (needs the unbuilt engine), metrics (not an
  alert stream). Trace fields reserved empty for additive upgrade.
- **D3 — Standalone process, poll Postgres via `correlation`, in-memory from-now cursor, no
  writable state.** Rejected: NATS fan-out (brain change + stream for latency we don't need);
  thread-in-brain (crown-jewel egress + SIEM creds in the key-holder); fold-into-observer
  (promotes a testing UI to production-required); a persistent checkpoint (deferred — additive).
- **D4 — Emit `details`, default on, gated, `sig_valid`-paired.** Rejected: default-off (chose
  usefulness, sink is the operator's own SIEM), never-emit (loses the intel). Structured
  attributes + `edge_recv_time`-only timestamp are the safety rails.
- **D5 — Emit to a URL; recommend a Collector; ship a sample config, not a Collector.** Rejected:
  bundling a Collector (a maintained product surface), direct-to-SIEM-only (couples config to one
  backend, no buffer/fan-out/redaction layer).
- **D6 — OTLP/HTTP default.** Rejected: gRPC default (heavier native dep; efficiency irrelevant at
  honeypot volumes).
- **D7 — Cursor seeds from "now" on every start; `BS_OTEL_START_TIME` override.** Rejected: full
  retained-history backfill on first enable (risks flooding the SIEM on turn-on).
- **D8 — Extend `correlation` (read `RecordDetail` + a new keyset-cursor reader); observer
  parity.** Rejected: clienting the observer REST API (runtime coupling; promotes a testing UI to
  critical infra), a bespoke tail query in `otel_export` (duplication; drifts from
  single-query-source).

## Known limitations (all additive to close)

- **Persistent checkpoint** — a `(edge_recv_time, record_id)` checkpoint for true
  at-least-once with catch-up across restarts/outages. Add only if push-gaps prove to matter.
- **Traces** — session→trace / hit→span once `correlation`'s stateful engine exists (trace
  fields already reserved empty).
- **gRPC / mTLS specifics** — cert distribution for an untrusted edge↔SIEM hop (aligns with
  the deferred edge-separation TLS work). The knobs exist (`BS_OTEL_TLS_*`); the distribution
  story is not built.
- **Byte-exact raw body** — would need a brain-side change to persist the pre-`interpret()`
  body; a distinct security decision, not folded here.
