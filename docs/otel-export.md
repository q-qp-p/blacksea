# Streaming Blacksea events to your SIEM with OpenTelemetry (OTLP)

Blacksea can push every honeypot hit out as an **OpenTelemetry (OTLP) log stream**, so you can feed it into your existing SOC/SIEM or observability stack — Splunk, Elastic, Microsoft Sentinel, Chronicle, **Grafana Loki**, Datadog, or anything that speaks OTLP — instead of scraping the observer API or reading Postgres directly.

A honeypot hit is about the highest-fidelity security signal there is: nobody has a legitimate reason to touch a lure, so the stream is essentially false-positive-free alert material. This guide sets that stream up end to end, and walks through a **complete, working Grafana Loki integration** you can run on your laptop.

- [How it works](#how-it-works)
- [Prerequisites](#prerequisites)
- [Configuration reference](#configuration-reference)
- [Quick start — see events on a Collector's stdout](#quick-start--see-events-on-a-collectors-stdout)
- [What an event looks like on the wire](#what-an-event-looks-like-on-the-wire)
- [Integration example: Grafana Loki (end to end)](#integration-example-grafana-loki-end-to-end)
- [Routing to other backends](#routing-to-other-backends)
- [Security & what goes on the wire](#security--what-goes-on-the-wire)
- [Operating the emitter](#operating-the-emitter)
- [Troubleshooting](#troubleshooting)

---

## How it works

The emitter is a small standalone process, `python -m blacksea.otel_export`, started for you by `blacksea otel run`. It **tails the durable `records` table** (the same events the observer shows), maps each assembled Record to one OTLP **LogRecord**, and **pushes** it to an OTLP endpoint you control — normally an **OpenTelemetry Collector** that fans out to your backend(s).

```
                                    ┌─────────────── you run this ───────────────┐
bait fires ─► edge ─► NATS ─► brain ─► Postgres          OTLP Collector ─► Splunk / Elastic /
                                (records)  │                    ▲            Loki / Sentinel / …
                                           │                    │ OTLP/HTTP
                              python -m blacksea.otel_export ──┘
                              (tails records, maps → OTLP, pushes)
```

Key properties — worth knowing before you wire it into production:

- **Push, not subscribe.** There is no feed to poll. Your entire "subscription" is: stand up an OTLP endpoint and give the emitter its URL. The Collector decouples Blacksea from your backend — **Blacksea never learns which SIEM you use**, and you can change sinks without touching it.
- **Off the ingest hot path.** The emitter reads the durable `records` table, not the live NATS stream. A slow or dead SIEM can only make the emitter *fall behind* — it can never back-pressure or block edge→brain→Postgres.
- **Holds no keys, writes nothing.** It is a separate process on purpose: a compromise of the emitter yields Postgres-read access + your SIEM credentials, but never the brain's decryption keys. It never writes to any table.
- **Trusted timestamps.** The event's primary timestamp is always `edge_recv_time` (stamped by the edge, trusted), never the attacker-controllable `sensor_time` (which rides only as a clearly-labelled secondary attribute).
- **Best-effort delivery, dedup downstream.** Delivery is at-least-once under normal operation; every record carries a deterministic `blacksea.record_id` so your SIEM can dedup. On a long outage it degrades to best-effort — events stay safe in Postgres regardless.

---

## Prerequisites

- A running Blacksea stack with events in Postgres. `blacksea up` brings the whole stack up; see the main [README](../services/README.md). The emitter needs read access to the same Postgres the brain writes.
- **Docker** — for the OTLP Collector (and, in the Loki example below, Loki + Grafana).
- The Python deps are installed by `make install` (they're declared in the root `pyproject.toml`).

---

## Configuration reference

Everything is configured through environment variables. The emitter is **off by default**.

| Variable | Default | Meaning |
|---|---|---|
| `BS_OTEL_ENABLED` | `false` | Master on/off. Must be truthy (`1`/`true`/`yes`/`on`) to run. |
| `BS_OTEL_ENDPOINT` | — | OTLP endpoint URL — your Collector, or a SIEM's OTLP receiver. For HTTP you may give the base URL (`http://host:4318`); the emitter appends the `/v1/logs` path. |
| `BS_OTEL_PROTOCOL` | `http/protobuf` | `http/protobuf` (default) or `grpc` (needs the optional `otlp-grpc` extra — `pip install -e ".[otlp-grpc]"` from `services/`; a plain `make install` does not pull it in). |
| `BS_OTEL_HEADERS` | — | Auth headers, comma-separated `key=value` (e.g. `Authorization=Bearer abc,X-Scope-OrgID=42`). |
| `BS_OTEL_TLS_CA` / `_TLS_CERT` / `_TLS_KEY` | — | CA bundle / client cert / client key for TLS or mTLS across an untrusted hop. |
| `BS_OTEL_DEPLOYMENT_ID` | `blacksea` | Sets the Resource attribute `blacksea.deployment_id` — use it to tell two Blacksea deployments apart in one SIEM. |
| `BS_OTEL_EMIT_DETAILS` | `true` | Include the per-bait `details` intel as attributes. Set `false` for a metadata-only feed (see [Security](#security--what-goes-on-the-wire)). |
| `BS_OTEL_POLL_INTERVAL` | `2.0` | How often (seconds) the emitter polls Postgres for new records. |
| `BS_OTEL_START_TIME` | *now* | Optional ms-epoch cursor seed. Default is "now" — only hits that arrive **after** the emitter starts are pushed. A value in the past **backfills** from that point. |
| `BS_OTEL_BATCH_LIMIT` | `500` | Max records fetched per poll (keyset page size). |

`POSTGRES_DSN` (the durable event store the emitter tails) is also required. `blacksea otel run` supplies it from `config/blacksea.env` for you; a standalone deployment sets it directly.

### Managing config with the `blacksea` console

The `blacksea` operator console can manage these `BS_OTEL_*` keys for you in a dedicated env file, `secrets/otel.env` (separate from `secrets/env`), and run the emitter — see [`docs/console.md`](./console.md#otel-telemetry-control):

```bash
blacksea otel config set BS_OTEL_ENDPOINT=http://localhost:4318 BS_OTEL_PROTOCOL=http/protobuf
blacksea otel config show
blacksea otel run                          # foreground: loads secrets/otel.env, streams logs, Ctrl-C stops
blacksea otel install-unit                 # emit a systemd unit (EnvironmentFile=secrets/otel.env) for always-on
```

Because the emitter reads `BS_OTEL_*` once at startup, **`blacksea otel config set` affects only the next `otel run` / unit start, never a running emitter** — restart it to apply. This is the same env-var contract as above; the console just persists the values in a file a subprocess (or a systemd unit) loads. `blacksea otel run` and a hand-exported environment continue to work unchanged.

> **Note on the cursor.** The emitter keeps its position in memory and, by default, starts from
> "now". So the usual order is: **start the emitter first, then fire hits.** To replay events that
> are already in Postgres, set `BS_OTEL_START_TIME` to a past millisecond epoch. There is no
> persistent checkpoint — on restart it reseeds from "now" (or `BS_OTEL_START_TIME`); Postgres and
> the observer remain the durable backstop.

---

## Quick start — see events on a Collector's stdout

The fastest way to confirm the pipe works: run a Collector that just prints what it receives. Blacksea ships a ready-made sample config ([`src/blacksea/otel_export/ops/collector-config.example.yaml`](../services/src/blacksea/otel_export/ops/collector-config.example.yaml)) whose `debug` exporter echoes each record to stdout.

```bash
# 1. Start a Collector (from the services/ directory):
docker run --rm -p 4318:4318 \
  -v "$PWD/src/blacksea/otel_export/ops/collector-config.example.yaml:/etc/otelcol-contrib/config.yaml" \
  otel/opentelemetry-collector-contrib:latest

# 2. In another terminal, start the emitter pointed at it:
blacksea otel config set BS_OTEL_ENABLED=1 BS_OTEL_ENDPOINT=http://localhost:4318
blacksea otel run

# 3. Fire a hit. Any bait works; the fastest is the OTLP e2e bait:
blacksea forge e2e_tests/otel_export/manifest.yaml   # register → build → approve; prints the artifact path
# ...then run the artifact it printed. A hit appears in the Collector's terminal within seconds:
#   Body: Str(payload_exec_collect on otel-export-probe from 127.0.0.1)
#    -> blacksea.bait_id: Str(otel-export-probe)
#    -> blacksea.instance_token: Str(…)
```

Once you can see events on the Collector's stdout, point the Collector at a real backend — the Loki example below is a complete, working one.

---

## What an event looks like on the wire

Each hit becomes one OTLP LogRecord. A **Resource** identifies the emitter (attached to every record); the **LogRecord** carries the event.

**Resource attributes:**

| Attribute | Value |
|---|---|
| `service.name` | `blacksea-brain` |
| `service.namespace` | `blacksea` |
| `blacksea.deployment_id` | your `BS_OTEL_DEPLOYMENT_ID` |

**LogRecord** — the human one-liner in the body, everything else as typed attributes:

- `timeUnixNano` = `edge_recv_time` (trusted). `observedTimeUnixNano` = when the emitter processed it.
- `severityNumber`/`severityText` from the hit's caution level: none → INFO, low → WARN, medium → ERROR, high → FATAL (floored at WARN when the signature is invalid).
- `body` = `"<event_type> on <bait_id> from <ip>"`.
- Attributes: `blacksea.record_id` (the dedup key), `blacksea.bait_id`, `blacksea.instance_token`, `blacksea.campaign_id`, `blacksea.event_type`, `client.address` (the source IP, using the OTel standard name), `blacksea.sig_valid`, `blacksea.caution_level`, `blacksea.instance_status`, `blacksea.test`, and — unless you turn them off — the per-bait intel under `blacksea.details.*`.

---

## Integration example: Grafana Loki (end to end)

This is a complete, self-contained example: an OpenTelemetry Collector forwarding to **Grafana Loki**, with **Grafana** pre-wired to query it. Everything is shipped under [`src/blacksea/otel_export/ops/loki-demo/`](../services/src/blacksea/otel_export/ops/loki-demo/) — a `docker-compose.yml`, the Collector config, and a Grafana datasource. *(This is a laptop demo — a single-binary Loki with filesystem storage and anonymous Grafana. Do not run it as-is in production.)*

### 1. Bring up Loki + Collector + Grafana

```bash
cd src/blacksea/otel_export/ops/loki-demo
docker compose up -d
```

This starts three containers:

| Service | Address | Role |
|---|---|---|
| `loki` | http://localhost:3100 | Log store (native OTLP ingest at `/otlp/v1/logs`) |
| `otel-collector` | OTLP/HTTP on **:4418** | Receives from the emitter, forwards to Loki |
| `grafana` | http://localhost:3000 | UI, with the Loki datasource pre-provisioned |

Wait until Loki reports ready:

```bash
curl -s http://localhost:3100/ready      # prints "ready"
```

The Collector forwards to Loki's native OTLP endpoint (`http://loki:3100/otlp`) — see [`loki-demo/otel-collector.yaml`](../services/src/blacksea/otel_export/ops/loki-demo/otel-collector.yaml).

### 2. Start the emitter, pointed at the demo Collector

From the `services/` directory (note the port is **4418**, the demo Collector's host port):

```bash
blacksea otel config set BS_OTEL_ENABLED=1 BS_OTEL_ENDPOINT=http://localhost:4418
blacksea otel run
```

Leave it running. It logs a line like:

```
otel_export → http://localhost:4418 (protocol=http/protobuf, emit_details=True); tailing records from cursor (…, '')
```

### 3. Fire a hit

In another terminal, trigger a bait (the emitter tails from "now", so fire *after* it starts). Any real hit works; the quickest is the OTLP e2e bait:

```bash
blacksea forge e2e_tests/otel_export/manifest.yaml   # register → build → approve; prints the artifact path
# run the printed artifact, e.g.:
#   .venv/bin/python <artifact_path>
```

Within a few seconds the emitter logs `emitted 1 record(s); cursor now (…)`.

### 4. See it in Loki

Query the Loki API directly:

```bash
START_NS=$(python3 -c "import time;print(int((time.time()-3600)*1e9))")
curl -s -G http://localhost:3100/loki/api/v1/query_range \
  --data-urlencode 'query={service_name="blacksea-brain"}' \
  --data-urlencode "start=$START_NS" --data-urlencode 'limit=5'
```

You'll get back the log line and its metadata. From a real run:

```
line   : payload_exec_collect on otel-export-probe from 127.0.0.1
labels : service_name="blacksea-brain", service_namespace="blacksea", …
metadata: blacksea_bait_id="otel-export-probe", blacksea_instance_token="01a769ef050a0ab7",
          blacksea_details_hostname="MacBook-Pro-3.local", blacksea_sig_valid="true",
          blacksea_caution_level=…, blacksea_test="true", severity_text="INFO", …
```

How the fields map into Loki:

- **`service.*` → Loki stream labels** (`service_name`, `service_namespace`, `service_instance_id`). These are the low-cardinality index — that's why you select streams with `{service_name="blacksea-brain"}`.
- **Every `blacksea.*` attribute → Loki structured metadata** (dots become underscores). Filter on them with LogQL, e.g.:

  ```logql
  {service_name="blacksea-brain"} | blacksea_instance_token="01a769ef050a0ab7"
  {service_name="blacksea-brain"} | blacksea_caution_level="high"
  {service_name="blacksea-brain"} | blacksea_test="true"        # only test/example bait hits
  ```

### 5. See it in Grafana

Open **http://localhost:3000** (anonymous admin — no login). Go to **Explore**, pick the **Loki** datasource (already provisioned), and run:

```logql
{service_name="blacksea-brain"}
```

Add a structured-metadata filter (e.g. `| blacksea_caution_level="high"`) to narrow to the hits you care about, and build a dashboard/alert from there. Because a honeypot hit is essentially never a false positive, a simple "any log where `blacksea_sig_valid="true"`" alert is already a high-confidence intrusion signal.

### 6. Tear it down

```bash
cd src/blacksea/otel_export/ops/loki-demo
docker compose down -v
```

---

## Routing to other backends

The Collector — not Blacksea — owns routing, fan-out, filtering, and redaction. To send to a different (or additional) backend, edit your Collector config's `exporters` and pipeline. The shipped [`collector-config.example.yaml`](../services/src/blacksea/otel_export/ops/collector-config.example.yaml) has commented-out stanzas for **Splunk HEC**, **Elasticsearch**, **Loki**, and any generic **OTLP-native** SIEM (Datadog agent, Sentinel via AMA, Chronicle forwarder, …). For example, to add Splunk alongside the debug exporter:

```yaml
exporters:
  splunk_hec/logs:
    token: "${SPLUNK_HEC_TOKEN}"
    endpoint: "https://splunk.example.com:8088/services/collector"
    source: "blacksea"
service:
  pipelines:
    logs:
      receivers: [otlp]
      processors: [batch]
      exporters: [splunk_hec/logs]        # add/replace sinks here
```

**Event filtering is the Collector's job too** — there is no "only high-caution" knob in the emitter. Drop or route by attribute in the Collector with the `filter`/`transform` processors, e.g. forward only medium-and-up caution to a paging sink while everything goes to cold storage.

---

## Security & what goes on the wire

- **`details` is attacker-influenced, and emitted by default.** The per-bait `details` intel (an analyzer's `interpret()` output) is where the actionable content lives, so it's emitted by default — but it's the same category of data the observer already shows, going to *your own* sink. Two safety rails apply: it always rides as **typed OTLP attributes** (so a malicious newline/ANSI stays *inside* a field and can't forge a separate log line), and it's always paired with `blacksea.sig_valid` so you can tell trustworthy from forgeable. Set `BS_OTEL_EMIT_DETAILS=false` for a metadata-only feed if your policy requires it.
- **Trust the timestamp.** The primary event time is always `edge_recv_time` (edge-stamped, trusted). The sensor-claimed clock is emitted only as the clearly-labelled secondary `blacksea.sensor_time` — never use it to anchor a timeline.
- **`blacksea.sig_valid` / `blacksea.instance_status` are the trust signals.** A `sig_valid=true` hit is cryptographically verified. `instance_status="revoked"` means someone is wielding a burned sensor — directly alertable.
- **Cross an untrusted hop with TLS.** If the emitter reaches the Collector/SIEM over an untrusted network, set `BS_OTEL_HEADERS` (auth) and `BS_OTEL_TLS_CA`/`_TLS_CERT`/`_TLS_KEY` (TLS/mTLS) — never ship credentials in the clear.
- **The emitter holds no keys** and only *reads* Postgres. Give its database role `SELECT`-only access to the `records` table if you can.

---

## Operating the emitter

- **Run it as a long-lived service.** It's a normal process — supervise it with systemd, a container, or whatever you use. It responds to SIGINT/SIGTERM by flushing in-flight records and exiting cleanly.
- **Restart behavior.** On restart it reseeds its cursor from "now" (or `BS_OTEL_START_TIME`), so a gap during downtime shows up only in the *push* — the events are still in Postgres. If you need a particular window re-sent after an outage, restart with `BS_OTEL_START_TIME` set to just before it.
- **Multiple deployments into one SIEM.** Give each a distinct `BS_OTEL_DEPLOYMENT_ID`; it lands on every record as `blacksea.deployment_id`.

---

## Troubleshooting

| Symptom | Likely cause / fix |
|---|---|
| Emitter logs "BS_OTEL_ENABLED is off" and exits | Set `BS_OTEL_ENABLED=1`. |
| "BS_OTEL_ENDPOINT is not set" | Point it at your Collector/SIEM, e.g. `BS_OTEL_ENDPOINT=http://localhost:4318`. |
| "POSTGRES_DSN is not set" | `blacksea otel run` sets it from `config/blacksea.env`; a standalone run must export it. |
| Emitter runs but nothing arrives | It tails from **now** — fire the hit *after* starting it, or set `BS_OTEL_START_TIME` to backfill. Confirm the hit reached Postgres (observer, or `SELECT … FROM records`). |
| Nothing in the Collector | Wrong port/URL (the Loki demo Collector is on **:4418**, the quick-start on :4318). For HTTP the emitter posts to `<endpoint>/v1/logs`. |
| Collector receives it but Loki is empty | Check `docker compose logs otel-collector` for exporter errors, and `curl http://localhost:3100/ready`. |
| Loki `{service_name="blacksea-brain"}` returns nothing | Widen the time range (`start`), and confirm the label exists: `curl http://localhost:3100/loki/api/v1/label/service_name/values`. |

---

## See also

- [`src/blacksea/otel_export/ops/collector-config.example.yaml`](../services/src/blacksea/otel_export/ops/collector-config.example.yaml) — the sample Collector config (debug + commented real sinks).
- [`src/blacksea/otel_export/ops/loki-demo/`](../services/src/blacksea/otel_export/ops/loki-demo/) — the Loki demo stack used above.
- [`e2e_tests/otel_export/`](../services/e2e_tests/otel_export/) — the automated end-to-end test for the whole path (fire → export → assert receipt at a live Collector).
