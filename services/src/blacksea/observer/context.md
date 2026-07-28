# observer/ — Read-only web observer (testing UI + API)

**Status:** implemented — a manual-testing UI, separate from the `blacksea` operator console.  
**Language:** Python 3.11+  
**Contracts:** None locked — this module consumes the registry (`src/blacksea/control_plane/context.md`,
design/instance records) and the event store (`src/blacksea/brain/context.md`, the `records` table)
read-only, via the shared `blacksea.correlation` read layer. It exposes no new contracts of its own.

## Scope

A lightweight web server that provides:

1. A **REST API** (`/api/v1/…`) over the registry (baits + instances) and the
   Postgres event store (records, sessions, health). This is the stable, typed
   interface for any observer consumer — web UI, CLI script, notebook, or future
   console frontend.
2. A **single-page testing UI** (`/`) for manual testing: four tabs (Baits,
   Instances, Events, Sessions) with live polling on the Events tab. Rows for a
   test/example/reference bait (`manifest.yaml`'s `test` flag, see
   `src/blacksea/control_plane/context.md`) carry a purple `TEST` badge next to the
   `bait_id` on the Baits, Events, and Sessions tabs, and in the Events detail panel —
   so a test hit is never mistaken for real attacker telemetry.

Record/session/health queries are **not** implemented in this module — they come from
the shared `blacksea.correlation` read layer (see its `context.md`), so the observer
and the future console render the same views from one set of query builders. `service.py`
only opens a connection, calls a `correlation.reader` function, and adapts the returned
view dataclass into a Pydantic response model.

This module is **read-only by design** — it never writes to the registry or the
database. It is a testing and observability aid; the production operator experience
lives in `blacksea/console/` (the terminal CLI).

## Scope boundary (what this module is NOT)

- Not the control plane: no lifecycle commands, no writes.
- Not the brain: no NATS consumer, no record assembly.
- Not the production console: that is `blacksea/console/`, a terminal CLI with session/actor views.
- Not a multi-user auth system: the observer is an internal tool (same VPN scope as
  the control plane, inv 10).

## Architecture

The key design invariant: **business logic lives in `service.py`, not in the HTTP
layer**. Any future consumer (a CLI reader, an integration test helper) should
instantiate `ObserverService` directly — not call HTTP endpoints.

```
models.py        ← Pydantic types (the stable API contract)
service.py       ← ObserverService: all data access (registry + postgres)
api.py           ← FastAPI routes: thin HTTP wrappers calling the service
__main__.py      ← Entry point: argparse + uvicorn.run
static/index.html ← Single-page testing UI (vanilla JS, no build step)
```

## API endpoints

```
GET /api/v1/stats                         SystemStats
GET /api/v1/baits                         list[BaitSummary]
GET /api/v1/baits/{bait_id}              BaitDetail
GET /api/v1/instances                     list[InstanceSummary]  (?bait_id&campaign_id&status)
GET /api/v1/instances/{instance_token}   InstanceDetail
GET /api/v1/events                        list[EventSummary]     (?bait_id&instance_token&campaign_id&sig_valid&limit&offset)
GET /api/v1/events/{record_id}           EventDetail
GET /api/v1/sessions                      list[SessionSummary]   (?bait_id&instance_token&campaign_id&limit&offset)
GET /api/v1/health                        HealthView             (?bait_id&since_ms&bucket_seconds)
GET /docs                                 OpenAPI / Swagger UI (FastAPI built-in)
GET /                                     Testing UI (index.html)
```

`InstanceSummary` carries the free-text operator `comment` (descriptive metadata captured at
forge/build time, empty → null) and `artifact_dir` (the vessel's whole `to_stage/` deployable
directory, `InstanceRecord.artifact_dir` — not a single file, since a build may stage several) —
both are shown as columns in the testing UI's instances table and returned on the list + detail
endpoints. Neither is on the ingest/routing/attribution path — see
`src/blacksea/control_plane/context.md`.

`sessions` is a read-time grouping of records by `(instance_token, session_id)` — an
approximation of the future correlation session engine (see `src/blacksea/correlation/context.md`'s
session state machine plan). `health` returns hit-rate buckets + caution-level distribution
(burn-detection inputs — see `src/blacksea/correlation/context.md`'s counter-deception notes),
read-only display.

## Running

```
blacksea up --infra-only && blacksea web-ui   # baits + instances + events (all Postgres now, D2)
```

The bait/instance catalog moved into Postgres (the `control_plane` schema, D2), so `POSTGRES_DSN`
is now required for *all* observer data — with no DSN the service returns empty lists (it no longer
reads flat registry files). Or directly:
```
BS_REGISTRY=registry POSTGRES_DSN="..." python -m blacksea.observer --port 8000
```

## Dependencies

- `fastapi` + `uvicorn[standard]` — ASGI server + framework
- `psycopg[binary]` — async Postgres connections (passed to the correlation reader)
- `blacksea.control_plane.registry` — Registry, DesignRecord, InstanceRecord
- `blacksea.correlation` — the shared read layer for record/session/health views
- `blacksea.config` (settings) — host/port, registry path, Postgres DSN, and page-size +
  health-bucket defaults, used by `__main__.py`/`api.py`/`service.py`
- No dependency on `brain/` or `sdk/`

## Invariants enforced here

- Read-only: no write path exists in this module.
- inv 10: internal-only; never exposed publicly (same VPN scope as control plane).

## File list

| File | Description |
|---|---|
| `__init__.py` | Package marker |
| `__main__.py` | Entry point: argparse + uvicorn.run |
| `models.py` | Pydantic response types (BaitSummary/Detail, InstanceSummary/Detail, EventSummary/Detail, SessionSummary, HitRateBucket, CautionCount, HealthView, SystemStats) |
| `service.py` | ObserverService: reads registry (sync) + delegates record/session/health queries to `blacksea.correlation.reader` (async), adapting view dataclasses → Pydantic |
| `api.py` | FastAPI app factory (make_app); routes (incl. `/sessions`, `/health`); static file serving |
| `static/index.html` | Single-page testing UI: Baits/Instances/Events/Sessions tabs, live event polling |
