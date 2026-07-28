"""blacksea.config.settings — the single source of truth for operational config.

Every deployment/runtime value that used to be a scattered ``os.environ.get(...)``
default — duplicated across the Makefile, inline in the Python modules, and the Go
edge — lives here once, with a one-line note on its role. Each value resolves from
its environment variable if set, otherwise the documented default, so `blacksea up`
or a real deployment can override any of them without editing code.

At import this module first loads the ONE unified config file ``config/blacksea.env``
(written by ``make init``) into ``os.environ`` via
:mod:`blacksea.config.envload` — env always wins over the file — so the DSN / NATS
coordinates + ``BS_INFRA`` mode resolve from that single file for every Python entry
point without a wrapper exporting them.

WHAT DOES **NOT** BELONG HERE — protocol / wire constants
    The crypto domain-separation labels (``bs-env-v2-enc`` / ``…-mac``), the
    envelope version ``ev``, the nonce/tag/header byte sizes, the DNS header
    layout, the record-id format, etc. are *contracts* that must match
    byte-for-byte across the payload, the brain, and the edge. They are named
    constants next to the code that uses them and are guarded by the golden
    wire-vector tests (``tests/sdk/test_envelope.py``,
    ``tests/brain/test_verifier.py``) — never a tunable knob. Do not move them here.

TWO-LANGUAGE NOTE
    The Go edge cannot import this module, so it keeps its own mirror of the values
    shared with it (``NATS_URL``/``NATS_STREAM``/``NATS_MAX_BYTES``/``NATS_MAX_AGE_S``/subjects,
    listen ports, timeouts) in ``edge/config.go``. When you change a shared default here, change
    it there too — the ``NATS_STREAM`` default in particular MUST agree on both
    sides or the edge and brain provision two overlapping JetStream streams, and the
    ``NATS_MAX_BYTES``/``NATS_MAX_AGE_S`` caps MUST agree or whichever side provisions the stream
    last silently re-widens it back toward unbounded.
"""

from __future__ import annotations

import os
from pathlib import Path

from . import envload

# Load the ONE unified config file (``config/blacksea.env``, written by ``make init``) into
# ``os.environ`` before any setting below is resolved — env always wins, so an
# explicit ``POSTGRES_DSN=…`` / ``--postgres`` / per-process env still overrides it. A missing file
# is a no-op. This is what makes "one file every consumer reads" true for the Python side (see
# ``envload``). ``BS_CONFIG_PATH`` records what was loaded (or ``None``) — surfaced by
# ``blacksea config show`` / ``status``.
BS_CONFIG_PATH = envload.load_into_environ()


# ── env helpers ────────────────────────────────────────────────────────────────
# Every setting reads its env var through one of these so "unset" and "set but
# empty" are treated the same way everywhere.

def _str(name: str, default: str) -> str:
    v = os.environ.get(name)
    return v if v not in (None, "") else default


def _opt(name: str) -> str | None:
    """Optional string: ``None`` when unset/empty (used for secrets + paths that
    have no safe literal default)."""
    v = os.environ.get(name)
    return v or None


def _int(name: str, default: int) -> int:
    v = os.environ.get(name)
    return int(v) if v not in (None, "") else default


def _float(name: str, default: float) -> float:
    v = os.environ.get(name)
    return float(v) if v not in (None, "") else default


def _bool(name: str, default: bool) -> bool:
    """Truthy env flag: ``1/true/yes/on`` (case-insensitive) → True, anything else
    → False. Unset/empty falls back to ``default``."""
    v = os.environ.get(name)
    if v in (None, ""):
        return default
    return v.strip().lower() in ("1", "true", "yes", "on")


# ── Project root anchor ─────────────────────────────────────────────────────────
# The absolute project root (``services/``), derived from THIS installed package's location by
# :mod:`blacksea.config.envload` (see its ``PROJECT_ROOT`` — CWD-independent, because Blacksea is
# always an editable install). It is the anchor that makes ``blacksea`` work from ANY working
# directory: the config file is discovered under it (envload), and every operational path default
# below resolves under it. ``None`` for a relocated/non-editable install → the defaults fall back to
# the historical CWD-relative behavior. Override with ``$BS_PROJECT_ROOT``.
BS_PROJECT_ROOT = envload.PROJECT_ROOT


def _root_path(name: str, *relparts: str) -> str:
    """A project path default: the ``$name`` override if set, else ``<BS_PROJECT_ROOT>/relparts`` when
    the root is known (installed/anchored — CWD-independent), else the plain relative ``relparts``
    (the pre-anchor CWD-relative fallback). In-tree the two are the same physical path, so behavior is
    unchanged when run from the repo root; out-of-tree the anchored form is what makes it correct."""
    v = os.environ.get(name)
    if v not in (None, ""):
        return v
    rel = os.path.join(*relparts)
    return os.path.join(BS_PROJECT_ROOT, rel) if BS_PROJECT_ROOT else rel


# ── Infra mode ────────────────────────────────────────────────────────────────
# How Blacksea gets its Postgres + NATS, chosen once by ``make init`` and written to
# ``config/blacksea.env``: ``docker`` (Blacksea runs them in containers; coordinates default to
# localhost) or ``external`` (the operator runs their own and supplies an opaque DSN/URL/creds,
# which Blacksea never provisions or overwrites). Consumers that manage containers (the Makefile's
# ``infra-*`` targets) gate on this; the app layer is mode-agnostic — it only needs a connection.
BS_INFRA = _str("BS_INFRA", "docker")


# ── Storage: Postgres event store + control-plane catalog ───────────────────────
# In **external** mode ``config/blacksea.env`` supplies an opaque ``POSTGRES_DSN`` (used verbatim —
# no ``localhost`` is ever assumed for a remote DB). In **docker** mode it supplies the coordinates
# (``POSTGRES_HOST``/``PORT``/``DB``/``USER``/``PASSWORD``) and the DSN is assembled from them by
# ``envload.dsn_from_coords`` — the ONE place that assembly lives.
#
# Coordinate assembly fires ONLY when a config file was actually loaded (``BS_CONFIG_PATH`` set), so a
# stray ambient ``POSTGRES_PASSWORD``/``POSTGRES_HOST`` in the shell — a common var, e.g. for another
# project's compose — does NOT silently conjure a ``host=localhost`` DSN and mask the honest "no DSN"
# error. With no file, only an explicit ``POSTGRES_DSN`` produces one. ``None`` (no file + no opaque
# DSN, or a file with no password) disables record/session queries in the observer; the brain requires
# it (validated there), and as of the registry-DB migration (D2) so does the control plane — authoring
# (register/build/approve/forge) hard-depends on a running Postgres (O7).
POSTGRES_DSN = _opt("POSTGRES_DSN") or (
    envload.dsn_from_coords(os.environ) if BS_CONFIG_PATH else None)
# Postgres schema holding the control-plane catalog (design/instance, O6). Isolated
# from the brain's event tables and SELECT-only for the brain role.
BS_CP_SCHEMA = _str("BS_CP_SCHEMA", "control_plane")


# ── Queue: NATS JetStream ───────────────────────────────────────────────────────
NATS_URL = _str("NATS_URL", "nats://localhost:4222")  # broker endpoint
NATS_USER = _opt("NATS_USER")                          # queue auth (no anonymous access)
NATS_PASS = _opt("NATS_PASS")                          # kept out of NATS_URL so it never logs
# JetStream stream shared by the edge (publisher) and the brain (consumer). MUST
# equal the edge's NATS_STREAM default in config.go — a mismatch silently creates a
# second stream with overlapping subjects.
NATS_STREAM = _str("NATS_STREAM", "BAITS")
# BAITS-stream disk caps (defense-in-depth against unauthenticated disk-exhaustion).
# Under LimitsPolicy retention a consumer ack does NOT evict a message; only a size/age
# limit can, so WITHOUT these the stream is an append-only log of every hit ever published, bounded
# only by host disk. The edge (publisher) and the brain (consumer) BOTH provision this stream —
# these MUST equal the edge's NATS_MAX_BYTES / NATS_MAX_AGE_S defaults in edge/config.go, or
# whichever side runs last on a fresh deploy silently re-widens the stream. 0 = unbounded for that
# dimension (reopens the gap — not recommended). BOTH are parsed as **integers** here to match the
# Go edge's integer parse (`strconv.ParseInt`) byte-for-byte: a fractional value (e.g. `604800.0`)
# that `_float` would accept but `ParseInt` rejects would otherwise leave the edge silently on its
# default while the brain honoured the fraction — the two provisioners must accept the same formats.
NATS_MAX_BYTES = _int("NATS_MAX_BYTES", 1 << 30)       # stream disk cap (bytes, 1 GiB)
NATS_MAX_AGE_S = _int("NATS_MAX_AGE_S", 7 * 24 * 3600)  # stream age cap (integer s, 7 days)
NATS_CONSUMER = _str("NATS_CONSUMER", "brain-pool")    # brain durable-consumer name
SUBJECT_FILTER = "bait.>"         # brain subscription + stream subject filter
# The dumb dead-drop edge publishes every hit to ONE subject — `bait._ingest` — under this
# `bait.>` namespace (it holds no directory, so it cannot compute a per-bait subject); the brain
# reads `tok` off the firehose and resolves routing from its own key directory. That literal lives
# in the Go edge (`ingestSubject`); the brain only needs the `bait.>` filter above that covers it.


# ── Registry, key directory, paths ─────────────────────────────────────────────
# BS_REGISTRY is the filesystem root that parents ``artifacts/`` (the material store) — the
# design/instance catalog lives in Postgres (the ``control_plane`` schema, D2). Anchored under
# BS_PROJECT_ROOT so it resolves the same directory whether ``blacksea`` runs from the repo root or
# elsewhere (see ``_root_path``); ``BS_REGISTRY`` still overrides.
BS_REGISTRY = _root_path("BS_REGISTRY", "registry")
# The **material** store (D7/O9): per-instance build outputs plus the frozen per-(bait_id,
# version) listener the brain imports (<artifacts-root>/<bait_id>/<version>/listener/).
# Both the control-plane factory (writer) and the brain (reader) resolve it — same relative
# structure per host. Defaults to <registry>/artifacts.
BS_ARTIFACTS_ROOT = _opt("BS_ARTIFACTS_ROOT") or os.path.join(BS_REGISTRY, "artifacts")
# (BS_BAITS_DIR removed — the brain no longer scans a git baits dir; it reads designs from
# the catalog and frozen listeners from BS_ARTIFACTS_ROOT, O9. Its only consumer was the scan.)
# Brain key directory (§5.11): the SOLE key directory now that the edge is a dumb dead-drop.
# Carries per-instance `_KEY`; lives under the 0700 `secrets/` tree in its own `keys/` subdir, so
# `blacksea reset` can wipe it (per-instance test state) without touching the write-once
# `secrets/env` infra creds. Stays on brain-controlled infra, never crossing the edge diode.
# Anchored under BS_PROJECT_ROOT (CWD-independent); ``BS_BRAIN_KEYDIR`` still overrides.
BRAIN_KEYDIR = _root_path("BS_BRAIN_KEYDIR", "secrets", "keys", "brain_keydir.json")
# Bundler vendor root — the src/ tree that holds the `blacksea/` namespace, so the bundler can
# inline `blacksea.sdk.payload.*` source. This file is src/blacksea/config/settings.py → parents[2]
# is that src/ root. (Override with BS_SDK_ROOT for a relocated/vendored SDK source.)
BS_SDK_ROOT = _str("BS_SDK_ROOT", str(Path(__file__).resolve().parents[2]))


# ── Brain runtime ───────────────────────────────────────────────────────────────
INTERPRET_TIMEOUT = _float("BS_INTERPRET_TIMEOUT", 10.0)      # per-hit analyzer interpret() timeout (s)
KEYDIR_POLL_S = _float("BS_BRAIN_KEYDIR_POLL_S", 10.0)        # brain key-directory hot-reload poll interval (s)
POOL_MAX_WORKERS = _int("BS_POOL_MAX_WORKERS", 1)             # analyzer ThreadPoolExecutor size
DETAILS_CAP = _int("BS_DETAILS_CAP", 256 * 1024)             # §3.5 record `details` size cap (bytes, 256 KiB)
# Brain liveness heartbeat: the pool upserts brain_health.last_poll_at on
# this cadence; `blacksea status` reads it against BRAIN_HEARTBEAT_STALE_S — a last_poll_at older
# than the staleness window reads as "brain stale/stopped" instead of a false green.
BRAIN_HEARTBEAT_S = _float("BS_BRAIN_HEARTBEAT_S", 10.0)      # brain heartbeat upsert cadence (s)
BRAIN_HEARTBEAT_STALE_S = _float("BS_BRAIN_HEARTBEAT_STALE_S", 30.0)  # console: max heartbeat age before "stale" (s)


# ── Observer: read-only web UI ──────────────────────────────────────────────────
OBSERVER_HOST = _str("OBSERVER_HOST", "127.0.0.1")  # HTTP bind address
OBSERVER_PORT = _int("OBSERVER_PORT", 8000)         # HTTP listen port


# ── Local lifecycle supervisor + edge runtime (blacksea up/down/logs/reset — step 3) ──
# The `blacksea up`/`down`/`logs`/`reset` verbs (console/supervisor.py) start the native app
# daemons (edge + brain) as detached background processes under BS_DEV_DIR, replacing the retired
# scripts/dev-up.sh nohup supervisor. The edge-runtime coordinates below are handed to the Go edge
# process at launch; the edge keeps matching fallbacks in
# edge/config.go (the two-language mirror noted at the top of this file) for a bare `edge` run — so
# a value changed here MUST be changed there too. The DNS listen addr defaults to :15353 (dev), not
# the edge binary's own :5353 fallback, because UDP 5353 is usually taken by mDNS on a dev host.
# These are anchored under BS_PROJECT_ROOT (CWD-independent) so `up`/`down`/`reset` operate on the
# repo's `.dev/`, `edge/`, and compose file regardless of the invoking directory; each env var still
# overrides. In-tree (root == cwd) the anchored path is identical to the old relative default.
BS_DEV_DIR = _root_path("BS_DEV_DIR", ".dev")                 # supervisor state dir (PID/log/cmd files)
EDGE_DIR = _root_path("EDGE_DIR", "edge")                     # edge Go module dir (for `go build`)
EDGE_BIN = _root_path("EDGE_BIN", "edge", "bin", "edge")      # the built Go edge binary
# The docker-compose file `blacksea up`/`down` drives (docker mode). Anchored so `docker compose -f`
# finds it from any CWD — the supervisor passes it explicitly rather than relying on compose's own
# CWD lookup. Override with $BS_COMPOSE_FILE.
BS_COMPOSE_FILE = _root_path("BS_COMPOSE_FILE", "docker-compose.yml")
EDGE_ID = _str("EDGE_ID", "edge-local")                      # edge node id stamped into the edge group
EDGE_DNS_ADDR = _str("DNS_ADDR", ":15353")                   # edge DNS listen addr (dev :15353, not mDNS :5353)
EDGE_DNS_ZONES = _str("DNS_ZONES", "cb.example.com")         # edge canary zones (comma-separated)
EDGE_HTTPS_ADDR = _str("HTTPS_ADDR", ":8443")                # edge HTTPS listen addr
# Who runs the app daemons in EXTERNAL mode: "blacksea" (`up` detaches them itself — external-infra
# dev) or "supervised" (systemd/containers own them; `up` starts nothing and only health-checks —
# true production, so a honeypot's uptime never depends on a CLI). Docker mode always uses blacksea.
BS_DAEMONS = _str("BS_DAEMONS", "blacksea")


# ── Read-view defaults (correlation reader + observer API) ──────────────────────
# One home for the page-size / bucket / table literals that were duplicated across
# correlation/queries.py, correlation/reader.py, observer/api.py and service.py.
RECORDS_TABLE = "records"    # event-store table the read layer queries (schema owned by the brain)
DEFAULT_LIMIT = 100          # default page size for record + session listings
MAX_LIMIT = 1000             # hard cap on a client-requested page size
DEFAULT_OFFSET = 0           # default listing offset
DEFAULT_ORDER = "desc"       # default sort direction over edge_recv_time
HEALTH_BUCKET_S = 3600       # hit-rate bucket width (s) for the burn-detection views (§6.8)


# ── Factory ─────────────────────────────────────────────────────────────────────
FACTORY_SUBPROCESS_TIMEOUT = _float("BS_FACTORY_TIMEOUT", 300.0)  # staging-vessel / build subprocess timeout (s)


# ── OTLP telemetry emitter (blacksea.otel_export) ──────────────────────────────
# The operator's entire "subscription": stand up an OTLP endpoint (normally an
# OpenTelemetry Collector) and point BS_OTEL_ENDPOINT at it. The standalone emitter
# (`python -m blacksea.otel_export`) polls the durable `records` table via the
# correlation read layer, maps each Record → one OTLP LogRecord, and pushes it — off
# the ingest hot path, holding no keys and writing nothing. See otel_export/context.md.
#
# CONFIG RESOLUTION (read this before wiring a new BS_OTEL_* knob): every value below is
# resolved from os.environ **at import time**, and the emitter reads the resulting constants
# **once at startup** — it never re-reads. The `blacksea` console manages these
# keys in a dedicated env file `secrets/otel.env` (`blacksea otel config set K=V`); `blacksea otel
# run` loads that file into a fresh emitter subprocess (whose settings.py then resolves from the
# injected env), and `blacksea otel install-unit` emits an OS unit with `EnvironmentFile=`. Because
# resolution is import-time, editing `secrets/otel.env` affects only the NEXT run/unit start, never
# a running emitter — restart it to apply. See docs/console.md + docs/otel-export.md.
BS_OTEL_ENABLED = _bool("BS_OTEL_ENABLED", False)         # master on/off (default OFF)
BS_OTEL_ENDPOINT = _opt("BS_OTEL_ENDPOINT")               # OTLP endpoint URL (their Collector / SIEM receiver)
BS_OTEL_PROTOCOL = _str("BS_OTEL_PROTOCOL", "http/protobuf")  # "http/protobuf" (default) | "grpc"
BS_OTEL_HEADERS = _opt("BS_OTEL_HEADERS")                 # auth headers, comma-sep "k=v" (e.g. "Authorization=Bearer …")
BS_OTEL_TLS_CA = _opt("BS_OTEL_TLS_CA")                   # CA bundle for a private-CA / untrusted hop
BS_OTEL_TLS_CERT = _opt("BS_OTEL_TLS_CERT")               # client cert (mTLS)
BS_OTEL_TLS_KEY = _opt("BS_OTEL_TLS_KEY")                 # client key (mTLS)
BS_OTEL_DEPLOYMENT_ID = _str("BS_OTEL_DEPLOYMENT_ID", "blacksea")  # Resource blacksea.deployment_id
BS_OTEL_EMIT_DETAILS = _bool("BS_OTEL_EMIT_DETAILS", True)  # include `details` attrs (default ON; §6)
BS_OTEL_POLL_INTERVAL = _float("BS_OTEL_POLL_INTERVAL", 2.0)  # poll cadence (s)
# Cursor seed: ms-epoch to start emitting *after* (default: process start "now"). A value in the
# past is a deliberate backfill window. None here means "seed from now" — resolved at start.
BS_OTEL_START_TIME = _opt("BS_OTEL_START_TIME")           # optional ms-epoch cursor seed (None → now)
BS_OTEL_BATCH_LIMIT = _int("BS_OTEL_BATCH_LIMIT", 500)    # max records fetched per poll (keyset page size)
