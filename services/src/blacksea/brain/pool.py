"""brain.pool — analyzer worker pool.

Consumes NATS JetStream messages from bait.*, re-verifies (inv 13), dispatches
to interpret() under timeout, assembles the Record, and writes to Postgres.

Dead-letters (acks + logs) on: JSON parse failure, unknown bait_id, verification
structural error, interpret() timeout or exception, storage failure. The pool
continues processing; a bad message never crashes the worker (inv 11).

Usage:
    python -m blacksea.brain.pool \\
        --nats  nats://localhost:4222 \\
        --postgres "host=localhost dbname=blacksea" \\
        --keydir path/to/brain_keydir.json \\
        --artifacts-root path/to/registry/artifacts/ \\
        --schema control_plane

``--keydir`` is the brain key directory (see src/blacksea/brain/context.md) — the sole key
directory now that the edge is a dumb dead-drop with none of its own. It carries per-instance
`_KEY` material; the brain resolves routing and decodes every hit against it. Pointing this at
anything without `key` (there is no longer an edge-facing routing directory) keyless-fails.

Baits are no longer scanned from a git dir (O9): the brain reads the design manifest +
live lifecycle from the shared control-plane catalog (``--schema`` / ``control_plane``,
SELECT-only per O6) and imports the *frozen* listener from the material store at
``--artifacts-root``/<bait_id>/<version>/listener/, verifying its bytes against the
catalog's pinned ``listener_hash`` before importing (O10/O11).
"""

from __future__ import annotations

import argparse
import asyncio
import base64
import json
import logging
from concurrent.futures import ThreadPoolExecutor
from dataclasses import replace
from typing import Any

import nats
import psycopg
from psycopg import sql

from blacksea.brain.assembly import assemble
from blacksea.brain.keydir_poller import KeyDirectoryHolder, poll_keydir
from blacksea.brain.storage import heartbeat, init_schema, write_record
from blacksea.brain.verifier import (
    KeyDirectory,
    VerificationError,
    resolve_entry,
    verify_with_entry,
)
from blacksea.config import settings
from blacksea.control_plane import listeners

log = logging.getLogger(__name__)

INTERPRET_TIMEOUT = settings.INTERPRET_TIMEOUT
KEYDIR_POLL_S = settings.KEYDIR_POLL_S
HEARTBEAT_S = settings.BRAIN_HEARTBEAT_S
NATS_STREAM = settings.NATS_STREAM
NATS_CONSUMER = settings.NATS_CONSUMER
NATS_MAX_BYTES = settings.NATS_MAX_BYTES
NATS_MAX_AGE_S = settings.NATS_MAX_AGE_S

# Directory statuses that make a hit an "orphan": a late hit from an instance that is no longer a
# live bait (§5.7). "revoked" is deliberately excluded — a revoked key is weaponized and heavy-
# sampled, not a dead-bait orphan. Named so this set can't silently drift from the derivation.
_ORPHAN_STATUSES = frozenset({"burned", "retired"})

# bait_id → (listener_instance, bait_version, deploy_class, test). The design *status*
# is NOT cached here — it is read live from the catalog per hit (O2), so a burn/retire
# is reflected without a brain restart. The listener + its immutable-per-version bytes
# are cached (importing is expensive; the frozen closure never changes for a version).
_registry: dict[str, tuple[Any, str, str, bool]] = {}


# ── bait loading — from the control-plane catalog + frozen material (O2/O9/O10/O11) ──
#
# The brain no longer scans a git baits dir (BS_BAITS_DIR is gone, O9). It reads the
# design manifest + lifecycle from the shared catalog (control_plane schema, SELECT-only
# per O6) and imports the *frozen* listener from the material store at a path derived from
# IDs — <artifacts-root>/<bait_id>/<version>/listener/ — verifying the bytes against the
# catalog's pinned listener_hash before importlib (O11). Baits are loaded lazily on first
# hit (so a bait forged after the brain started is still picked up — the e2e stack brings
# the brain up before forging), with a best-effort pre-load at startup for fail-fast logs.


async def _fetch_design(cat: psycopg.AsyncConnection, schema: str, bait_id: str) -> dict | None:
    """Point-read a design's ``version``/``manifest``/``listener_hash``/``status`` from the
    catalog. Returns ``None`` if the bait is unknown or the catalog is not initialised yet."""
    q = sql.SQL(
        "SELECT version, manifest, listener_hash, status FROM {}.design WHERE bait_id = %s"
    ).format(sql.Identifier(schema))
    try:
        async with cat.cursor() as cur:
            await cur.execute(q, (bait_id,))
            row = await cur.fetchone()
    except psycopg.errors.UndefinedTable:
        return None  # control_plane catalog not bootstrapped yet — no baits to load
    except Exception as exc:  # noqa: BLE001 — a catalog read must never crash the worker (inv 11)
        log.error("catalog read failed for bait %r: %s", bait_id, exc)
        return None
    if row is None:
        return None
    version, manifest, listener_hash, status = row
    return {"version": str(version), "manifest": manifest,
            "listener_hash": listener_hash, "status": status}


async def _ensure_bait(
    cat: psycopg.AsyncConnection, artifacts_root: str, schema: str, bait_id: str,
) -> tuple | None:
    """Return the cached ``_registry`` entry for ``bait_id``, loading + verifying it from the
    catalog + frozen material on a cache miss (O9/O10/O11). Returns ``None`` (→ dead-letter)
    if the bait is unknown or the frozen listener is missing / fails hash verification."""
    hit = _registry.get(bait_id)
    if hit is not None:
        return hit
    design = await _fetch_design(cat, schema, bait_id)
    if design is None:
        return None
    manifest = design["manifest"]
    version = design["version"]
    try:
        listener = listeners.load_frozen_listener(
            artifacts_root, bait_id, version, manifest,
            expected_hash=design["listener_hash"])
    except listeners.ListenerError as exc:
        # Hash mismatch / missing material — refuse to import untrusted code (O11).
        log.error("bait %r v%s: %s — not loading (dead-letter + alert)", bait_id, version, exc)
        return None
    listener.on_register()
    deploy_class = str(manifest.get("deploy_class", ""))
    is_test = bool(manifest.get("test", False))
    entry = (listener, version, deploy_class, is_test)
    _registry[bait_id] = entry
    log.info("loaded bait %r v%s deploy_class=%s test=%s (frozen listener, hash-verified)",
             bait_id, version, deploy_class, is_test)
    return entry


async def _design_status(cat: psycopg.AsyncConnection, schema: str, bait_id: str) -> str:
    """Live design status from the catalog (O2 — replaces the hardcoded 'deployed').
    Falls back to 'unknown' if the design vanished or the catalog is unavailable."""
    design = await _fetch_design(cat, schema, bait_id)
    return design["status"] if design is not None else "unknown"


async def load_baits(cat: psycopg.AsyncConnection, artifacts_root: str, schema: str) -> None:
    """Best-effort pre-load of every current design from the catalog at startup. A bait
    that fails to load (missing/tampered frozen listener) is logged and skipped, not fatal —
    it will simply dead-letter its hits until fixed. Baits registered after startup load
    lazily on first hit (see :func:`_ensure_bait`)."""
    q = sql.SQL("SELECT bait_id FROM {}.design").format(sql.Identifier(schema))
    try:
        async with cat.cursor() as cur:
            await cur.execute(q)
            bait_ids = [r[0] for r in await cur.fetchall()]
    except psycopg.errors.UndefinedTable:
        log.info("control_plane catalog not initialised yet — baits will load lazily on first hit")
        return
    for bait_id in bait_ids:
        await _ensure_bait(cat, artifacts_root, schema, bait_id)


# ── NATS setup ───────────────────────────────────────────────────────────────

def _baits_stream_config():
    """The StreamConfig for the shared BAITS stream. Split out so it is unit-testable without a live
    NATS (tests/brain/test_stream_config.py) and so the exact limit fields live in one place.

    The ``max_bytes``/``max_age`` caps + ``discard=old`` bound the stream's on-disk footprint: under
    LimitsPolicy retention a consumer ack does NOT evict a message — only a size/count/age limit can
    — so WITHOUT these the stream is an append-only log of every hit ever published, bounded only by
    host disk, which an unauthenticated party can drive to exhaustion through the edge's beacon
    endpoints. These fields MUST match the edge's ``baitsStreamConfig`` in
    ``edge/queue.go`` — both provision the same stream, and whichever side runs last on a fresh
    deploy wins (see the two-language note in ``blacksea.config.settings``)."""
    from nats.js.api import DiscardPolicy, RetentionPolicy, StorageType, StreamConfig
    return StreamConfig(
        name=NATS_STREAM,
        subjects=[settings.SUBJECT_FILTER],
        retention=RetentionPolicy.LIMITS,
        storage=StorageType.FILE,
        discard=DiscardPolicy.OLD,          # trim oldest when a cap is reached, don't reject new
        max_bytes=NATS_MAX_BYTES or None,   # disk cap (bytes); None = unbounded (0 in settings)
        max_age=NATS_MAX_AGE_S or None,     # age cap (seconds); None = unbounded (0 in settings)
        duplicate_window=120.0,             # matches the edge's Duplicates: 2 * time.Minute
    )


async def _ensure_stream(js) -> None:
    """Create the BAITS JetStream stream, or update an existing one to carry the current disk caps.

    add_stream errors if the stream already exists (with any config); we fall back to update_stream
    so a stream an older, unbounded build created gets tightened to the issue-#19 caps on the next
    brain start rather than staying append-only. retention/storage stay LimitsPolicy/File (unchanged
    from the historical default), so update never touches an immutable field."""
    cfg = _baits_stream_config()
    try:
        await js.add_stream(cfg)
        log.info("created NATS stream %r (max_bytes=%s max_age_s=%s)",
                 NATS_STREAM, NATS_MAX_BYTES, NATS_MAX_AGE_S)
        return
    except Exception as exc:
        log.debug("add_stream %r: %s (stream likely already exists — updating caps)", NATS_STREAM, exc)
    try:
        await js.update_stream(cfg)
        log.info("updated NATS stream %r caps (max_bytes=%s max_age_s=%s)",
                 NATS_STREAM, NATS_MAX_BYTES, NATS_MAX_AGE_S)
    except Exception as exc:
        log.warning("could not apply BAITS stream caps to %r: %s", NATS_STREAM, exc)


# ── message handling ─────────────────────────────────────────────────────────

async def _handle(msg, keydir_holder: KeyDirectoryHolder, pg: psycopg.AsyncConnection,
                  cat: psycopg.AsyncConnection, artifacts_root: str, schema: str,
                  executor: ThreadPoolExecutor) -> None:
    try:
        queued: dict = json.loads(msg.data)
    except Exception as exc:
        log.error("JSON parse failed: %s — dead-lettering", exc)
        await msg.ack()
        return

    # Resolve the hit's key-directory entry ONCE (the sole routing lookup) against a single
    # snapshot of the live directory, so bait_id derivation, decryption, and the status stamp all
    # see a consistent view even if the poller hot-swaps mid-handle. The edge is a dumb dead-drop —
    # it forwards only `tok`, never `bait_id`; every routing fact comes from this one entry.
    entry = resolve_entry(keydir_holder.current, queued)
    bait_id = entry.bait_id if entry is not None else ""
    reg = await _ensure_bait(cat, artifacts_root, schema, bait_id)
    if reg is None:
        log.warning("unroutable hit (token %r not in key directory / bait_id %r not in catalog / "
                    "frozen listener unavailable) — dead-lettering",
                    queued.get("instance_token", ""), bait_id)
        await msg.ack()
        return

    listener, bait_version, deploy_class, is_test = reg
    # Live design status from the catalog (O2) — a burned/retired design is reflected
    # without restarting the brain.
    design_status = await _design_status(cat, schema, bait_id)

    try:
        envelope, core_body, sig_valid = verify_with_entry(queued, entry)
    except VerificationError as exc:
        log.error("verification error (bait=%r): %s — dead-lettering", bait_id, exc)
        await msg.ack()
        return

    # Patch bait_version from the bait registry (registry-derived, not in signed-core).
    envelope = replace(envelope, bait_version=bait_version)

    # Body for interpret(): decrypted fixed binary core for tier≥1; obs_body bytes for tier 0
    # (the DNS payload — DNS is the only tier-0 channel). The tier is the brain-authoritative value
    # from the verified envelope (keydir-derived), not an edge-supplied field.
    if envelope.assurance_tier == 0:
        body = _decode_obs_body(queued.get("obs_body", ""))
    else:
        body = core_body

    loop = asyncio.get_event_loop()
    try:
        analyzer_out = await asyncio.wait_for(
            loop.run_in_executor(executor, listener.interpret, envelope, body),
            timeout=INTERPRET_TIMEOUT,
        )
    except asyncio.TimeoutError:
        log.error("interpret() timeout (bait=%r) — dead-lettering", bait_id)
        await msg.ack()
        return
    except Exception as exc:
        log.error("interpret() raised (bait=%r): %s — dead-lettering", bait_id, exc)
        await msg.ack()
        return

    # §5.7: instance_status is the brain's authoritative directory status (from the entry resolved
    # above — the sole routing authority now that the edge is a dumb dead-drop), and orphan is
    # derived from it. The edge supplies neither field.
    inst_status = entry.status if entry is not None else "unknown"
    record = assemble(
        envelope=envelope,
        analyzer_out=analyzer_out,
        deploy_class=deploy_class,
        design_status=design_status,
        instance_status=inst_status,
        orphan=inst_status in _ORPHAN_STATUSES,
        test=is_test,
    )

    try:
        await write_record(pg, record)
        await pg.commit()
    except Exception as exc:
        log.error("storage write failed (bait=%r record=%s): %s — dead-lettering",
                  bait_id, record.get("record_id"), exc)
        await pg.rollback()
        await msg.ack()
        return

    await msg.ack()
    log.info("stored record %s (bait=%s sig_valid=%s event=%s)",
             record["record_id"], bait_id, sig_valid, record["event_type"])


def _decode_obs_body(obs_body: str) -> bytes:
    if not obs_body:
        return b""
    try:
        return base64.b64decode(obs_body)
    except Exception:
        return b""


# ── liveness heartbeat ─────────────────────────────────────────────────────────

async def _heartbeat_loop(hb: psycopg.AsyncConnection, interval_s: float) -> None:
    """Upsert ``brain_health.last_poll_at`` every ``interval_s`` so ``blacksea status`` reads
    the brain's liveness directly. Runs on its own autocommit connection (never the
    record-write one) so a heartbeat can never entangle a record commit, and a heartbeat
    failure is logged but never crashes the worker (inv 11) — the console just sees the row
    go stale, which is exactly the "brain stopped" signal."""
    while True:
        try:
            await heartbeat(hb)
        except Exception as exc:  # noqa: BLE001 — heartbeat must never kill the pool (inv 11)
            log.warning("brain heartbeat upsert failed (will retry): %s", exc)
        await asyncio.sleep(interval_s)


# ── main loop ─────────────────────────────────────────────────────────────────

async def run(
    nats_url: str,
    pg_dsn: str,
    keydir_path: str,
    artifacts_root: str,
    schema: str,
    nats_user: str,
    nats_pass: str,
) -> None:
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s %(levelname)s %(name)s: %(message)s",
    )

    keydir_holder = KeyDirectoryHolder(KeyDirectory.from_file(keydir_path))

    pg = await psycopg.AsyncConnection.connect(pg_dsn, autocommit=False)
    await init_schema(pg)
    # Separate, read-only connection for the control-plane catalog (O6: the brain only
    # SELECTs the control_plane schema) — kept apart from the record-write transaction so a
    # catalog read never entangles a record commit. Autocommit: each SELECT is standalone.
    cat = await psycopg.AsyncConnection.connect(pg_dsn, autocommit=True)
    await load_baits(cat, artifacts_root, schema)
    # Dedicated autocommit connection for the liveness heartbeat — its own
    # handle so a heartbeat upsert never touches the record-write transaction. brain_health lives
    # in the brain's own (public) schema, which its login role can write.
    hb = await psycopg.AsyncConnection.connect(pg_dsn, autocommit=True)

    # Credentials are passed as separate kwargs (not in nats_url) so they never reach the logs
    # that print nats_url below.
    nc = await nats.connect(nats_url, user=nats_user, password=nats_pass)
    js = nc.jetstream()
    await _ensure_stream(js)

    executor = ThreadPoolExecutor(max_workers=settings.POOL_MAX_WORKERS)

    async def cb(msg):
        await _handle(msg, keydir_holder, pg, cat, artifacts_root, schema, executor)

    await js.subscribe(settings.SUBJECT_FILTER, durable=NATS_CONSUMER, stream=NATS_STREAM, cb=cb)
    poll_task = asyncio.create_task(poll_keydir(keydir_holder, keydir_path, KEYDIR_POLL_S))
    # Seed one heartbeat immediately (so `blacksea status` is green the moment the pool is up),
    # then keep it fresh on the heartbeat cadence.
    await heartbeat(hb)
    hb_task = asyncio.create_task(_heartbeat_loop(hb, HEARTBEAT_S))
    log.info(
        "brain pool running (nats=%s keydir=%s poll=%ss heartbeat=%ss artifacts=%s schema=%s)",
        nats_url, keydir_path, KEYDIR_POLL_S, HEARTBEAT_S, artifacts_root, schema,
    )

    try:
        await asyncio.sleep(float("inf"))
    finally:
        poll_task.cancel()
        hb_task.cancel()
        executor.shutdown(wait=False)
        await nc.drain()
        await pg.close()
        await cat.close()
        await hb.close()


def main() -> None:
    parser = argparse.ArgumentParser(description="Blacksea brain analyzer pool")
    parser.add_argument("--nats", default=settings.NATS_URL)
    parser.add_argument("--nats-user", default=settings.NATS_USER)
    parser.add_argument("--nats-pass", default=settings.NATS_PASS)
    # No literal default for the DSN: it would embed credentials. Required via env/flag.
    parser.add_argument("--postgres", default=settings.POSTGRES_DSN)
    # The brain key directory (§5.11): BS_BRAIN_KEYDIR — the sole key directory now that the edge
    # is a dumb dead-drop with none of its own. It carries `_KEY`; the brain decodes every hit
    # against it. Pointing this at anything without `key` silently keyless-fails every hit.
    parser.add_argument("--keydir", default=settings.BRAIN_KEYDIR)
    # Material store root (O9): the brain imports frozen listeners from
    # <artifacts-root>/<bait_id>/<version>/listener/. Must resolve to the same tree the
    # control plane's factory writes (co-located in dev; a signed distribution channel is
    # O10's open sub-item for multi-host prod).
    parser.add_argument("--artifacts-root", dest="artifacts_root",
                        default=settings.BS_ARTIFACTS_ROOT)
    parser.add_argument("--schema", default=settings.BS_CP_SCHEMA)
    args = parser.parse_args()
    if not args.postgres:
        parser.error("POSTGRES_DSN is required (no default credentials) — run via `make run-brain`")
    if not args.nats_user or not args.nats_pass:
        parser.error("NATS_USER and NATS_PASS are required (no anonymous NATS) — run via `make run-brain`")
    asyncio.run(run(args.nats, args.postgres, args.keydir, args.artifacts_root, args.schema,
                    args.nats_user, args.nats_pass))


if __name__ == "__main__":
    main()
