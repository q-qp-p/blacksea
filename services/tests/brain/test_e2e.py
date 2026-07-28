"""End-to-end vertical slice.

Drives the real pool.handle path — verify → interpret(real bait) → assemble →
write — against a live Postgres, using the reference hostname-probe bait and a
QueuedEnvelope shaped exactly as the edge publishes it. Also pins the
dead-letter behaviour: a bad message acks and never crashes the worker (inv 11).

These tests commit, then delete the records they wrote (targeted by a dedicated
instance_token) so the database is left clean.
"""

from __future__ import annotations

import asyncio
import json
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

import psycopg
import pytest
import yaml

from blacksea.brain import pool, storage
from blacksea.brain.keydir_poller import KeyDirectoryHolder
from blacksea.brain.verifier import DirEntry, KeyDirectory
from blacksea.control_plane import listeners
from blacksea.control_plane.registry import DesignRecord, Registry

from _helpers import FakeMsg, tier0_dns_envelope

BAIT_DIR = Path(__file__).resolve().parents[2] / "test_fixtures" / "baits" / "hostname_probe"
E2E_TOKEN = "e2e00000e2e00000"  # dedicated token so cleanup is surgical
_E2E_SCHEMA = "cp_braine2e"

# The brain resolves bait_id from its OWN key directory now (the dead-drop edge forwards only
# `tok`). A real deployment's token is always in the brain keydir (the factory writes every built
# instance), so the e2e seeds it here — an active hostname-probe entry keyed by E2E_TOKEN.
E2E_KEYDIR = KeyDirectory({
    bytes.fromhex(E2E_TOKEN): DirEntry(
        key_bytes=b"\x00" * 32, status="active", bait_id="hostname-probe",
        campaign_id="camp-1", assurance_tier=0, default_channel="dns",
        valid_from=0, valid_until=None,
    ),
})


@pytest.fixture(scope="module")
def catalog(pg_dsn, tmp_path_factory):
    """Seed the control-plane catalog + frozen material with the reference bait, exactly
    as `register` would (D2/O10). The brain then loads it from here — no git baits dir."""
    root = tmp_path_factory.mktemp("cp")
    artifacts = str(root / "artifacts")
    manifest = yaml.safe_load((BAIT_DIR / "manifest.yaml").read_text())
    with psycopg.connect(pg_dsn, autocommit=True) as conn:
        conn.execute(f"DROP SCHEMA IF EXISTS {_E2E_SCHEMA} CASCADE")
    reg = Registry(pg_dsn, registry_root=str(root / "registry"), schema=_E2E_SCHEMA)
    reg.ensure_schema()
    h = listeners.freeze_listener(
        str(BAIT_DIR), manifest, artifacts_root=artifacts,
        bait_id="hostname-probe", version="1.0.0")
    reg.put_design(DesignRecord(
        bait_id="hostname-probe", manifest=manifest, bait_dir=str(BAIT_DIR),
        status="deployed", listener_hash=h))
    reg.close()
    pool._registry.clear()   # force a fresh lazy-load from this catalog
    yield _E2E_SCHEMA, artifacts
    pool._registry.clear()
    with psycopg.connect(pg_dsn, autocommit=True) as conn:
        conn.execute(f"DROP SCHEMA IF EXISTS {_E2E_SCHEMA} CASCADE")


async def _cleanup(conn):
    await conn.execute("DELETE FROM records WHERE instance_token = %s", (E2E_TOKEN,))
    await conn.commit()


def _drive(dsn, queued: dict, catalog, keydir: KeyDirectory = E2E_KEYDIR):
    """Run one message through the pool against a real DB; return (acked, record). The
    bait loads lazily from the catalog on first hit (O2/O10)."""
    schema, artifacts = catalog

    async def _wrap():
        conn = await psycopg.AsyncConnection.connect(dsn, autocommit=False)
        await storage.init_schema(conn)
        cat = await psycopg.AsyncConnection.connect(dsn, autocommit=True)
        ex = ThreadPoolExecutor(max_workers=1)
        try:
            await _cleanup(conn)
            msg = FakeMsg(queued)
            await pool._handle(
                msg, KeyDirectoryHolder(keydir), conn, cat, artifacts, schema, ex)
            rec_id = (
                f"{queued['instance_token']}-{queued['session_id']}"
                f"-{int(queued['seq_no']):04x}"
            )
            rec = await storage.read_record(conn, rec_id)
            await _cleanup(conn)
            return msg.acked, rec
        finally:
            ex.shutdown(wait=False)
            await conn.close()
            await cat.close()

    return asyncio.run(_wrap())


def test_tier0_hostname_probe_lands_in_postgres(pg_dsn, catalog):
    """First bait fires → Record in Postgres. obs_body carries the hostname,
    interpret() classifies it, the framework assembles and stores the record."""
    body = json.dumps({"hostname": "victim-box"}, sort_keys=True,
                      separators=(",", ":")).encode()
    queued = tier0_dns_envelope(instance_token=E2E_TOKEN, body=body)

    acked, rec = _drive(pg_dsn, queued, catalog)

    assert acked is True
    assert rec is not None
    assert rec["bait_id"] == "hostname-probe"
    assert rec["bait_version"] == "1.0.0"
    assert rec["deploy_class"] == "portable_artifact"
    assert rec["assurance_tier"] == 0
    assert rec["sig_valid"] is False           # tier-0 is unsigned by design
    assert rec["event_type"] == "payload_exec_collect"
    assert rec["details"] == {"hostname": "victim-box"}
    assert rec["source_type"] == "resolver"
    # orphan is brain-derived from the directory status now (the edge sends nothing): the seeded
    # instance is active, so this is a live hit, not an orphan.
    assert rec["orphan"] is False
    assert rec["test"] is True                # hostname-probe's manifest sets test: true


def test_tier0_retired_instance_is_orphan(pg_dsn, catalog):
    """orphan is derived from the brain's directory status now (the edge sends nothing): a late
    hit from a retired instance is stored + flagged orphan (intel, never dropped, §5.7)."""
    retired_keydir = KeyDirectory({
        bytes.fromhex(E2E_TOKEN): DirEntry(
            key_bytes=b"\x00" * 32, status="retired", bait_id="hostname-probe",
            campaign_id="camp-1", assurance_tier=0, default_channel="dns",
            valid_from=0, valid_until=None,
        ),
    })
    body = json.dumps({"hostname": "victim-box"}, sort_keys=True,
                      separators=(",", ":")).encode()
    queued = tier0_dns_envelope(instance_token=E2E_TOKEN, seq_no=5, body=body)

    acked, rec = _drive(pg_dsn, queued, catalog, keydir=retired_keydir)

    assert acked is True
    assert rec is not None
    assert rec["instance_status"] == "retired"
    assert rec["orphan"] is True


def test_tier0_zero_body_is_signal_only(pg_dsn, catalog):
    """No obs_body → empty body → the bait returns the signal-only event."""
    queued = tier0_dns_envelope(instance_token=E2E_TOKEN, seq_no=3, body=None)
    acked, rec = _drive(pg_dsn, queued, catalog)

    assert acked is True
    assert rec is not None
    assert rec["event_type"] == "signal_only"
    assert rec["details"] is None


def test_unknown_token_is_dead_lettered(pg_dsn, catalog):
    """An unroutable hit — token absent from the brain key directory — acks (dead-letter) and
    writes nothing. Routing is now keyed on the token via the brain keydir, not an edge-supplied
    bait_id, so an unseeded token is the unroutable case."""
    queued = tier0_dns_envelope(instance_token="00ffff0000ffff00")
    acked, rec = _drive(pg_dsn, queued, catalog)

    assert acked is True   # acked so it does not requeue forever
    assert rec is None     # nothing stored


def test_malformed_json_is_dead_lettered(pg_dsn, catalog):
    """A non-JSON message acks and never reaches storage — the worker survives."""
    schema, artifacts = catalog

    async def _wrap():
        conn = await psycopg.AsyncConnection.connect(pg_dsn, autocommit=False)
        await storage.init_schema(conn)
        cat = await psycopg.AsyncConnection.connect(pg_dsn, autocommit=True)
        ex = ThreadPoolExecutor(max_workers=1)
        try:
            msg = FakeMsg(b"this is not json{{{")
            await pool._handle(
                msg, KeyDirectoryHolder(KeyDirectory({})), conn, cat, artifacts, schema, ex)
            return msg.acked
        finally:
            ex.shutdown(wait=False)
            await conn.close()
            await cat.close()

    assert asyncio.run(_wrap()) is True
