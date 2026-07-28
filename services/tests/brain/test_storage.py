"""storage.py — Postgres client (§3.1).

Integration tests against a live Postgres (skipped when none is reachable —
see conftest). Each test runs inside a single connection and never commits, so
the database is left untouched (rollback on close).
"""

from __future__ import annotations

import asyncio

import psycopg

from blacksea.brain import storage
from blacksea.brain.assembly import assemble
from blacksea.sdk.types import AnalyzerOutput, Signals
from blacksea.sdk.listener import test_envelope


# A token used only by this module so delete-first cleanup is surgical and these
# tests never collide with rows committed elsewhere (the e2e suite, manual runs).
STORAGE_TOKEN = "5709a6e05709a6e0"


def _record(*, seq_no=0, sig_valid=True, signals=None, details=None,
            instance_token=STORAGE_TOKEN, session_id="aabbccddeeff0011",
            sensor_time=1_700_000_000_123, bait_id="hostname-probe",
            campaign_id="camp-1", test=False):
    env = test_envelope(
        tier=2 if sig_valid else 0,
        bait_id=bait_id,
        campaign_id=campaign_id,
        instance_token=bytes.fromhex(instance_token),
        session_id=bytes.fromhex(session_id),
        seq_no=seq_no,
        sensor_time=sensor_time,
        sig_valid=sig_valid,
    )
    return assemble(
        env,
        AnalyzerOutput(event_type="payload_exec_collect", signals=signals, details=details),
        deploy_class="portable_artifact",
        design_status="deployed",
        instance_status="active",
        orphan=False,
        test=test,
    )


def _run(dsn, coro_fn):
    async def _wrap():
        # autocommit=False + never committing → the connection rolls back on close.
        conn = await psycopg.AsyncConnection.connect(dsn, autocommit=False)
        try:
            await storage.init_schema(conn)  # commits the (idempotent) DDL only
            # Delete-first inside this (uncommitted) txn so the tests are isolated
            # from any rows committed by earlier runs and so the idempotency test
            # observes a clean insert rather than a pre-existing conflict.
            await conn.execute("DELETE FROM records WHERE instance_token = %s", (STORAGE_TOKEN,))
            return await coro_fn(conn)
        finally:
            await conn.rollback()
            await conn.close()

    return asyncio.run(_wrap())


def test_write_then_read_roundtrip(pg_dsn):
    rec = _record(details={"hostname": "victim-box"})

    async def body(conn):
        await storage.write_record(conn, rec)
        return await storage.read_record(conn, rec["record_id"])

    got = _run(pg_dsn, body)
    assert got is not None
    assert got["record_id"] == rec["record_id"]
    assert got["event_type"] == "payload_exec_collect"
    assert got["sig_valid"] is True
    assert got["details"] == {"hostname": "victim-box"}
    assert got["source_type"] == "client"


def test_write_is_idempotent_on_record_id(pg_dsn):
    """§3.2: replay of the same record_id is a no-op (ON CONFLICT DO NOTHING).
    The first write wins; a second write with different content must not clobber."""
    first = _record(details={"hostname": "first"})
    second = _record(details={"hostname": "SECOND"})  # same record_id

    async def body(conn):
        await storage.write_record(conn, first)
        await storage.write_record(conn, second)
        return await storage.read_record(conn, first["record_id"])

    got = _run(pg_dsn, body)
    assert got["details"] == {"hostname": "first"}


def test_list_records_filters(pg_dsn):
    async def body(conn):
        await storage.write_record(conn, _record(seq_no=1, campaign_id="camp-A"))
        await storage.write_record(conn, _record(seq_no=2, campaign_id="camp-B"))
        a = await storage.list_records(conn, campaign_id="camp-A")
        sig = await storage.list_records(conn, sig_valid=True, campaign_id="camp-A")
        none = await storage.list_records(conn, campaign_id="camp-DOES-NOT-EXIST")
        return a, sig, none

    only_a, sig_true, empty = _run(pg_dsn, body)
    assert all(r["campaign_id"] == "camp-A" for r in only_a)
    assert all(r["sig_valid"] for r in sig_true)
    assert empty == []


def test_iter_typed_events_strips_sensor_time_and_details(pg_dsn):
    """§6.0.1 / inv 12 + 17: the TypedEvent projection has no sensor_time and no
    details field at all, and promotes signals into flat columns."""
    rec = _record(
        signals=Signals(caution_level="high", fingerprint_hash="fp123"),
        details={"secret": "do-not-leak"},
    )

    async def body(conn):
        await storage.write_record(conn, rec)
        events = [e async for e in storage.iter_typed_events(conn)]
        return events

    events = _run(pg_dsn, body)
    mine = [e for e in events if e.record_id == rec["record_id"]]
    assert len(mine) == 1
    ev = mine[0]
    # Structurally absent — the dataclass simply has no such fields.
    assert not hasattr(ev, "sensor_time")
    assert not hasattr(ev, "details")
    # Promoted signals are flat columns on the projection.
    assert ev.caution_level == "high"
    assert ev.fingerprint_hash == "fp123"
    assert ev.event_type == "payload_exec_collect"
    assert ev.instance_token == bytes.fromhex(STORAGE_TOKEN)
