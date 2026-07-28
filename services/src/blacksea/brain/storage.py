"""brain.storage — Postgres storage client (§3.1).

write_record   idempotent upsert keyed by record_id (ON CONFLICT DO NOTHING — §3.2).
read_record    point-read by record_id.
list_records   filtered scan for console/analyst queries.
iter_typed_events  TypedEvent projection stream for Tier-2 replay (§6.0.1).
"""

from __future__ import annotations

from pathlib import Path
from typing import Any, AsyncIterator

import psycopg
from psycopg.rows import dict_row
from psycopg.types.json import Jsonb

from blacksea.sdk.framework.types import TypedEvent

_SCHEMA_SQL = (Path(__file__).parent / "schema.sql").read_text()


async def init_schema(conn: psycopg.AsyncConnection) -> None:
    """Create the records table if it does not exist (idempotent)."""
    await conn.execute(_SCHEMA_SQL)
    await conn.commit()


async def write_record(conn: psycopg.AsyncConnection, record: dict) -> None:
    """Upsert a record by record_id. On conflict, do nothing (idempotent replay — §3.2)."""
    obs = record["observed_source"]
    signals = record.get("signals")
    details = record.get("details")

    await conn.execute(
        """
        INSERT INTO records (
            record_id, bait_id, bait_version, instance_token, campaign_id,
            assurance_tier, deploy_class,
            session_id, seq_no, event_type,
            edge_recv_time, sensor_time,
            source_ip, source_ja3, source_type,
            sig_valid, channel, edge_id,
            orphan, instance_status, design_status, test,
            signals, details, details_truncated
        ) VALUES (
            %(record_id)s, %(bait_id)s, %(bait_version)s, %(instance_token)s, %(campaign_id)s,
            %(assurance_tier)s, %(deploy_class)s,
            %(session_id)s, %(seq_no)s, %(event_type)s,
            %(edge_recv_time)s, %(sensor_time)s,
            %(source_ip)s, %(source_ja3)s, %(source_type)s,
            %(sig_valid)s, %(channel)s, %(edge_id)s,
            %(orphan)s, %(instance_status)s, %(design_status)s, %(test)s,
            %(signals)s, %(details)s, %(details_truncated)s
        )
        ON CONFLICT (record_id) DO NOTHING
        """,
        {
            "record_id": record["record_id"],
            "bait_id": record["bait_id"],
            "bait_version": record["bait_version"],
            "instance_token": record["instance_token"],
            "campaign_id": record["campaign_id"],
            "assurance_tier": record["assurance_tier"],
            "deploy_class": record["deploy_class"],
            "session_id": record["session_id"],
            "seq_no": record["seq_no"],
            "event_type": record["event_type"],
            "edge_recv_time": record["edge_recv_time"],
            "sensor_time": record["sensor_time"],
            "source_ip": obs["ip"],
            "source_ja3": obs.get("ja3"),
            "source_type": obs["source_type"],
            "sig_valid": record["sig_valid"],
            "channel": record["channel"],
            "edge_id": record["edge_id"],
            "orphan": record["orphan"],
            "instance_status": record["instance_status"],
            "design_status": record["design_status"],
            "test": record["test"],
            "signals": Jsonb(signals) if signals is not None else None,
            "details": Jsonb(details) if details is not None else None,
            "details_truncated": record.get("details_truncated", False),
        },
    )


async def heartbeat(conn: psycopg.AsyncConnection, *, consumer_lag: int | None = None) -> None:
    """Upsert the brain liveness heartbeat.

    Bumps ``brain_health.last_poll_at`` to ``now()`` on the single (id=1) row so
    ``blacksea status`` can read the brain's liveness directly instead of inferring it —
    the brain can otherwise silently stop consuming with nothing noticing. ``consumer_lag``
    is optional (NULL until JetStream lag is wired in). Commits (its own tiny transaction,
    kept off the record-write connection so it never entangles a record commit)."""
    await conn.execute(
        """
        INSERT INTO brain_health (id, last_poll_at, consumer_lag)
        VALUES (1, now(), %(lag)s)
        ON CONFLICT (id) DO UPDATE
            SET last_poll_at = EXCLUDED.last_poll_at,
                consumer_lag = EXCLUDED.consumer_lag
        """,
        {"lag": consumer_lag},
    )
    await conn.commit()


async def read_record(conn: psycopg.AsyncConnection, record_id: str) -> dict | None:
    async with conn.cursor(row_factory=dict_row) as cur:
        await cur.execute("SELECT * FROM records WHERE record_id = %s", (record_id,))
        row = await cur.fetchone()
    return dict(row) if row else None


async def list_records(
    conn: psycopg.AsyncConnection,
    *,
    bait_id: str | None = None,
    campaign_id: str | None = None,
    instance_token: str | None = None,
    sig_valid: bool | None = None,
    limit: int = 100,
    offset: int = 0,
) -> list[dict]:
    clauses: list[str] = []
    params: dict[str, Any] = {"limit": limit, "offset": offset}

    if bait_id is not None:
        clauses.append("bait_id = %(bait_id)s")
        params["bait_id"] = bait_id
    if campaign_id is not None:
        clauses.append("campaign_id = %(campaign_id)s")
        params["campaign_id"] = campaign_id
    if instance_token is not None:
        clauses.append("instance_token = %(instance_token)s")
        params["instance_token"] = instance_token
    if sig_valid is not None:
        clauses.append("sig_valid = %(sig_valid)s")
        params["sig_valid"] = sig_valid

    where = ("WHERE " + " AND ".join(clauses)) if clauses else ""
    sql = (
        f"SELECT * FROM records {where} "
        "ORDER BY edge_recv_time DESC "
        "LIMIT %(limit)s OFFSET %(offset)s"
    )

    async with conn.cursor(row_factory=dict_row) as cur:
        await cur.execute(sql, params)
        rows = await cur.fetchall()
    return [dict(r) for r in rows]


async def iter_typed_events(
    conn: psycopg.AsyncConnection,
    *,
    after_record_id: str | None = None,
) -> AsyncIterator[TypedEvent]:
    """Yield TypedEvent projections in edge_recv_time order for Tier-2 replay.

    Strips sensor_time and details per the TypedEvent contract (§6.0.1, inv 12/17).
    after_record_id: if set, skip all records up to and including that record_id.
    """
    sql = "SELECT * FROM records ORDER BY edge_recv_time ASC, record_id ASC"
    skip = after_record_id is not None
    async with conn.cursor(row_factory=dict_row) as cur:
        await cur.execute(sql)
        async for row in cur:
            r = dict(row)
            if skip:
                if r["record_id"] == after_record_id:
                    skip = False
                continue
            yield _to_typed_event(r)


def _to_typed_event(r: dict) -> TypedEvent:
    signals: dict = r.get("signals") or {}
    return TypedEvent(
        record_id=r["record_id"],
        bait_id=r["bait_id"],
        instance_token=bytes.fromhex(r["instance_token"]),
        campaign_id=r["campaign_id"],
        deploy_class=r["deploy_class"],
        assurance_tier=r["assurance_tier"],
        session_id=bytes.fromhex(r["session_id"]),
        seq_no=r["seq_no"],
        event_type=r["event_type"],
        edge_recv_time=r["edge_recv_time"],
        source_ip=r["source_ip"],
        source_ja3=r.get("source_ja3"),
        source_type=r["source_type"],
        fingerprint_hash=signals.get("fingerprint_hash"),
        caution_level=signals.get("caution_level"),
        explicit_session_end=bool(signals.get("explicit_session_end", False)),
        sig_valid=r["sig_valid"],
        orphan=r["orphan"],
        instance_status=r["instance_status"],
    )
