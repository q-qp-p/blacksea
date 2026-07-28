"""reader.py — the public read-only view API over the record store.

This is the layer consumers call. Every view exists as a **pair**: a sync
``foo(conn, ...)`` taking a ``psycopg.Connection`` and an async ``afoo(conn, ...)``
taking a ``psycopg.AsyncConnection``. Both members of a pair share the exact same
SQL builder (``queries.py``) and row mapper (``models.py``) — the only thing that
differs is the two-line execute, which is genuinely unavoidable across psycopg's
sync/async cursor APIs. That is how the sync console and the async observer get
one source of truth for *what* is queried and *how a row maps to a view*, without
duplicating either.

All functions are strictly read-only. None of them write, and the module never
opens or closes a connection — the caller owns connection lifecycle (per-request
in the observer, once-per-invocation in the console), so pooling and error
handling stay the caller's decision.
"""

from __future__ import annotations

from typing import Any

import psycopg
from psycopg.rows import dict_row

from blacksea.config import settings

from . import queries
from .models import (
    CautionCount,
    RecordCursor,
    RecordDetail,
    RecordFilter,
    RecordSummary,
    SessionView,
    TimeBucket,
)

_EMPTY = RecordFilter()


# ── execute helpers (the only sync/async fork) ────────────────────────────────


def _rows_sync(conn: "psycopg.Connection", sql: str, params: dict[str, Any]) -> list[dict]:
    with conn.cursor(row_factory=dict_row) as cur:
        cur.execute(sql, params)
        return [dict(r) for r in cur.fetchall()]


async def _rows_async(
    conn: "psycopg.AsyncConnection", sql: str, params: dict[str, Any]
) -> list[dict]:
    async with conn.cursor(row_factory=dict_row) as cur:
        await cur.execute(sql, params)
        return [dict(r) for r in await cur.fetchall()]


# ── records: list ─────────────────────────────────────────────────────────────


def list_records(
    conn: "psycopg.Connection",
    filt: RecordFilter | None = None,
    *,
    limit: int = settings.DEFAULT_LIMIT,
    offset: int = settings.DEFAULT_OFFSET,
    order: str = settings.DEFAULT_ORDER,
) -> list[RecordSummary]:
    sql, params = queries.list_records_sql(filt or _EMPTY, limit=limit, offset=offset, order=order)
    return [RecordSummary.from_row(r) for r in _rows_sync(conn, sql, params)]


async def alist_records(
    conn: "psycopg.AsyncConnection",
    filt: RecordFilter | None = None,
    *,
    limit: int = settings.DEFAULT_LIMIT,
    offset: int = settings.DEFAULT_OFFSET,
    order: str = settings.DEFAULT_ORDER,
) -> list[RecordSummary]:
    sql, params = queries.list_records_sql(filt or _EMPTY, limit=limit, offset=offset, order=order)
    return [RecordSummary.from_row(r) for r in await _rows_async(conn, sql, params)]


# ── records: single ───────────────────────────────────────────────────────────


def get_record(conn: "psycopg.Connection", record_id: str) -> RecordDetail | None:
    sql, params = queries.get_record_sql(record_id)
    rows = _rows_sync(conn, sql, params)
    return RecordDetail.from_row(rows[0]) if rows else None


async def aget_record(conn: "psycopg.AsyncConnection", record_id: str) -> RecordDetail | None:
    sql, params = queries.get_record_sql(record_id)
    rows = await _rows_async(conn, sql, params)
    return RecordDetail.from_row(rows[0]) if rows else None


# ── records: keyset tail (records after a cursor) ─────────────────────────────
# The one addition the otel_export emitter needs: a gap-free, duplicate-free tail
# read over the durable `records` log. Returns full RecordDetail views so the
# emitter renders the *same* value object the observer displays (observer parity).


def records_after(
    conn: "psycopg.Connection",
    cursor: RecordCursor,
    filt: RecordFilter | None = None,
    *,
    limit: int = settings.DEFAULT_LIMIT,
) -> list[RecordDetail]:
    sql, params = queries.records_after_sql(cursor, filt, limit=limit)
    return [RecordDetail.from_row(r) for r in _rows_sync(conn, sql, params)]


async def arecords_after(
    conn: "psycopg.AsyncConnection",
    cursor: RecordCursor,
    filt: RecordFilter | None = None,
    *,
    limit: int = settings.DEFAULT_LIMIT,
) -> list[RecordDetail]:
    sql, params = queries.records_after_sql(cursor, filt, limit=limit)
    return [RecordDetail.from_row(r) for r in await _rows_async(conn, sql, params)]


# ── records: count ────────────────────────────────────────────────────────────


def count_records(conn: "psycopg.Connection", filt: RecordFilter | None = None) -> int:
    sql, params = queries.count_records_sql(filt or _EMPTY)
    return int(_rows_sync(conn, sql, params)[0]["n"])


async def acount_records(conn: "psycopg.AsyncConnection", filt: RecordFilter | None = None) -> int:
    sql, params = queries.count_records_sql(filt or _EMPTY)
    return int((await _rows_async(conn, sql, params))[0]["n"])


# ── hit-rate ──────────────────────────────────────────────────────────────────


def hit_rate(
    conn: "psycopg.Connection",
    filt: RecordFilter | None = None,
    *,
    bucket_seconds: int = settings.HEALTH_BUCKET_S,
) -> list[TimeBucket]:
    sql, params = queries.hit_rate_sql(filt or _EMPTY, bucket_ms=bucket_seconds * 1000)
    return [TimeBucket.from_row(r) for r in _rows_sync(conn, sql, params)]


async def ahit_rate(
    conn: "psycopg.AsyncConnection",
    filt: RecordFilter | None = None,
    *,
    bucket_seconds: int = settings.HEALTH_BUCKET_S,
) -> list[TimeBucket]:
    sql, params = queries.hit_rate_sql(filt or _EMPTY, bucket_ms=bucket_seconds * 1000)
    return [TimeBucket.from_row(r) for r in await _rows_async(conn, sql, params)]


# ── caution distribution ──────────────────────────────────────────────────────


def caution_distribution(
    conn: "psycopg.Connection", filt: RecordFilter | None = None
) -> list[CautionCount]:
    sql, params = queries.caution_distribution_sql(filt or _EMPTY)
    return [CautionCount.from_row(r) for r in _rows_sync(conn, sql, params)]


async def acaution_distribution(
    conn: "psycopg.AsyncConnection", filt: RecordFilter | None = None
) -> list[CautionCount]:
    sql, params = queries.caution_distribution_sql(filt or _EMPTY)
    return [CautionCount.from_row(r) for r in await _rows_async(conn, sql, params)]


# ── sessions (read-time grouping) ─────────────────────────────────────────────


def session_views(
    conn: "psycopg.Connection",
    filt: RecordFilter | None = None,
    *,
    limit: int = settings.DEFAULT_LIMIT,
    offset: int = settings.DEFAULT_OFFSET,
) -> list[SessionView]:
    sql, params = queries.session_views_sql(filt or _EMPTY, limit=limit, offset=offset)
    return [SessionView.from_row(r) for r in _rows_sync(conn, sql, params)]


async def asession_views(
    conn: "psycopg.AsyncConnection",
    filt: RecordFilter | None = None,
    *,
    limit: int = settings.DEFAULT_LIMIT,
    offset: int = settings.DEFAULT_OFFSET,
) -> list[SessionView]:
    sql, params = queries.session_views_sql(filt or _EMPTY, limit=limit, offset=offset)
    return [SessionView.from_row(r) for r in await _rows_async(conn, sql, params)]
