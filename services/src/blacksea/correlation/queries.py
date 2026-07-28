"""queries.py — pure SQL builders over the ``records`` table.

Every function here is I/O-free: it returns ``(sql, params)`` and touches no
connection. That is what lets one query definition be executed by both the
async observer and the sync console without duplicating the SQL (reader.py wraps
these with a two-line executor per flavor).

``where_clause`` is the single primitive every view shares — add a new filter
dimension once here and every view (list, count, hit-rate, caution, sessions)
picks it up. All values are bound as parameters (``%(name)s``); nothing is
string-interpolated except a validated ORDER direction.
"""

from __future__ import annotations

from typing import Any

from blacksea.config import settings

from .models import CAUTION_RANK, RecordCursor, RecordFilter

_TABLE = settings.RECORDS_TABLE

# max(...) over this CASE gives a session's strongest caution level as an int;
# SessionView.from_row maps it back to a label. Kept in sync with models.CAUTION_RANK.
_CAUTION_CASE = (
    "max(CASE coalesce(signals->>'caution_level','none') "
    f"WHEN 'high' THEN {CAUTION_RANK['high']} "
    f"WHEN 'medium' THEN {CAUTION_RANK['medium']} "
    f"WHEN 'low' THEN {CAUTION_RANK['low']} "
    f"ELSE {CAUTION_RANK['none']} END)"
)


def where_clause(filt: RecordFilter) -> tuple[str, dict[str, Any]]:
    """Build the ``WHERE`` fragment (or ``""``) + bound params for a filter."""
    clauses: list[str] = []
    params: dict[str, Any] = {}

    def eq(col: str, value: Any) -> None:
        if value is not None:
            clauses.append(f"{col} = %({col})s")
            params[col] = value

    eq("bait_id", filt.bait_id)
    eq("instance_token", filt.instance_token)
    eq("campaign_id", filt.campaign_id)
    eq("session_id", filt.session_id)
    eq("event_type", filt.event_type)
    eq("source_type", filt.source_type)
    eq("channel", filt.channel)
    eq("sig_valid", filt.sig_valid)

    if filt.since_ms is not None:
        clauses.append("edge_recv_time >= %(since_ms)s")
        params["since_ms"] = filt.since_ms
    if filt.until_ms is not None:
        clauses.append("edge_recv_time < %(until_ms)s")
        params["until_ms"] = filt.until_ms

    where = ("WHERE " + " AND ".join(clauses)) if clauses else ""
    return where, params


def list_records_sql(
    filt: RecordFilter,
    *,
    limit: int = settings.DEFAULT_LIMIT,
    offset: int = settings.DEFAULT_OFFSET,
    order: str = settings.DEFAULT_ORDER,
) -> tuple[str, dict[str, Any]]:
    where, params = where_clause(filt)
    direction = "ASC" if str(order).lower() == "asc" else "DESC"
    params["limit"] = max(1, int(limit))
    params["offset"] = max(0, int(offset))
    sql = (
        f"SELECT * FROM {_TABLE} {where} "
        f"ORDER BY edge_recv_time {direction}, record_id {direction} "
        "LIMIT %(limit)s OFFSET %(offset)s"
    )
    return sql, params


def get_record_sql(record_id: str) -> tuple[str, dict[str, Any]]:
    return f"SELECT * FROM {_TABLE} WHERE record_id = %(record_id)s", {"record_id": record_id}


def records_after_sql(
    cursor: RecordCursor,
    filt: RecordFilter | None = None,
    *,
    limit: int = settings.DEFAULT_LIMIT,
) -> tuple[str, dict[str, Any]]:
    """Keyset tail read: every record strictly after ``cursor`` in
    ``(edge_recv_time, record_id)`` order, ascending, capped at ``limit``.

    Uses a row-value comparison ``(edge_recv_time, record_id) > (cursor_time,
    cursor_id)`` — the correct, gap-free, duplicate-free way to page a stream on a
    non-unique timestamp (both columns are ``NOT NULL``, so no NULL-comparison
    surprises). Composes with the shared :func:`where_clause` so a caller can also
    scope the tail (e.g. one bait) though otel_export tails everything.
    """
    where, params = where_clause(filt or RecordFilter())
    keyset = "(edge_recv_time, record_id) > (%(cursor_time)s, %(cursor_id)s)"
    params["cursor_time"] = int(cursor.edge_recv_time)
    params["cursor_id"] = str(cursor.record_id)
    params["limit"] = max(1, int(limit))
    predicate = f"{where} AND {keyset}" if where else f"WHERE {keyset}"
    sql = (
        f"SELECT * FROM {_TABLE} {predicate} "
        "ORDER BY edge_recv_time ASC, record_id ASC "
        "LIMIT %(limit)s"
    )
    return sql, params


def count_records_sql(filt: RecordFilter) -> tuple[str, dict[str, Any]]:
    where, params = where_clause(filt)
    return f"SELECT count(*) AS n FROM {_TABLE} {where}", params


def hit_rate_sql(filt: RecordFilter, *, bucket_ms: int) -> tuple[str, dict[str, Any]]:
    """Bucketed hit count by ``edge_recv_time`` — the burn-detection input an
    attacker cannot suppress without actually reducing interaction rate (§6.8-b).
    Buckets are aligned to the epoch: ``floor(t / bucket_ms) * bucket_ms``.
    """
    where, params = where_clause(filt)
    params["bucket_ms"] = max(1, int(bucket_ms))
    sql = (
        f"SELECT (edge_recv_time / %(bucket_ms)s) * %(bucket_ms)s AS bucket_start, "
        f"count(*) AS n FROM {_TABLE} {where} "
        "GROUP BY bucket_start ORDER BY bucket_start ASC"
    )
    return sql, params


def caution_distribution_sql(filt: RecordFilter) -> tuple[str, dict[str, Any]]:
    where, params = where_clause(filt)
    sql = (
        "SELECT coalesce(signals->>'caution_level','none') AS caution_level, "
        f"count(*) AS n FROM {_TABLE} {where} "
        "GROUP BY caution_level ORDER BY n DESC, caution_level ASC"
    )
    return sql, params


def session_views_sql(
    filt: RecordFilter,
    *,
    limit: int = settings.DEFAULT_LIMIT,
    offset: int = settings.DEFAULT_OFFSET,
) -> tuple[str, dict[str, Any]]:
    """Group records into approximate sessions by ``(instance_token, session_id)``.

    No idle-gap / state machine — see :class:`~blacksea.correlation.models.SessionView`.
    ``bait_id``/``campaign_id``/``deploy_class`` are constant within a real
    session; ``min()`` picks the single value without needing them in GROUP BY.
    """
    where, params = where_clause(filt)
    params["limit"] = max(1, int(limit))
    params["offset"] = max(0, int(offset))
    sql = (
        "SELECT instance_token, session_id, "
        "min(bait_id) AS bait_id, min(campaign_id) AS campaign_id, "
        "min(deploy_class) AS deploy_class, "
        "count(*) AS event_count, "
        "min(edge_recv_time) AS first_event_at, max(edge_recv_time) AS last_event_at, "
        "array_agg(DISTINCT event_type) AS event_types, "
        "array_agg(DISTINCT source_ip) AS source_ips, "
        "array_agg(DISTINCT source_type) AS source_types, "
        "min(seq_no) AS seq_min, max(seq_no) AS seq_max, "
        f"{_CAUTION_CASE} AS caution_rank, "
        "bool_and(sig_valid) AS sig_valid_all, "
        "bool_or(orphan) AS orphan_any, "
        "bool_or(test) AS test "
        f"FROM {_TABLE} {where} "
        "GROUP BY instance_token, session_id "
        "ORDER BY last_event_at DESC "
        "LIMIT %(limit)s OFFSET %(offset)s"
    )
    return sql, params
