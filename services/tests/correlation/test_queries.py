"""Pure SQL-builder tests — no database required (run in `make test`)."""

from __future__ import annotations

from blacksea.correlation import queries
from blacksea.correlation.models import RecordCursor, RecordFilter


def test_where_clause_empty():
    where, params = queries.where_clause(RecordFilter())
    assert where == ""
    assert params == {}


def test_where_clause_all_dimensions():
    f = RecordFilter(
        bait_id="b",
        instance_token="tok",
        campaign_id="c",
        session_id="s",
        event_type="signal_only",
        source_type="client",
        channel="https",
        sig_valid=False,
        since_ms=5,
        until_ms=10,
    )
    where, params = queries.where_clause(f)
    assert where.startswith("WHERE ")
    for col in ("bait_id", "instance_token", "campaign_id", "session_id",
                "event_type", "source_type", "channel", "sig_valid"):
        assert f"{col} = %({col})s" in where
    assert "edge_recv_time >= %(since_ms)s" in where
    assert "edge_recv_time < %(until_ms)s" in where
    assert params["sig_valid"] is False  # False must still bind (not dropped)
    assert params["since_ms"] == 5 and params["until_ms"] == 10


def test_list_records_sql_order_is_validated():
    # An unrecognised (or hostile) order string must collapse to DESC, never
    # be interpolated verbatim.
    sql, _ = queries.list_records_sql(RecordFilter(), order="; DROP TABLE records;--")
    assert "DROP" not in sql
    assert "ORDER BY edge_recv_time DESC" in sql

    sql_asc, _ = queries.list_records_sql(RecordFilter(), order="asc")
    assert "ORDER BY edge_recv_time ASC" in sql_asc


def test_list_records_sql_limit_offset_bound():
    sql, params = queries.list_records_sql(RecordFilter(bait_id="b"), limit=5, offset=10)
    assert params["limit"] == 5 and params["offset"] == 10
    assert params["bait_id"] == "b"
    assert "LIMIT %(limit)s OFFSET %(offset)s" in sql


def test_count_sql():
    sql, params = queries.count_records_sql(RecordFilter(campaign_id="c"))
    assert "count(*) AS n" in sql
    assert params == {"campaign_id": "c"}


def test_session_views_sql_groups():
    sql, params = queries.session_views_sql(RecordFilter(instance_token="x"), limit=7)
    assert "GROUP BY instance_token, session_id" in sql
    assert "instance_token = %(instance_token)s" in sql
    assert params["limit"] == 7
    # aggregates the SessionView mapper depends on
    for expr in ("event_count", "first_event_at", "last_event_at",
                 "event_types", "source_ips", "caution_rank", "sig_valid_all",
                 "orphan_any", "bool_or(test) AS test"):
        assert expr in sql


def test_hit_rate_sql_bucket_param():
    sql, params = queries.hit_rate_sql(RecordFilter(), bucket_ms=60_000)
    assert params["bucket_ms"] == 60_000
    assert "GROUP BY bucket_start" in sql


def test_caution_distribution_sql():
    sql, _ = queries.caution_distribution_sql(RecordFilter())
    assert "coalesce(signals->>'caution_level','none')" in sql
    assert "GROUP BY caution_level" in sql


def test_records_after_sql_keyset_and_order():
    sql, params = queries.records_after_sql(RecordCursor(1_000, "rid-7"), limit=50)
    # row-value keyset, ascending, bound as params (never interpolated)
    assert "(edge_recv_time, record_id) > (%(cursor_time)s, %(cursor_id)s)" in sql
    assert "ORDER BY edge_recv_time ASC, record_id ASC" in sql
    assert "LIMIT %(limit)s" in sql
    assert params["cursor_time"] == 1_000
    assert params["cursor_id"] == "rid-7"
    assert params["limit"] == 50


def test_records_after_sql_composes_with_filter():
    sql, params = queries.records_after_sql(
        RecordCursor(5, ""), RecordFilter(bait_id="b"), limit=10
    )
    # filter predicate AND the keyset both present
    assert "bait_id = %(bait_id)s" in sql
    assert "AND (edge_recv_time, record_id) >" in sql
    assert params["bait_id"] == "b"
    assert params["cursor_id"] == ""
