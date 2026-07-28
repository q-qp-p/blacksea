"""Reader integration tests — Postgres-backed, skip cleanly when no DB is up."""

from __future__ import annotations

import asyncio

import psycopg

from blacksea.correlation import (
    RecordCursor,
    RecordFilter,
    caution_distribution,
    count_records,
    get_record,
    hit_rate,
    list_records,
    records_after,
    session_views,
)
from blacksea.correlation.reader import alist_records, arecords_after, asession_views

_SID_A = "aa" * 8
_SID_B = "bb" * 8


def test_list_and_count(conn, seed, itoken):
    seed(session_id=_SID_A, seq_no=0, edge_recv_time=1_000)
    seed(session_id=_SID_B, seq_no=0, edge_recv_time=2_000, event_type="signal_only")
    f = RecordFilter(instance_token=itoken)

    assert count_records(conn, f) == 2
    rows = list_records(conn, f)
    assert len(rows) == 2
    # default order is edge_recv_time DESC → newest first
    assert rows[0].edge_recv_time == 2_000
    assert rows[1].edge_recv_time == 1_000

    asc = list_records(conn, f, order="asc")
    assert asc[0].edge_recv_time == 1_000


def test_count_respects_filter(conn, seed, itoken):
    seed(session_id=_SID_A, seq_no=0, sig_valid=True)
    seed(session_id=_SID_A, seq_no=1, sig_valid=False)
    assert count_records(conn, RecordFilter(instance_token=itoken)) == 2
    assert count_records(conn, RecordFilter(instance_token=itoken, sig_valid=False)) == 1


def test_get_record(conn, seed, itoken):
    rid = seed(session_id=_SID_A, seq_no=0, signals={"caution_level": "low"})
    detail = get_record(conn, rid)
    assert detail is not None
    assert detail.record_id == rid
    assert detail.instance_token == itoken
    assert detail.signals == {"caution_level": "low"}
    assert detail.test is False
    assert get_record(conn, "does-not-exist") is None


def test_test_flag_surfaces_on_summary_detail_and_session(conn, seed, itoken):
    rid = seed(session_id=_SID_A, seq_no=0, test=True)
    assert get_record(conn, rid).test is True

    rows = list_records(conn, RecordFilter(instance_token=itoken))
    assert rows[0].test is True

    views = session_views(conn, RecordFilter(instance_token=itoken))
    assert views[0].test is True


def test_session_views_grouping(conn, seed, itoken):
    # Session A: 3 events (one high-caution, one invalid sig, two distinct IPs)
    seed(session_id=_SID_A, seq_no=0, edge_recv_time=1_000, event_type="honeypot_access",
         source_ip="10.0.0.1")
    seed(session_id=_SID_A, seq_no=1, edge_recv_time=1_500, event_type="honeypot_command",
         source_ip="10.0.0.1", signals={"caution_level": "high"})
    seed(session_id=_SID_A, seq_no=2, edge_recv_time=2_000, event_type="honeypot_command",
         source_ip="10.0.0.2", sig_valid=False)
    # Session B: single later event
    seed(session_id=_SID_B, seq_no=0, edge_recv_time=3_000, event_type="signal_only")

    views = session_views(conn, RecordFilter(instance_token=itoken))
    assert len(views) == 2
    # ordered by last_event_at DESC → B (3000) before A (2000)
    assert views[0].session_id == _SID_B

    a = next(v for v in views if v.session_id == _SID_A)
    assert a.session_record_id == f"{itoken}-{_SID_A}"
    assert a.event_count == 3
    assert a.first_event_at == 1_000 and a.last_event_at == 2_000
    assert a.caution_level == "high"          # max over events
    assert a.sig_valid_all is False           # AND over events
    assert a.seq_min == 0 and a.seq_max == 2
    assert set(a.source_ips) == {"10.0.0.1", "10.0.0.2"}
    assert set(a.event_types) == {"honeypot_access", "honeypot_command"}


def test_hit_rate_buckets(conn, seed, itoken):
    seed(session_id=_SID_A, seq_no=0, edge_recv_time=1_000)
    seed(session_id=_SID_A, seq_no=1, edge_recv_time=1_500)
    seed(session_id=_SID_B, seq_no=0, edge_recv_time=10_000)
    buckets = {b.bucket_start_ms: b.count
               for b in hit_rate(conn, RecordFilter(instance_token=itoken), bucket_seconds=1)}
    assert buckets == {1_000: 2, 10_000: 1}


def test_caution_distribution(conn, seed, itoken):
    seed(session_id=_SID_A, seq_no=0, signals={"caution_level": "high"})
    seed(session_id=_SID_A, seq_no=1, signals={"caution_level": "high"})
    seed(session_id=_SID_A, seq_no=2)  # no signals → "none"
    dist = {c.caution_level: c.count
            for c in caution_distribution(conn, RecordFilter(instance_token=itoken))}
    assert dist == {"high": 2, "none": 1}


def test_records_after_keyset_tail(conn, seed, itoken):
    # Two hits share a millisecond — the exact case a plain since_ms filter would
    # skip or double-read. record_id breaks the tie deterministically.
    r1 = seed(session_id=_SID_A, seq_no=0, edge_recv_time=1_000)
    r2 = seed(session_id=_SID_A, seq_no=1, edge_recv_time=1_000)
    r3 = seed(session_id=_SID_B, seq_no=0, edge_recv_time=2_000)
    f = RecordFilter(instance_token=itoken)

    # From the very beginning: all three, ascending by (edge_recv_time, record_id).
    tail = records_after(conn, RecordCursor(0, ""), f)
    got = [d.record_id for d in tail]
    assert got == sorted([r1, r2, r3], key=lambda rid: (
        1_000 if rid in (r1, r2) else 2_000, rid))
    assert [d.edge_recv_time for d in tail] == [1_000, 1_000, 2_000]

    # Resume strictly after the first row: never re-reads r-first even at the same ms.
    first = tail[0]
    resumed = records_after(conn, RecordCursor(first.edge_recv_time, first.record_id), f)
    assert first.record_id not in [d.record_id for d in resumed]
    assert len(resumed) == 2

    # Cursor past everything → empty (the steady-state "caught up" poll).
    assert records_after(conn, RecordCursor(2_000, r3), f) == []


def test_records_after_honours_limit(conn, seed, itoken):
    for i in range(5):
        seed(session_id=_SID_A, seq_no=i, edge_recv_time=1_000 + i)
    f = RecordFilter(instance_token=itoken)
    page = records_after(conn, RecordCursor(0, ""), f, limit=2)
    assert len(page) == 2
    # paging forward from the last of the page yields the rest
    nxt = records_after(conn, RecordCursor(page[-1].edge_recv_time, page[-1].record_id), f, limit=2)
    assert len(nxt) == 2
    assert {d.record_id for d in page}.isdisjoint({d.record_id for d in nxt})


def test_records_after_returns_full_detail(conn, seed, itoken):
    # Observer parity: the tail returns the same RecordDetail the observer shows,
    # details + signals + sensor_time included.
    seed(session_id=_SID_A, seq_no=0, edge_recv_time=1_000,
         signals={"caution_level": "low"}, details={"hostname": "victim-box"})
    d = records_after(conn, RecordCursor(0, ""), RecordFilter(instance_token=itoken))[0]
    assert d.details == {"hostname": "victim-box"}
    assert d.signals == {"caution_level": "low"}
    assert d.sensor_time == 1_000


def test_arecords_after_matches_sync(conn, seed, itoken, pg_dsn):
    seed(session_id=_SID_A, seq_no=0, edge_recv_time=1_000)
    seed(session_id=_SID_A, seq_no=1, edge_recv_time=2_000)
    f = RecordFilter(instance_token=itoken)
    sync = [d.record_id for d in records_after(conn, RecordCursor(0, ""), f)]

    async def _go():
        aconn = await psycopg.AsyncConnection.connect(pg_dsn)
        try:
            return [d.record_id for d in await arecords_after(aconn, RecordCursor(0, ""), f)]
        finally:
            await aconn.close()

    assert asyncio.run(_go()) == sync


def test_async_variants_match_sync(conn, seed, itoken, pg_dsn):
    seed(session_id=_SID_A, seq_no=0, edge_recv_time=1_000)
    seed(session_id=_SID_A, seq_no=1, edge_recv_time=2_000)

    async def _go():
        aconn = await psycopg.AsyncConnection.connect(pg_dsn)
        try:
            recs = await alist_records(aconn, RecordFilter(instance_token=itoken))
            sess = await asession_views(aconn, RecordFilter(instance_token=itoken))
            return recs, sess
        finally:
            await aconn.close()

    recs, sess = asyncio.run(_go())
    assert len(recs) == 2
    assert len(sess) == 1
    assert sess[0].event_count == 2
