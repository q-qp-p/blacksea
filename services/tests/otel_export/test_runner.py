"""Runner tests — the poll → map → emit → advance loop against a Postgres-backed
``records`` fixture and an in-memory OTLP sink. Skips cleanly with no Postgres.

These prove the loop mechanics the golden mapping tests can't: the keyset cursor
advances with no gap and no re-emit, a "from now" seed skips history, a burst larger
than one page drains fully, and the whole thing renders through the real SDK emit
path into a sink (so a wire-shape regression surfaces here, not in production).
"""

from __future__ import annotations

from blacksea.correlation import RecordCursor, RecordFilter

from blacksea.otel_export import OtelRunner


def _finished(sink) -> list:
    """Flatten the sink's ReadableLogRecords to the inner LogRecord objects."""
    return [rl.log_record for rl in sink.get_finished_logs()]


def _runner(emitter, itoken, *, start_ms=0, limit=500, emit_details=True):
    # Scope the tail to this test's own instance_token so the runner doesn't pick up
    # rows other tests / the dev stack left in the shared records table. Production
    # passes no filter (tails everything).
    return OtelRunner(
        dsn="unused-in-poll_once",
        emitter=emitter,
        start_cursor=RecordCursor(start_ms, ""),
        emit_details=emit_details,
        batch_limit=limit,
        filt=RecordFilter(instance_token=itoken),
    )


def test_poll_once_emits_and_advances(conn, seed, itoken, emitter_and_sink):
    emitter, sink = emitter_and_sink
    seed(session_id="a" * 16, seq_no=0, edge_recv_time=1_000)
    seed(session_id="a" * 16, seq_no=1, edge_recv_time=2_000)
    seed(session_id="b" * 16, seq_no=0, edge_recv_time=3_000)

    r = _runner(emitter, itoken)
    n = r.poll_once(conn)
    emitter.force_flush()

    assert n == 3
    recs = _finished(sink)
    assert len(recs) == 3
    # ascending by edge_recv_time; primary timestamp is edge_recv_time in ns
    times = [lr.timestamp for lr in recs]
    assert times == sorted(times)
    assert times[0] == 1_000 * 1_000_000
    # cursor advanced past the last (highest) record
    assert r.cursor.edge_recv_time == 3_000


def test_tail_is_idempotent_no_reemit(conn, seed, itoken, emitter_and_sink):
    emitter, sink = emitter_and_sink
    seed(session_id="a" * 16, seq_no=0, edge_recv_time=1_000)
    seed(session_id="a" * 16, seq_no=1, edge_recv_time=2_000)

    r = _runner(emitter, itoken)
    assert r.poll_once(conn) == 2
    # nothing new since the cursor advanced → a second poll emits nothing
    assert r.poll_once(conn) == 0
    emitter.force_flush()
    assert len(_finished(sink)) == 2


def test_same_millisecond_hits_not_skipped(conn, seed, itoken, emitter_and_sink):
    # The exact case a plain since_ms filter mishandles: two hits in one ms.
    emitter, sink = emitter_and_sink
    seed(session_id="a" * 16, seq_no=0, edge_recv_time=5_000)
    seed(session_id="a" * 16, seq_no=1, edge_recv_time=5_000)

    r = _runner(emitter, itoken)
    assert r.poll_once(conn) == 2
    assert r.poll_once(conn) == 0  # both consumed, none re-read
    emitter.force_flush()
    assert len(_finished(sink)) == 2


def test_from_now_seed_skips_history(conn, seed, itoken, emitter_and_sink):
    emitter, sink = emitter_and_sink
    seed(session_id="a" * 16, seq_no=0, edge_recv_time=1_000)  # "old"
    seed(session_id="a" * 16, seq_no=1, edge_recv_time=9_000)  # "new"

    r = _runner(emitter, itoken, start_ms=5_000)  # seeded from a point in the middle
    assert r.poll_once(conn) == 1
    emitter.force_flush()
    recs = _finished(sink)
    assert len(recs) == 1
    assert recs[0].timestamp == 9_000 * 1_000_000


def test_drain_pages_beyond_batch_limit(conn, seed, itoken, emitter_and_sink):
    emitter, sink = emitter_and_sink
    for i in range(5):
        seed(session_id="a" * 16, seq_no=i, edge_recv_time=1_000 + i)

    r = _runner(emitter, itoken, limit=2)  # 5 records, 2 per page → 3 pages
    total = r.drain(conn)
    emitter.force_flush()
    assert total == 5
    assert len(_finished(sink)) == 5


def test_details_gate_through_runner(conn, seed, itoken, emitter_and_sink):
    emitter, sink = emitter_and_sink
    seed(session_id="a" * 16, seq_no=0, edge_recv_time=1_000, details={"hostname": "victim"})

    r = _runner(emitter, itoken, emit_details=False)
    r.poll_once(conn)
    emitter.force_flush()
    attrs = dict(_finished(sink)[0].attributes)
    assert not any(k.startswith("blacksea.details.") for k in attrs)


def test_wire_shape_end_to_end(conn, seed, itoken, emitter_and_sink):
    emitter, sink = emitter_and_sink
    seed(
        session_id="a" * 16,
        seq_no=0,
        edge_recv_time=1_700_000_000_000,
        bait_id="hostname-beacon",
        source_ip="203.0.113.77",
        signals={"caution_level": "low"},
        details={"hostname": "victim-box"},
    )
    r = _runner(emitter, itoken)
    r.poll_once(conn)
    emitter.force_flush()

    rl = _finished(sink)[0]
    attrs = dict(rl.attributes)
    assert rl.body == "payload_exec_collect on hostname-beacon from 203.0.113.77"
    assert rl.severity_text == "WARN"
    assert attrs["client.address"] == "203.0.113.77"
    assert attrs["blacksea.details.hostname"] == "victim-box"
    assert attrs["blacksea.sig_valid"] is True


def test_resource_identity_attached(conn, seed, itoken, emitter_and_sink):
    emitter, sink = emitter_and_sink
    seed(session_id="a" * 16, seq_no=0, edge_recv_time=1_000)
    _runner(emitter, itoken).poll_once(conn)
    emitter.force_flush()

    res = sink.get_finished_logs()[0].resource
    assert res.attributes["service.name"] == "blacksea-brain"
    assert res.attributes["service.namespace"] == "blacksea"
    assert res.attributes["blacksea.deployment_id"] == "dep-test"
