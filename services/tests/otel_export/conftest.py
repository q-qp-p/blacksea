"""otel_export test fixtures.

Two flavours, mirroring the correlation suite's convention:

- ``test_mapping.py`` is pure (no DB, no SDK network): it builds a ``RecordDetail``
  in memory via the ``make_detail`` helper and asserts on the mapped ``MappedLog``.
- ``test_runner.py`` connects to Postgres (skips cleanly when none is reachable),
  seeds the brain's own ``records`` table via the shared ``seed`` fixture, and drives
  the runner against an **in-memory OTLP sink** (``emitter_and_sink``) so no live
  Collector is needed.

The ``records`` table is created from the brain's ``schema.sql`` (via the installed
module path — no duplicated DDL), and rows are namespaced by a random
``instance_token`` and deleted on teardown so tests never see each other's data.
"""

from __future__ import annotations

import os
import warnings
from pathlib import Path

import psycopg
import pytest
from psycopg.types.json import Jsonb

from blacksea.correlation import RecordDetail

PG_DSN = os.environ.get("POSTGRES_DSN")

# The logs signal is "not stable yet" upstream; the in-memory exporter name is mid-
# rename. Silence that one deprecation so the suite output stays clean.
warnings.filterwarnings("ignore", message=".*InMemoryLogRecordExporter.*")


# ── in-memory RecordDetail (mapping tests) ────────────────────────────────────

_DETAIL_DEFAULTS: dict = {
    "record_id": "tok0-sid0-0000",
    "bait_id": "hostname-beacon",
    "instance_token": "0011223344556677",
    "campaign_id": "C-test",
    "session_id": "aabbccddeeff0011",
    "seq_no": 0,
    "event_type": "payload_exec_collect",
    "source_ip": "203.0.113.77",
    "source_type": "client",
    "sig_valid": True,
    "orphan": False,
    "channel": "https",
    "edge_recv_time": 1_700_000_000_000,
    "bait_version": "1",
    "assurance_tier": 1,
    "deploy_class": "portable_artifact",
    "edge_id": "edge-1",
    "instance_status": "active",
    "design_status": "active",
    "source_ja3": None,
    "sensor_time": 1_700_000_000_500,
    "signals": None,
    "details": None,
    "details_truncated": False,
    "ingested_at": None,
    "test": False,
}


@pytest.fixture
def make_detail():
    """Build a full ``RecordDetail`` from the §3.1 defaults; override any field via
    kwargs."""

    def _make(**over) -> RecordDetail:
        row = dict(_DETAIL_DEFAULTS)
        row.update(over)
        return RecordDetail.from_row(row)

    return _make


# ── in-memory OTLP sink (runner tests) ────────────────────────────────────────


def _in_memory_exporter():
    try:
        from opentelemetry.sdk._logs.export import InMemoryLogRecordExporter as Exp
    except ImportError:  # older SDK spelling
        from opentelemetry.sdk._logs.export import InMemoryLogExporter as Exp
    return Exp()


@pytest.fixture
def emitter_and_sink():
    """An ``OtelEmitter`` wired to a synchronous in-memory sink. Returns
    ``(emitter, exporter)``; ``exporter.get_finished_logs()`` yields exactly what
    would go on the wire (SimpleLogRecordProcessor → no batch delay)."""
    from opentelemetry.sdk._logs.export import SimpleLogRecordProcessor

    from blacksea.otel_export import OtelEmitter, resource_attributes

    sink = _in_memory_exporter()
    emitter = OtelEmitter(
        resource_attrs=resource_attributes("dep-test"),
        processor=SimpleLogRecordProcessor(sink),
    )
    try:
        yield emitter, sink
    finally:
        emitter.shutdown()


# ── Postgres records table (runner tests) — same convention as correlation ────


def _records_schema_sql() -> str:
    import blacksea.brain.storage as bs

    return (Path(bs.__file__).parent / "schema.sql").read_text()


def _pg_reachable(dsn: str) -> bool:
    try:
        conn = psycopg.connect(dsn, connect_timeout=2)
        conn.close()
        return True
    except Exception:
        return False


@pytest.fixture(scope="session")
def pg_dsn() -> str:
    if not PG_DSN:
        pytest.skip("POSTGRES_DSN not set — run `make init && blacksea up --infra-only`")
    if not _pg_reachable(PG_DSN):
        pytest.skip(f"no Postgres reachable at {PG_DSN!r} — run `blacksea up --infra-only`")
    return PG_DSN


@pytest.fixture
def conn(pg_dsn: str):
    c = psycopg.connect(pg_dsn, autocommit=True)
    c.execute(_records_schema_sql())  # idempotent CREATE TABLE/INDEX IF NOT EXISTS
    try:
        yield c
    finally:
        c.close()


@pytest.fixture
def itoken() -> str:
    return os.urandom(8).hex()


@pytest.fixture
def seed(conn, itoken: str):
    """Insert a records row, filling §3.1 defaults; returns the record_id. Rows are
    deleted (by instance_token) on teardown."""
    _JSON_COLS = ("signals", "details")

    def _insert(**over) -> str:
        row: dict = {
            "bait_id": "hostname-beacon",
            "bait_version": "1",
            "instance_token": itoken,
            "campaign_id": "C-test",
            "assurance_tier": 1,
            "deploy_class": "portable_artifact",
            "session_id": "aa" * 8,
            "seq_no": 0,
            "event_type": "payload_exec_collect",
            "edge_recv_time": 1_000,
            "sensor_time": 1_000,
            "source_ip": "203.0.113.77",
            "source_ja3": None,
            "source_type": "client",
            "sig_valid": True,
            "channel": "https",
            "edge_id": "edge-1",
            "orphan": False,
            "instance_status": "active",
            "design_status": "active",
            "test": False,
            "signals": None,
            "details": None,
            "details_truncated": False,
        }
        row.update(over)
        if "record_id" not in row:
            row["record_id"] = f"{row['instance_token']}-{row['session_id']}-{row['seq_no']:04x}"

        cols = list(row)
        params = dict(row)
        for jc in _JSON_COLS:
            if params[jc] is not None:
                params[jc] = Jsonb(params[jc])
        placeholders = ", ".join(f"%({c})s" for c in cols)
        conn.execute(
            f"INSERT INTO records ({', '.join(cols)}) VALUES ({placeholders}) ON CONFLICT DO NOTHING",
            params,
        )
        return row["record_id"]

    try:
        yield _insert
    finally:
        conn.execute("DELETE FROM records WHERE instance_token = %s", (itoken,))
