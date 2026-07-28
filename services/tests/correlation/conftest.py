"""Correlation test fixtures.

Pure query-builder tests (``test_queries.py``) need no database. The reader
integration tests (``test_reader.py``) connect to Postgres and skip cleanly when
none is reachable — same convention as the brain suite. The ``records`` table is
created from the brain's own ``schema.sql`` (located via the installed module, so
there is no duplicated DDL), and every seeded row is namespaced by a random
``instance_token`` and deleted on teardown so tests never see each other's data.
"""

from __future__ import annotations

import os
from pathlib import Path

import psycopg
import pytest
from psycopg.types.json import Jsonb

PG_DSN = os.environ.get("POSTGRES_DSN")


def _records_schema_sql() -> str:
    # The records table is the brain's; reuse its DDL via the installed module
    # path rather than copying it here (the brain package is installed).
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
    """A unique 16-char-hex instance_token to namespace one test's rows."""
    return os.urandom(8).hex()


@pytest.fixture
def seed(conn, itoken: str):
    """Insert a records row, filling §3.1 defaults. Returns the record_id.

    Override any column via kwargs. Rows are deleted (by instance_token) on
    teardown so the test DB is left as found.
    """
    _JSON_COLS = ("signals", "details")

    def _insert(**over) -> str:
        row: dict = {
            "bait_id": "test_bait",
            "bait_version": "1",
            "instance_token": itoken,
            "campaign_id": "test_campaign",
            "assurance_tier": 1,
            "deploy_class": "portable_artifact",
            "session_id": "aa" * 8,
            "seq_no": 0,
            "event_type": "tripwire_fire",
            "edge_recv_time": 1_000,
            "sensor_time": 1_000,
            "source_ip": "10.0.0.1",
            "source_ja3": None,
            "source_type": "client",
            "sig_valid": True,
            "channel": "https",
            "edge_id": "edge-test",
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
            f"INSERT INTO records ({', '.join(cols)}) VALUES ({placeholders}) "
            "ON CONFLICT DO NOTHING",
            params,
        )
        return row["record_id"]

    try:
        yield _insert
    finally:
        conn.execute("DELETE FROM records WHERE instance_token = %s", (itoken,))
