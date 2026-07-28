"""Phase 0 — catalog schema DDL is idempotent, and the O6 grant matrix isolates the
brain: brain_role reads design/instance but cannot write anywhere in the schema. Proven
via SET ROLE (blacksea is a superuser in dev, so the split is provable rather than
enforced by the shared dev DSN — see schema.py)."""

from __future__ import annotations

import psycopg
import pytest

from blacksea.control_plane import schema


def _denied(cur, stmt: str) -> bool:
    cur.execute("SET ROLE brain_role")
    try:
        cur.execute(stmt)
        return False
    except psycopg.errors.InsufficientPrivilege:
        return True
    finally:
        cur.execute("RESET ROLE")


def test_catalog_ddl_is_idempotent(pg_dsn, cp_schema):
    with psycopg.connect(pg_dsn, autocommit=True) as conn:
        schema.ensure_catalog(conn, cp_schema)
        schema.ensure_catalog(conn, cp_schema)  # second run must not error
        # design + instance tables exist after the DDL.
        for tbl in ("design", "instance"):
            conn.execute(f"SELECT count(*) FROM {cp_schema}.{tbl}")


def test_grants_isolate_the_brain(pg_dsn, cp_schema):
    with psycopg.connect(pg_dsn, autocommit=True) as conn:
        schema.ensure_catalog(conn, cp_schema)
        schema.ensure_roles_and_grants(conn, cp_schema)
        cur = conn.cursor()

        # brain_role CAN read the control tables (live lifecycle).
        cur.execute("SET ROLE brain_role")
        cur.execute(f"SELECT count(*) FROM {cp_schema}.design")
        cur.execute(f"SELECT count(*) FROM {cp_schema}.instance")
        cur.execute("RESET ROLE")

        # …but cannot write them anywhere in the schema (O6).
        assert _denied(cur, f"INSERT INTO {cp_schema}.design(bait_id,version,manifest) "
                            f"VALUES ('x','1','{{}}'::jsonb)")
        assert _denied(cur, f"UPDATE {cp_schema}.instance SET status='active'")


def test_invalid_schema_name_rejected():
    with pytest.raises(ValueError):
        schema.validate_schema("bad-name; DROP TABLE x")
