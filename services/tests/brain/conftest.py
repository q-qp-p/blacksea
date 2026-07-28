"""Brain test fixtures.

The async tests drive their own event loop via ``asyncio.run`` (no
pytest-asyncio dependency — see Makefile install list). Postgres-backed tests
skip cleanly when no database is reachable, so ``make test`` runs
unit-only on a machine without infra and full when ``blacksea up --infra-only`` is live.
"""

from __future__ import annotations

import asyncio
import os

import psycopg
import pytest

# No hardcoded default — credentials are never baked in. `make test` supplies POSTGRES_DSN
# (assembled from secrets/env); without it the DB-backed tests skip cleanly.
PG_DSN = os.environ.get("POSTGRES_DSN")


def _pg_reachable(dsn: str) -> bool:
    async def _probe() -> bool:
        try:
            conn = await psycopg.AsyncConnection.connect(dsn, connect_timeout=2)
            await conn.close()
            return True
        except Exception:
            return False

    return asyncio.run(_probe())


@pytest.fixture(scope="session")
def pg_dsn() -> str:
    """DSN of a reachable Postgres, or skip the test if none is configured/up."""
    if not PG_DSN:
        pytest.skip("POSTGRES_DSN not set — run `make init && blacksea up --infra-only`, then `make test`")
    if not _pg_reachable(PG_DSN):
        pytest.skip(f"no Postgres reachable at {PG_DSN!r} — run `blacksea up --infra-only`")
    return PG_DSN
