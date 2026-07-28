"""Phase 3 — the brain loads baits from the control-plane catalog + frozen material
(O2/O9/O10/O11), not from a git baits dir. Verifies lazy load, hash verification, and
live design status. Skips cleanly when no Postgres is reachable (see conftest)."""

from __future__ import annotations

import asyncio

import psycopg

from blacksea.brain import pool
from blacksea.control_plane import listeners
from blacksea.control_plane.registry import DesignRecord, Registry

_LISTENER = (
    "class CatListener:\n"
    "    def on_register(self):\n"
    "        pass\n"
    "    def interpret(self, envelope, body):\n"
    "        return None\n"
)
_SCHEMA = "cp_braintest"


def _seed(pg_dsn, tmp_path, *, bait_id="catbait", version="1.0.0", status="deployed"):
    """Fresh throwaway catalog + a design row + a frozen listener. Returns
    (schema, artifacts_root, listener_hash)."""
    with psycopg.connect(pg_dsn, autocommit=True) as conn:
        conn.execute(f"DROP SCHEMA IF EXISTS {_SCHEMA} CASCADE")
    reg = Registry(pg_dsn, registry_root=str(tmp_path / "registry"), schema=_SCHEMA)
    reg.ensure_schema()
    bait_dir = tmp_path / "bait"
    bait_dir.mkdir(exist_ok=True)
    (bait_dir / "listener.py").write_text(_LISTENER)
    manifest = {
        "bait_id": bait_id, "version": version, "deploy_class": "portable_artifact",
        "test": True, "listener_class": "listener.CatListener",
    }
    artifacts = str(tmp_path / "artifacts")
    h = listeners.freeze_listener(
        str(bait_dir), manifest, artifacts_root=artifacts, bait_id=bait_id, version=version)
    reg.put_design(DesignRecord(
        bait_id=bait_id, manifest=manifest, bait_dir=str(bait_dir),
        status=status, listener_hash=h))
    reg.close()
    return _SCHEMA, artifacts, h


def _drop(pg_dsn):
    with psycopg.connect(pg_dsn, autocommit=True) as conn:
        conn.execute(f"DROP SCHEMA IF EXISTS {_SCHEMA} CASCADE")


def test_ensure_bait_loads_frozen_listener(pg_dsn, tmp_path):
    pool._registry.clear()
    schema, artifacts, _ = _seed(pg_dsn, tmp_path)

    async def go():
        cat = await psycopg.AsyncConnection.connect(pg_dsn, autocommit=True)
        try:
            entry = await pool._ensure_bait(cat, artifacts, schema, "catbait")
            assert entry is not None
            listener, version, deploy_class, is_test = entry
            assert version == "1.0.0"
            assert deploy_class == "portable_artifact"
            assert is_test is True
            assert listener.__class__.__name__ == "CatListener"
            # Cached on the second call.
            assert await pool._ensure_bait(cat, artifacts, schema, "catbait") is entry
        finally:
            await cat.close()

    try:
        asyncio.run(go())
    finally:
        pool._registry.clear()
        _drop(pg_dsn)


def test_unknown_bait_returns_none(pg_dsn, tmp_path):
    pool._registry.clear()
    schema, artifacts, _ = _seed(pg_dsn, tmp_path)

    async def go():
        cat = await psycopg.AsyncConnection.connect(pg_dsn, autocommit=True)
        try:
            assert await pool._ensure_bait(cat, artifacts, schema, "ghost") is None
        finally:
            await cat.close()

    try:
        asyncio.run(go())
    finally:
        pool._registry.clear()
        _drop(pg_dsn)


def test_hash_mismatch_refuses_to_load(pg_dsn, tmp_path):
    """O11 #3: tampered frozen bytes → the brain refuses to import (→ dead-letter)."""
    pool._registry.clear()
    schema, artifacts, _ = _seed(pg_dsn, tmp_path)
    # Tamper the frozen listener after the catalog hash was pinned.
    frozen = listeners.frozen_listener_dir(artifacts, "catbait", "1.0.0")
    with open(f"{frozen}/listener.py", "a") as f:
        f.write("\n# tampered post-freeze\n")

    async def go():
        cat = await psycopg.AsyncConnection.connect(pg_dsn, autocommit=True)
        try:
            assert await pool._ensure_bait(cat, artifacts, schema, "catbait") is None
        finally:
            await cat.close()

    try:
        asyncio.run(go())
    finally:
        pool._registry.clear()
        _drop(pg_dsn)


def test_design_status_is_live(pg_dsn, tmp_path):
    """O2: the hardcoded 'deployed' is gone — design status reads live from the catalog,
    so a burn is reflected without restarting the brain."""
    pool._registry.clear()
    schema, artifacts, _ = _seed(pg_dsn, tmp_path, status="deployed")

    async def go():
        cat = await psycopg.AsyncConnection.connect(pg_dsn, autocommit=True)
        try:
            assert await pool._design_status(cat, schema, "catbait") == "deployed"
            # Burn the design out-of-band; the next read reflects it (no cache).
            with psycopg.connect(pg_dsn, autocommit=True) as c:
                c.execute(f"UPDATE {schema}.design SET status='burned' WHERE bait_id='catbait'")
            assert await pool._design_status(cat, schema, "catbait") == "burned"
            assert await pool._design_status(cat, schema, "ghost") == "unknown"
        finally:
            await cat.close()

    try:
        asyncio.run(go())
    finally:
        pool._registry.clear()
        _drop(pg_dsn)


def test_load_baits_preloads_all_designs(pg_dsn, tmp_path):
    pool._registry.clear()
    schema, artifacts, _ = _seed(pg_dsn, tmp_path)

    async def go():
        cat = await psycopg.AsyncConnection.connect(pg_dsn, autocommit=True)
        try:
            await pool.load_baits(cat, artifacts, schema)
            assert "catbait" in pool._registry
        finally:
            await cat.close()

    try:
        asyncio.run(go())
    finally:
        pool._registry.clear()
        _drop(pg_dsn)
