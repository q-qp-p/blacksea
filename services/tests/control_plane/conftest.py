"""Shared fixtures for the control_plane tests.

The happy-path bait is the ``hostname_probe`` reference/test bait fixture at
``test_fixtures/baits/hostname_probe/`` (a manifest that references its payload/
listener/staging-vessel catalog entries in ``lure_material/`` by a ``../``-relative
path — see ``docs/bait-authoring.md``). Validation tests copy the manifest into a tmp dir
and mutate it so each rule can be exercised against an otherwise-valid bait.

**Postgres-backed (D2).** The registry moved from flat files into the ``control_plane``
schema of the brain's Postgres. Every test that touches the registry runs against a
**unique throwaway schema** (``cp_schema``) created on first use and dropped on teardown,
so the shared dev database stays isolated between tests. These tests skip cleanly when no
database is reachable (mirroring the brain suite) — ``make test`` supplies ``POSTGRES_DSN``.
"""

from __future__ import annotations

import itertools
import os
import shutil
from pathlib import Path

import psycopg
import pytest
import yaml

# tests/control_plane/ → tests/ → services/ ; the reference bait fixture lives at
# test_fixtures/baits/, and the SDK vendor root (the src/ tree holding the blacksea/ namespace)
# at src/. The manifest's ../-relative catalog paths into lure_material/ are resolved from the
# fixture dir, unaffected by this refactor.
_SERVICES = Path(__file__).resolve().parents[2]
HOSTNAME_PROBE = _SERVICES / "test_fixtures" / "baits" / "hostname_probe"
SDK_ROOT = _SERVICES / "src"

_PG_DSN = os.environ.get("POSTGRES_DSN")
_schema_seq = itertools.count()


def _pg_reachable(dsn: str) -> bool:
    try:
        with psycopg.connect(dsn, connect_timeout=2):
            return True
    except Exception:
        return False


@pytest.fixture(scope="session")
def pg_dsn() -> str:
    """DSN of a reachable Postgres, or skip. The control plane now hard-depends on it (O7)."""
    if not _PG_DSN:
        pytest.skip("POSTGRES_DSN not set — run `make init && blacksea up --infra-only`, then `make test`")
    if not _pg_reachable(_PG_DSN):
        pytest.skip(f"no Postgres reachable at {_PG_DSN!r} — run `blacksea up --infra-only`")
    return _PG_DSN


@pytest.fixture
def cp_schema(pg_dsn) -> str:
    """A unique throwaway catalog schema, dropped (CASCADE) after the test — per-test
    isolation over the shared database."""
    schema = f"cp_test_{os.getpid()}_{next(_schema_seq)}"
    yield schema
    with psycopg.connect(pg_dsn, autocommit=True) as conn:
        conn.execute(f"DROP SCHEMA IF EXISTS {schema} CASCADE")


@pytest.fixture
def registry(pg_dsn, cp_schema, tmp_path):
    """A ready DB-backed :class:`Registry` bound to the throwaway ``cp_schema`` and a tmp
    filesystem root (parent of the material store ``artifacts/``)."""
    from blacksea.control_plane.registry import Registry
    reg = Registry(pg_dsn, registry_root=str(tmp_path / "registry"), schema=cp_schema)
    reg.ensure_schema()
    try:
        yield reg
    finally:
        reg.close()


@pytest.fixture
def sdk_root() -> str:
    return str(SDK_ROOT)


def _absolutize_catalog_ref(value: str, base: Path) -> str:
    """A manifest's payload_file/listener_class/staging_vessel may be a `../`-relative
    reference into lure_material/, resolved via plain path-join from wherever the
    manifest lives (see lure_material/README.md). That resolution breaks once the bait
    directory is copied into a pytest tmp_path, so rewrite it to an absolute path —
    still relative-portable in the committed manifest.yaml, absolute only in this
    fixture's throwaway copy."""
    if not value.startswith("../"):
        return value
    return str((base / value).resolve())


@pytest.fixture
def bait_factory(tmp_path):
    """Return a callable ``make(**manifest_overrides) -> bait_dir`` that copies the
    reference bait into a fresh tmp dir and applies shallow manifest overrides.
    Pass ``key=None`` to delete a manifest field."""
    counter = {"n": 0}

    def make(**overrides) -> str:
        counter["n"] += 1
        dest = tmp_path / f"bait_{counter['n']}"
        shutil.copytree(HOSTNAME_PROBE, dest)

        manifest_path = dest / "manifest.yaml"
        manifest = yaml.safe_load(manifest_path.read_text())

        for field in ("payload_file", "staging_vessel"):
            value = manifest.get(field, "")
            if isinstance(value, str):
                manifest[field] = _absolutize_catalog_ref(value, HOSTNAME_PROBE)
        listener_class = manifest.get("listener_class", "")
        if isinstance(listener_class, str) and listener_class.startswith("../"):
            module_part, _, class_name = listener_class.rpartition(".")
            manifest["listener_class"] = (
                f"{_absolutize_catalog_ref(module_part, HOSTNAME_PROBE)}.{class_name}"
            )

        for key, value in overrides.items():
            if value is None:
                manifest.pop(key, None)
            else:
                manifest[key] = value
        manifest_path.write_text(yaml.safe_dump(manifest, sort_keys=False))
        return str(dest)

    return make
