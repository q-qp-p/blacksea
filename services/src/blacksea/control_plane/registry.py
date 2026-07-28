"""registry.py — the control-plane **catalog**, backed by Postgres (D1/D2/D6).

Holds two kinds of record:

* **DesignRecord** (see context.md's "Registry record (runtime extension)" section) —
  the manifest fields plus design-level lifecycle state.
  One row per ``bait_id`` (the *current* version; multi-version dispatch is still an
  open item — see context.md). Created on ingestion (``register``).
* **InstanceRecord** (see context.md's "Instance record fields" section) — per-deployment child of a design: the master
  ``instance_token``, the operator-set ``campaign_id`` + ``callback_addresses``,
  and instance-level lifecycle state.

Storage moved from flat JSON files to a ``control_plane`` schema in the brain's
Postgres (``schema.py``, D2). The change is **behind this interface** (D6): the
``get_/put_/list_`` signatures and the ``DesignRecord`` / ``InstanceRecord``
dataclasses are unchanged, so every caller (``lifecycle``,
``brain_keydir.sync_routing_fields``, ``forge``, ``operations``, ``cli``, the
observer) is untouched except for how it *constructs* a ``Registry`` (now a DSN +
a filesystem root, not a bare path). The new capability this migration exists to make:

* :meth:`transaction` — a context-managed multi-record transaction (O3). Reads take
  ``SELECT … FOR UPDATE`` row locks, so racing ``approve``/``burn`` serialize and a
  crash mid-transition rolls back to *neither* write rather than half of both.

(There is no snapshot ``seq`` counter anymore: the edge is a dumb dead-drop with no
directory, so there is no signed edge snapshot to sequence — see
``edge/context.md``.)

**inv 16:** the per-instance HMAC-SHA256 master key ``_KEY`` is *never* written here.
The instance row stores only ``key_ref`` (a pointer); ``_KEY`` goes straight to the
brain's key directory (see context.md's "Brain key directory — write side" section) and is
discarded server-side after ``build()``.
"""

from __future__ import annotations

import os
from contextlib import contextmanager
from dataclasses import dataclass, field, replace
from typing import Any, Iterator

import psycopg
from psycopg import sql
from psycopg.types.json import Jsonb

from blacksea.control_plane.schema import DEFAULT_SCHEMA, ensure_catalog, validate_schema


class CatalogUnavailableError(RuntimeError):
    """A catalog operation was attempted without a configured ``POSTGRES_DSN`` (D2/O7).
    Raised lazily on first catalog access, with a clear message rather than psycopg's
    default-socket surprise."""

# ── lifecycle state vocabularies (see context.md's "Lifecycle state machines" section) ──

DESIGN_STATES = ("draft", "staged", "deployed", "burned", "retired")
INSTANCE_STATES = ("pending", "active", "burned", "retired", "revoked")


# ── records ──────────────────────────────────────────────────────────────────


@dataclass
class DesignRecord:
    """Design-level registry record (see context.md's "Registry record (runtime extension)"
    section): manifest projection + lifecycle.

    ``manifest`` is the parsed manifest.yaml verbatim (the design-level source of
    truth — never overridden here; O1: it is the authoritative copy in the DB).
    ``bait_dir`` is the absolute path to the bait directory, kept so the *factory*
    can read ``payload_file`` / ``staging_vessel`` at build time on the control-plane
    host (it does not resolve on the brain host — O9). ``listener_hash`` is the
    sha256 of the frozen listener closure (O11), set at ``register`` (freeze time).
    """

    bait_id: str
    manifest: dict[str, Any]
    bait_dir: str
    status: str = "draft"
    registered_at: str | None = None
    staged_at: str | None = None
    burned_at: str | None = None
    retired_at: str | None = None
    listener_hash: str | None = None

    @property
    def version(self) -> str:
        return str(self.manifest.get("version", ""))

    @property
    def assurance_tier(self) -> int:
        return int(self.manifest.get("assurance_tier", 0))

    @property
    def deploy_class(self) -> str:
        return str(self.manifest.get("deploy_class", ""))

    @property
    def default_channel(self) -> str:
        """First declared channel — the derivable ``default_channel``."""
        channels = self.manifest.get("channels") or {}
        return next(iter(channels), "")

    @property
    def test(self) -> bool:
        """Optional manifest flag (default ``false``) marking a test/example/reference
        bait — not real intel. Propagated to every record this bait produces
        (``records.test``, see brain/context.md) and surfaced in the observer UI."""
        return bool(self.manifest.get("test", False))


@dataclass
class InstanceRecord:
    """Per-deployment instance record (see context.md's "Instance record fields" section).
    Child of a DesignRecord.

    ``instance_token`` is a hex string (the wire/JSON form the edge routing directory
    + brain key directory consume). ``key_ref`` is a *reference*, not key material
    (inv 16) — ``_KEY`` itself goes straight to the brain's key directory (see context.md's
    "Brain key directory — write side" section),
    never into this catalog. ``artifact`` is the Artifact descriptor recorded by
    the factory. ``listener_hash`` is the design's ``listener_hash`` pinned onto the
    instance at build (O11 #2) — it survives any later edit to the design row.
    ``comment`` is a free-text operator note captured at forge/build time (empty is fine) —
    purely descriptive metadata (why this instance was built), never on the routing/attribution path.
    """

    instance_token: str                       # 16-char hex (8 B)
    bait_id: str
    bait_version: str
    key_ref: str                              # reference only — never the key (inv 16)
    campaign_id: str
    callback_addresses: dict[str, str]
    status: str = "pending"
    artifact: dict[str, Any] | None = None
    built_at: str | None = None
    approved_at: str | None = None
    burned_at: str | None = None
    retired_at: str | None = None
    listener_hash: str | None = None
    comment: str | None = None                # free-text operator note (descriptive only)

    @property
    def artifact_dir(self) -> str | None:
        """Absolute path to this instance's staged deployable **directory** — the vessel's
        ``to_stage/`` output in the registry material store
        (``<artifacts-root>/<bait_id>/<timestamp>/to_stage/``), read from the stored artifact
        descriptor's ``output_dir``. This is the *whole directory* an operator ships (it may hold
        more than the primary file — supporting files, a loader, etc.), not a single file.
        ``None`` until the instance is built. Build-host path (same relocation caveat as
        ``DesignRecord.bait_dir``)."""
        raw = self.artifact
        if not isinstance(raw, dict):
            return None
        # The stored value is the {artifact_type, descriptor} envelope; tolerate a bare descriptor.
        desc = raw.get("descriptor", raw)
        if not isinstance(desc, dict):
            return None
        out_dir = desc.get("output_dir")
        return str(out_dir) if out_dir else None


# ── column plumbing ────────────────────────────────────────────────────────────

_DESIGN_COLS = (
    "bait_id", "version", "manifest", "bait_dir", "listener_hash",
    "status", "registered_at", "staged_at", "burned_at", "retired_at",
)
_INSTANCE_COLS = (
    "instance_token", "bait_id", "bait_version", "key_ref", "listener_hash",
    "campaign_id", "callback_addresses", "artifact", "status",
    "built_at", "approved_at", "burned_at", "retired_at", "comment",
)


def _tbl(schema: str, name: str) -> sql.Composed:
    return sql.SQL("{}.{}").format(sql.Identifier(schema), sql.Identifier(name))


def _cols(names: tuple[str, ...]) -> sql.Composed:
    return sql.SQL(", ").join(sql.Identifier(c) for c in names)


def _row_to_design(row: tuple) -> DesignRecord:
    d = dict(zip(_DESIGN_COLS, row))
    return DesignRecord(
        bait_id=d["bait_id"],
        manifest=d["manifest"],
        bait_dir=d["bait_dir"],
        status=d["status"],
        registered_at=d["registered_at"],
        staged_at=d["staged_at"],
        burned_at=d["burned_at"],
        retired_at=d["retired_at"],
        listener_hash=d["listener_hash"],
    )


def _design_params(r: DesignRecord) -> tuple:
    # ``version`` is denormalised from the manifest for querying; ``manifest`` stays authoritative.
    return (
        r.bait_id, r.version, Jsonb(r.manifest), r.bait_dir, r.listener_hash,
        r.status, r.registered_at, r.staged_at, r.burned_at, r.retired_at,
    )


def _row_to_instance(row: tuple) -> InstanceRecord:
    d = dict(zip(_INSTANCE_COLS, row))
    return InstanceRecord(
        instance_token=d["instance_token"],
        bait_id=d["bait_id"],
        bait_version=d["bait_version"],
        key_ref=d["key_ref"],
        listener_hash=d["listener_hash"],
        campaign_id=d["campaign_id"],
        callback_addresses=d["callback_addresses"],
        artifact=d["artifact"],
        status=d["status"],
        built_at=d["built_at"],
        approved_at=d["approved_at"],
        burned_at=d["burned_at"],
        retired_at=d["retired_at"],
        comment=d["comment"],
    )


def _instance_params(r: InstanceRecord) -> tuple:
    return (
        r.instance_token, r.bait_id, r.bait_version, r.key_ref, r.listener_hash,
        r.campaign_id, Jsonb(r.callback_addresses),
        Jsonb(r.artifact) if r.artifact is not None else None,
        r.status, r.built_at, r.approved_at, r.burned_at, r.retired_at, r.comment,
    )


# ── low-level catalog ops (shared by Registry + its transaction view) ──────────


def _get_design(conn, schema, bait_id, *, for_update=False) -> DesignRecord | None:
    q = sql.SQL("SELECT {cols} FROM {tbl} WHERE bait_id = %s{lock}").format(
        cols=_cols(_DESIGN_COLS), tbl=_tbl(schema, "design"),
        lock=sql.SQL(" FOR UPDATE") if for_update else sql.SQL(""),
    )
    with conn.cursor() as cur:
        cur.execute(q, (bait_id,))
        row = cur.fetchone()
    return _row_to_design(row) if row else None


def _list_designs(conn, schema) -> list[DesignRecord]:
    q = sql.SQL("SELECT {cols} FROM {tbl} ORDER BY bait_id").format(
        cols=_cols(_DESIGN_COLS), tbl=_tbl(schema, "design"))
    with conn.cursor() as cur:
        cur.execute(q)
        return [_row_to_design(r) for r in cur.fetchall()]


def _put_design(conn, schema, record: DesignRecord) -> None:
    updates = sql.SQL(", ").join(
        sql.SQL("{c} = EXCLUDED.{c}").format(c=sql.Identifier(c))
        for c in _DESIGN_COLS if c != "bait_id"
    )
    q = sql.SQL(
        "INSERT INTO {tbl} ({cols}) VALUES ({ph}) "
        "ON CONFLICT (bait_id) DO UPDATE SET {updates}"
    ).format(
        tbl=_tbl(schema, "design"), cols=_cols(_DESIGN_COLS),
        ph=sql.SQL(", ").join(sql.Placeholder() * len(_DESIGN_COLS)),
        updates=updates,
    )
    conn.execute(q, _design_params(record))


def _get_instance(conn, schema, token, *, for_update=False) -> InstanceRecord | None:
    q = sql.SQL("SELECT {cols} FROM {tbl} WHERE instance_token = %s{lock}").format(
        cols=_cols(_INSTANCE_COLS), tbl=_tbl(schema, "instance"),
        lock=sql.SQL(" FOR UPDATE") if for_update else sql.SQL(""),
    )
    with conn.cursor() as cur:
        cur.execute(q, (token,))
        row = cur.fetchone()
    return _row_to_instance(row) if row else None


def _list_instances(conn, schema, bait_id=None) -> list[InstanceRecord]:
    where = sql.SQL(" WHERE bait_id = %s") if bait_id is not None else sql.SQL("")
    q = sql.SQL("SELECT {cols} FROM {tbl}{where} ORDER BY instance_token").format(
        cols=_cols(_INSTANCE_COLS), tbl=_tbl(schema, "instance"), where=where)
    params = (bait_id,) if bait_id is not None else ()
    with conn.cursor() as cur:
        cur.execute(q, params)
        return [_row_to_instance(r) for r in cur.fetchall()]


def _put_instance(conn, schema, record: InstanceRecord) -> None:
    updates = sql.SQL(", ").join(
        sql.SQL("{c} = EXCLUDED.{c}").format(c=sql.Identifier(c))
        for c in _INSTANCE_COLS if c != "instance_token"
    )
    q = sql.SQL(
        "INSERT INTO {tbl} ({cols}) VALUES ({ph}) "
        "ON CONFLICT (instance_token) DO UPDATE SET {updates}"
    ).format(
        tbl=_tbl(schema, "instance"), cols=_cols(_INSTANCE_COLS),
        ph=sql.SQL(", ").join(sql.Placeholder() * len(_INSTANCE_COLS)),
        updates=updates,
    )
    conn.execute(q, _instance_params(record))


# ── transaction view ───────────────────────────────────────────────────────────


class _Tx:
    """Row-locking view over an open Postgres transaction (O3). Its ``get_*`` take
    ``FOR UPDATE`` so concurrent transitions on the same record serialize, and a
    multi-record transition (``approve`` promotes the design *and* activates the
    instance) commits atomically or rolls back to neither write."""

    def __init__(self, conn, schema: str) -> None:
        self._conn = conn
        self._schema = schema

    def get_design(self, bait_id: str) -> DesignRecord | None:
        return _get_design(self._conn, self._schema, bait_id, for_update=True)

    def put_design(self, record: DesignRecord) -> None:
        _put_design(self._conn, self._schema, record)

    def get_instance(self, instance_token: str) -> InstanceRecord | None:
        return _get_instance(self._conn, self._schema, instance_token, for_update=True)

    def put_instance(self, record: InstanceRecord) -> None:
        _put_instance(self._conn, self._schema, record)


# ── store ────────────────────────────────────────────────────────────────────


class Registry:
    """Postgres-backed catalog for the control-plane ``design`` / ``instance`` state (D2).

    ``dsn`` is a libpq connection string (the brain's Postgres, D2). ``registry_root``
    is the filesystem root that is the default parent of ``artifacts/`` (the material
    store). ``schema`` is the catalog schema (default ``control_plane``; tests use a
    throwaway per-test schema for isolation).

    A single autocommit connection is opened lazily and reused; individual
    ``get_/put_/list_`` calls autocommit, and :meth:`transaction` opens an explicit
    transaction block over the same connection.
    """

    def __init__(self, dsn: str, *, registry_root: str, schema: str = DEFAULT_SCHEMA,
                 auto_ensure: bool = True) -> None:
        self.dsn = dsn
        self.schema = validate_schema(schema)
        self.registry_root = os.path.abspath(registry_root)
        # When False, connections skip the idempotent catalog DDL — for read-only callers,
        # or additional handles onto an already-bootstrapped schema (avoids redundant
        # concurrent ``CREATE … IF NOT EXISTS``).
        self._auto_ensure = auto_ensure
        self._conn: psycopg.Connection | None = None
        self._schema_ready = False

    # ── connection lifecycle ───────────────────────────────────────────────────

    def _connection(self) -> psycopg.Connection:
        if not self.dsn:
            # Constructed without a DSN; only a command that actually touches the catalog reaches
            # here. Fail with a clear message rather than psycopg's default-socket surprise.
            raise CatalogUnavailableError(
                "control-plane requires POSTGRES_DSN (the registry is Postgres now, D2) — "
                "run via `blacksea forge` / another `blacksea` command, or pass --postgres")
        if self._conn is None or self._conn.closed:
            self._conn = psycopg.connect(self.dsn, autocommit=True)
            self._schema_ready = not self._auto_ensure
        if not self._schema_ready:
            ensure_catalog(self._conn, self.schema)
            self._schema_ready = True
        return self._conn

    def ensure_schema(self) -> None:
        """Create the catalog schema + tables if absent (idempotent). Called lazily on
        first use; exposed so a bootstrap step can pre-create before concurrent use."""
        self._connection()

    def close(self) -> None:
        if self._conn is not None and not self._conn.closed:
            self._conn.close()
        self._conn = None

    # ── designs ──────────────────────────────────────────────────────────────

    def get_design(self, bait_id: str) -> DesignRecord | None:
        return _get_design(self._connection(), self.schema, bait_id)

    def put_design(self, record: DesignRecord) -> None:
        _put_design(self._connection(), self.schema, record)

    def list_designs(self) -> list[DesignRecord]:
        return _list_designs(self._connection(), self.schema)

    # ── instances ──────────────────────────────────────────────────────────────

    def get_instance(self, instance_token: str) -> InstanceRecord | None:
        return _get_instance(self._connection(), self.schema, instance_token)

    def put_instance(self, record: InstanceRecord) -> None:
        _put_instance(self._connection(), self.schema, record)

    def list_instances(self, bait_id: str | None = None) -> list[InstanceRecord]:
        return _list_instances(self._connection(), self.schema, bait_id)

    # ── transactions (O3) ──────────────────────────────────────────────────────

    @contextmanager
    def transaction(self) -> Iterator[_Tx]:
        """Run a multi-record lifecycle transition atomically. Reads inside take
        ``FOR UPDATE`` row locks; the whole block commits on clean exit and rolls back
        on any exception — so a crash between two writes leaves *neither* applied."""
        conn = self._connection()
        with conn.transaction():
            yield _Tx(conn, self.schema)


# Re-export ``replace`` so callers can update immutable-ish records ergonomically.
__all__ = [
    "DESIGN_STATES",
    "INSTANCE_STATES",
    "DesignRecord",
    "InstanceRecord",
    "Registry",
    "replace",
]
