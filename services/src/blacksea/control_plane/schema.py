"""schema.py — the control-plane **catalog** DDL + role/grant bootstrap (Phase 0).

The registry's design/instance/lifecycle state lives in the brain's Postgres under a
dedicated ``control_plane`` schema (D2 — one store, O6 — isolated by role grants). This
module is the idempotent DDL runner: it creates the schema + tables (``ensure_catalog``)
and, separately, the least-privilege roles + grants (``ensure_roles_and_grants``,
superuser-only) that make "the brain cannot forge lifecycle" a DB guarantee rather than
a convention.

Two stores, joined by ID:

* **catalog** (here) — designs, instances, lifecycle status, the full parsed
  manifest (``jsonb``, O1), the artifact descriptor, the ``listener_hash`` (O11).
* **material** (``registry/artifacts/``) — the file bytes (frozen listener code,
  payload bundles, deployables); joined to the catalog by ``(bait_id, version)`` /
  ``instance_token``, never by a stored path.

**Secrets never enter the catalog (D3, inv 16):** the instance row holds only
``key_ref`` (a pointer), never ``_KEY``; ``_KEY`` goes straight to the brain key
directory (see context.md's "Brain key directory — write side" section) — the sole
key directory now that the edge is a dead-drop.

**Timestamps are ``text`` (ISO-8601), not ``timestamptz``,** so the ``DesignRecord`` /
``InstanceRecord`` ``str | None`` timestamp contract round-trips byte-for-byte.
"""

from __future__ import annotations

import re

import psycopg
from psycopg import sql

DEFAULT_SCHEMA = "control_plane"
CP_ROLE = "cp_role"
BRAIN_ROLE = "brain_role"

_IDENT_RE = re.compile(r"^[a-z_][a-z0-9_]*$")


def validate_schema(schema: str) -> str:
    """Guard the schema name — it is composed into DDL as an identifier. Config/tests
    supply it (never an end user), but validate anyway so a typo fails loudly rather
    than mangling SQL."""
    if not _IDENT_RE.match(schema):
        raise ValueError(f"invalid schema identifier {schema!r}")
    return schema


def _catalog_ddl(schema: str) -> sql.Composed:
    s = sql.Identifier(validate_schema(schema))
    return sql.SQL(
        """
        CREATE SCHEMA IF NOT EXISTS {s};

        CREATE TABLE IF NOT EXISTS {s}.design (
            bait_id        text PRIMARY KEY,
            version        text        NOT NULL,
            manifest       jsonb       NOT NULL,          -- O1: full parsed manifest, authoritative
            bait_dir       text,                          -- build-time source anchor (control-plane host only)
            listener_hash  text,                          -- O11: sha256 of the frozen listener closure
            status         text        NOT NULL DEFAULT 'draft',
            registered_at  text,
            staged_at      text,
            burned_at      text,
            retired_at     text
        );

        CREATE TABLE IF NOT EXISTS {s}.instance (
            instance_token     text PRIMARY KEY,          -- 16-hex (8 B)
            bait_id            text NOT NULL REFERENCES {s}.design(bait_id),
            bait_version       text NOT NULL,
            key_ref            text NOT NULL,              -- D3: pointer only — never the key (inv 16)
            listener_hash      text,                       -- O11: pinned at build, survives design edits
            campaign_id        text NOT NULL,
            callback_addresses jsonb NOT NULL,
            artifact           jsonb,                      -- descriptor (filenames + sha256)
            status             text NOT NULL DEFAULT 'pending',
            built_at    text,
            approved_at text,
            burned_at   text,
            retired_at  text,
            comment     text                       -- free-text operator note, descriptive only
        );

        CREATE INDEX IF NOT EXISTS idx_cp_instance_bait_id ON {s}.instance (bait_id);

        -- Additive migration for catalogs created before `comment` existed (CREATE TABLE
        -- IF NOT EXISTS above is a no-op on an existing table, so the column is added here).
        ALTER TABLE {s}.instance ADD COLUMN IF NOT EXISTS comment text;
        """
    ).format(s=s)


def ensure_catalog(conn: psycopg.Connection, schema: str = DEFAULT_SCHEMA) -> None:
    """Create the ``control_plane`` schema + tables if absent (idempotent). Runnable
    by the owning control-plane role — no superuser needed. Commits."""
    conn.execute(_catalog_ddl(schema))
    conn.commit()


def ensure_roles_and_grants(conn: psycopg.Connection, schema: str = DEFAULT_SCHEMA) -> None:
    """Create the ``cp_role`` / ``brain_role`` group roles and apply the O6 grant
    matrix (idempotent). **Superuser / CREATEROLE required.**

    Grants (O6):

    * ``cp_role`` — ``USAGE`` on the schema + ``ALL`` on every catalog table (owner/DML).
    * ``brain_role`` — ``USAGE`` + ``SELECT`` on ``design`` / ``instance`` only; **no**
      write anywhere in the schema. A brain compromise gets read-only lifecycle
      visibility, never write — it cannot revive a revoked instance or flip a status.

    The current login role is granted membership in **both** so a single dev DSN keeps
    working (``blacksea forge`` / the brain both connect as it); enforcing the split in
    production means giving the brain a DSN that is a member of only ``brain_role``.
    The isolation is provable today via ``SET ROLE brain_role`` (see the Phase 0 test).
    """
    validate_schema(schema)
    s = sql.Identifier(schema)
    cp = sql.Identifier(CP_ROLE)
    brain = sql.Identifier(BRAIN_ROLE)

    # Group roles (NOLOGIN — memberships, not login accounts). CREATE ROLE has no
    # IF NOT EXISTS, so guard with a DO block.
    for role in (CP_ROLE, BRAIN_ROLE):
        conn.execute(
            sql.SQL(
                "DO $$ BEGIN "
                "IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = {name}) THEN "
                "CREATE ROLE {ident} NOLOGIN; END IF; END $$;"
            ).format(name=sql.Literal(role), ident=sql.Identifier(role))
        )

    conn.execute(sql.SQL("GRANT USAGE ON SCHEMA {s} TO {cp};").format(s=s, cp=cp))
    conn.execute(
        sql.SQL(
            "GRANT ALL ON ALL TABLES IN SCHEMA {s} TO {cp};"
        ).format(s=s, cp=cp)
    )
    conn.execute(sql.SQL("GRANT USAGE ON SCHEMA {s} TO {brain};").format(s=s, brain=brain))
    conn.execute(
        sql.SQL(
            "GRANT SELECT ON {s}.design, {s}.instance TO {brain};"
        ).format(s=s, brain=brain)
    )
    # NB: brain_role gets SELECT only, and no write anywhere in the schema (O6).

    # Keep the current login role able to act as either (single-DSN dev ergonomics).
    conn.execute(
        sql.SQL("GRANT {cp}, {brain} TO CURRENT_USER;").format(cp=cp, brain=brain)
    )
    conn.commit()
