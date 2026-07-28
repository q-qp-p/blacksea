"""models.py — the record filter + the read-view value types.

These are plain, frozen dataclasses (no Pydantic, no I/O) so the module stays
importable by any consumer — the async observer, the future sync console, a
notebook — without dragging a web framework along. Each view type carries a
``from_row`` classmethod that maps a raw ``records`` row (a ``dict`` produced by
``psycopg`` ``dict_row``) into the view. Query construction lives in
``queries.py``; execution lives in ``reader.py``. This file is the single place
that defines *what a view looks like*.

Scope note (inv 12 / inv 17): this is a **UI read layer**, not the Tier-2
attribution engine's input. It may surface full record fields — including
``details`` and ``sensor_time`` on :class:`RecordDetail` — because those are for
human display in the observer/console, exactly as the observer showed them
before. The future stateful correlation engine (§6) consumes the narrowed
``TypedEvent`` projection instead, which structurally excludes those two fields.
Do not feed :class:`RecordDetail` into attribution logic.
"""

from __future__ import annotations

from dataclasses import dataclass, field


# ── caution-level ordering (§3.4) ─────────────────────────────────────────────
# Absent/None is treated as "none". Kept here so both the SQL rank expression
# (queries.py) and the label mapping (SessionView.from_row) agree on one order.
CAUTION_RANK: dict[str | None, int] = {None: 0, "none": 0, "low": 1, "medium": 2, "high": 3}
CAUTION_LABEL: dict[int, str] = {0: "none", 1: "low", 2: "medium", 3: "high"}


@dataclass(frozen=True)
class RecordFilter:
    """A composable, read-only predicate over the ``records`` table.

    Every field defaults to ``None`` ( = no constraint). One instance is shared
    by *all* view queries — the single extension point for adding a new filter
    dimension is here plus ``queries.where_clause``.
    """

    bait_id: str | None = None
    instance_token: str | None = None
    campaign_id: str | None = None
    session_id: str | None = None
    event_type: str | None = None
    source_type: str | None = None
    channel: str | None = None
    sig_valid: bool | None = None
    since_ms: int | None = None      # edge_recv_time >= since_ms (inclusive)
    until_ms: int | None = None      # edge_recv_time <  until_ms (exclusive)


@dataclass(frozen=True)
class RecordCursor:
    """A keyset position in the ``records`` log, ordered by
    ``(edge_recv_time, record_id)`` ascending.

    A plain ``since_ms`` filter is a *non-unique* ``edge_recv_time`` predicate —
    two hits landing in the same millisecond could be skipped or double-read
    across polls. This proper keyset (the full ``(time, id)`` tuple, ``record_id``
    breaking ms ties) is what lets a tail reader page forward with no gap and no
    duplicate. ``record_id`` is ``NOT NULL`` in the schema and never empty, so a
    ``(t, "")`` cursor means "everything at or after ms ``t``" — the form the
    otel_export runner seeds from "now".
    """

    edge_recv_time: int
    record_id: str = ""

    def as_tuple(self) -> tuple[int, str]:
        return (self.edge_recv_time, self.record_id)


# ── record views ──────────────────────────────────────────────────────────────


@dataclass(frozen=True)
class RecordSummary:
    """List-view projection — the dense-table fields, one row per hit."""

    record_id: str
    bait_id: str
    instance_token: str
    campaign_id: str
    session_id: str
    seq_no: int
    event_type: str
    source_ip: str
    source_type: str
    sig_valid: bool
    orphan: bool
    channel: str
    edge_recv_time: int          # ms epoch, observed-tier (inv 17)
    test: bool                   # from a test/example/reference bait, not real intel

    @classmethod
    def from_row(cls, r: dict) -> "RecordSummary":
        return cls(
            record_id=r["record_id"],
            bait_id=r["bait_id"],
            instance_token=r["instance_token"],
            campaign_id=r["campaign_id"],
            session_id=r["session_id"],
            seq_no=r["seq_no"],
            event_type=r["event_type"],
            source_ip=r["source_ip"],
            source_type=r["source_type"],
            sig_valid=r["sig_valid"],
            orphan=r["orphan"],
            channel=r["channel"],
            edge_recv_time=r["edge_recv_time"],
            test=bool(r.get("test", False)),
        )


@dataclass(frozen=True)
class RecordDetail:
    """Full record view — every §3.1 field including bait-level intel.

    Includes ``details`` and ``sensor_time`` for human display only; see the
    module docstring's inv 12/17 note.
    """

    record_id: str
    bait_id: str
    instance_token: str
    campaign_id: str
    session_id: str
    seq_no: int
    event_type: str
    source_ip: str
    source_type: str
    sig_valid: bool
    orphan: bool
    channel: str
    edge_recv_time: int
    bait_version: str
    assurance_tier: int
    deploy_class: str
    edge_id: str
    instance_status: str
    design_status: str
    source_ja3: str | None
    sensor_time: int             # ms epoch, claimed-tier (inv 17)
    signals: dict | None
    details: dict | None
    details_truncated: bool
    ingested_at: str | None      # ISO wall-clock, housekeeping only
    test: bool                   # from a test/example/reference bait, not real intel

    @classmethod
    def from_row(cls, r: dict) -> "RecordDetail":
        return cls(
            record_id=r["record_id"],
            bait_id=r["bait_id"],
            instance_token=r["instance_token"],
            campaign_id=r["campaign_id"],
            session_id=r["session_id"],
            seq_no=r["seq_no"],
            event_type=r["event_type"],
            source_ip=r["source_ip"],
            source_type=r["source_type"],
            sig_valid=r["sig_valid"],
            orphan=r["orphan"],
            channel=r["channel"],
            edge_recv_time=r["edge_recv_time"],
            bait_version=r["bait_version"],
            assurance_tier=r["assurance_tier"],
            deploy_class=r["deploy_class"],
            edge_id=r["edge_id"],
            instance_status=r["instance_status"],
            design_status=r["design_status"],
            source_ja3=r.get("source_ja3"),
            sensor_time=r["sensor_time"],
            signals=r.get("signals"),
            details=r.get("details"),
            details_truncated=bool(r.get("details_truncated", False)),
            ingested_at=str(r["ingested_at"]) if r.get("ingested_at") else None,
            test=bool(r.get("test", False)),
        )


# ── aggregate views ───────────────────────────────────────────────────────────


@dataclass(frozen=True)
class SessionView:
    """A read-time grouping of records sharing ``(instance_token, session_id)``.

    This is a **best-effort approximation** of a session computed purely by SQL
    ``GROUP BY`` — it has no idle-gap timer, no open/close state machine, and no
    late-hit semantics. It is the seed of, and will be superseded by, the
    stateful Tier-2 session engine (§6.2). Use it for a quick "what happened in
    this interaction" view, not as an attribution-grade session record.

    ``session_record_id`` uses the §6.3 form (``<itoken_hex>-<sid_hex>``) so it
    lines up with the future engine's key.
    """

    session_record_id: str
    instance_token: str
    session_id: str
    bait_id: str
    campaign_id: str
    deploy_class: str
    event_count: int
    first_event_at: int
    last_event_at: int
    event_types: list[str] = field(default_factory=list)
    source_ips: list[str] = field(default_factory=list)
    source_types: list[str] = field(default_factory=list)
    seq_min: int = 0
    seq_max: int = 0
    caution_level: str = "none"
    sig_valid_all: bool = True
    orphan_any: bool = False
    test: bool = False           # from a test/example/reference bait, not real intel

    @classmethod
    def from_row(cls, r: dict) -> "SessionView":
        itoken = r["instance_token"]
        sid = r["session_id"]
        return cls(
            session_record_id=f"{itoken}-{sid}",
            instance_token=itoken,
            session_id=sid,
            bait_id=r["bait_id"],
            campaign_id=r["campaign_id"],
            deploy_class=r["deploy_class"],
            event_count=r["event_count"],
            first_event_at=r["first_event_at"],
            last_event_at=r["last_event_at"],
            event_types=sorted(r.get("event_types") or []),
            source_ips=sorted(r.get("source_ips") or []),
            source_types=sorted(r.get("source_types") or []),
            seq_min=r.get("seq_min") or 0,
            seq_max=r.get("seq_max") or 0,
            caution_level=CAUTION_LABEL.get(r.get("caution_rank") or 0, "none"),
            sig_valid_all=bool(r.get("sig_valid_all", True)),
            orphan_any=bool(r.get("orphan_any", False)),
            test=bool(r.get("test", False)),
        )


@dataclass(frozen=True)
class TimeBucket:
    """One hit-rate bucket: ``count`` records whose ``edge_recv_time`` fell in
    ``[bucket_start_ms, bucket_start_ms + bucket_ms)``."""

    bucket_start_ms: int
    count: int

    @classmethod
    def from_row(cls, r: dict) -> "TimeBucket":
        return cls(bucket_start_ms=int(r["bucket_start"]), count=int(r["n"]))


@dataclass(frozen=True)
class CautionCount:
    """Number of records at a given ``caution_level`` (§3.4)."""

    caution_level: str
    count: int

    @classmethod
    def from_row(cls, r: dict) -> "CautionCount":
        return cls(caution_level=r["caution_level"] or "none", count=int(r["n"]))
