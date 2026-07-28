"""models.py — observer API response types (the stable contract).

These Pydantic models define the shape of every response the observer API
produces. Any future UI — another web frontend, a CLI consumer, a notebook —
should be written against *these types*, not against raw dicts. If the backing
data source changes, only
``service.py`` changes; the models and any UI built on them remain stable.
"""

from __future__ import annotations

from typing import Any

from pydantic import BaseModel


# ── baits ─────────────────────────────────────────────────────────────────────


class BaitSummary(BaseModel):
    bait_id: str
    status: str
    assurance_tier: int
    deploy_class: str
    version: str
    default_channel: str
    registered_at: str | None
    instance_count: int
    test: bool                  # example/reference bait — not real intel


class BaitDetail(BaitSummary):
    manifest: dict[str, Any]
    bait_dir: str


# ── instances ─────────────────────────────────────────────────────────────────


class InstanceSummary(BaseModel):
    instance_token: str
    bait_id: str
    bait_version: str
    campaign_id: str
    callback_addresses: dict[str, str]
    status: str
    built_at: str | None
    approved_at: str | None
    burned_at: str | None
    retired_at: str | None
    comment: str | None          # free-text operator note (descriptive only; empty → null)
    artifact_dir: str | None     # staged deployable dir (to_stage/) in the registry material store (derived)


class InstanceDetail(InstanceSummary):
    key_ref: str
    artifact: dict[str, Any] | None


# ── events ────────────────────────────────────────────────────────────────────


class EventSummary(BaseModel):
    """List-view projection: fields safe to display in a dense table."""

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
    edge_recv_time: int         # ms epoch (observed-tier timestamp, inv 17)
    test: bool                  # from a test/example/reference bait — not real intel


class EventDetail(EventSummary):
    """Full event record: all §3.1 fields including bait-level intel."""

    bait_version: str
    assurance_tier: int
    deploy_class: str
    edge_id: str
    instance_status: str
    design_status: str
    source_ja3: str | None
    sensor_time: int            # ms epoch (claimed-tier, inv 17)
    signals: dict[str, Any] | None
    details: dict[str, Any] | None
    details_truncated: bool
    ingested_at: str | None     # ISO wall-clock, housekeeping only


# ── sessions ──────────────────────────────────────────────────────────────────


class SessionSummary(BaseModel):
    """A read-time grouping of records sharing (instance_token, session_id).

    Approximation of a session computed by SQL GROUP BY — no idle-gap / state
    machine. Superseded by the stateful Tier-2 session engine (§6.2). Fields
    mirror ``blacksea.correlation.models.SessionView`` one-to-one.
    """

    session_record_id: str
    instance_token: str
    session_id: str
    bait_id: str
    campaign_id: str
    deploy_class: str
    event_count: int
    first_event_at: int          # ms epoch (observed-tier)
    last_event_at: int
    event_types: list[str]
    source_ips: list[str]
    source_types: list[str]
    seq_min: int
    seq_max: int
    caution_level: str           # max over events: none|low|medium|high
    sig_valid_all: bool          # AND over events
    orphan_any: bool             # OR over events
    test: bool                   # from a test/example/reference bait — not real intel


# ── health ────────────────────────────────────────────────────────────────────


class HitRateBucket(BaseModel):
    bucket_start_ms: int
    count: int


class CautionCount(BaseModel):
    caution_level: str
    count: int


class HealthView(BaseModel):
    bait_id: str | None
    bucket_seconds: int
    hit_rate: list[HitRateBucket]
    caution_distribution: list[CautionCount]
    note: str


# ── system stats ──────────────────────────────────────────────────────────────


class SystemStats(BaseModel):
    bait_count: int
    instance_count: int
    active_instance_count: int
    event_count: int
    postgres_ok: bool
