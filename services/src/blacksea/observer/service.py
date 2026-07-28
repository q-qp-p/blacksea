"""service.py — ObserverService: the canonical read-only data-access layer.

Any observer UI (this web server, a future CLI, a notebook) should call
*this class* and not touch storage directly. The method signatures and return
types (Pydantic models from ``models.py``) form the stable interface contract.
If the backing data source changes, the implementation here will
change; callers do not.

Data sources (both read-only):
  * Registry catalog (Postgres) → baits + instances (sync; the ``control_plane``
    schema, D2 — read through the same ``Registry`` facade the control plane writes)
  * ``blacksea.correlation`` → record + session + health views over Postgres
    (async). The record/session SQL is NOT written here — it lives once in the
    shared correlation read layer so the console can reuse the exact same
    queries. This service only opens a connection, calls a reader, and adapts
    the returned view dataclass into the observer's Pydantic response model.
"""

from __future__ import annotations

from dataclasses import asdict

import psycopg

from blacksea.config import settings
from blacksea.control_plane.registry import InstanceRecord, Registry
from blacksea.correlation import reader
from blacksea.correlation.models import RecordFilter

from .models import (
    BaitDetail,
    BaitSummary,
    CautionCount,
    EventDetail,
    EventSummary,
    HealthView,
    HitRateBucket,
    InstanceDetail,
    InstanceSummary,
    SessionSummary,
    SystemStats,
)

_HEALTH_NOTE = (
    "hit-rate + caution distribution computed over per-hit records; this "
    "approximates the session-level signal until the stateful correlation "
    "engine and revoked_source exclusion land (§6.6)."
)


class ObserverService:
    """Read-only view over the Blacksea control plane and event store.

    ``registry_root``  — filesystem root that parents the material store ``artifacts/``;
                         the design/instance catalog itself lives in Postgres now (D2), so
                         ``postgres_dsn`` is required for bait/instance data too.
    ``postgres_dsn``   — libpq connection string; ``None`` disables *all* catalog and
                         record/session queries (the whole store is now Postgres, D2/O7).
    """

    def __init__(self, registry_root: str, postgres_dsn: str | None) -> None:
        self._dsn = postgres_dsn
        # The catalog is in Postgres (D2); with no DSN there is nothing to read.
        self._reg: Registry | None = (
            Registry(postgres_dsn, registry_root=registry_root, schema=settings.BS_CP_SCHEMA)
            if postgres_dsn else None
        )

    # ── baits ─────────────────────────────────────────────────────────────────

    def list_baits(self) -> list[BaitSummary]:
        if self._reg is None:
            return []
        designs = self._reg.list_designs()
        counts: dict[str, int] = {}
        for inst in self._reg.list_instances():
            counts[inst.bait_id] = counts.get(inst.bait_id, 0) + 1
        return [
            BaitSummary(
                bait_id=d.bait_id,
                status=d.status,
                assurance_tier=d.assurance_tier,
                deploy_class=d.deploy_class,
                version=d.version,
                default_channel=d.default_channel,
                registered_at=d.registered_at,
                instance_count=counts.get(d.bait_id, 0),
                test=d.test,
            )
            for d in designs
        ]

    def get_bait(self, bait_id: str) -> BaitDetail | None:
        if self._reg is None:
            return None
        d = self._reg.get_design(bait_id)
        if d is None:
            return None
        return BaitDetail(
            bait_id=d.bait_id,
            status=d.status,
            assurance_tier=d.assurance_tier,
            deploy_class=d.deploy_class,
            version=d.version,
            default_channel=d.default_channel,
            registered_at=d.registered_at,
            instance_count=len(self._reg.list_instances(bait_id=bait_id)),
            test=d.test,
            manifest=d.manifest,
            bait_dir=d.bait_dir,
        )

    # ── instances ─────────────────────────────────────────────────────────────

    def list_instances(
        self,
        *,
        bait_id: str | None = None,
        campaign_id: str | None = None,
        status: str | None = None,
    ) -> list[InstanceSummary]:
        if self._reg is None:
            return []
        rows = self._reg.list_instances(bait_id=bait_id)
        if campaign_id is not None:
            rows = [r for r in rows if r.campaign_id == campaign_id]
        if status is not None:
            rows = [r for r in rows if r.status == status]
        return [_to_instance_summary(r) for r in rows]

    def get_instance(self, instance_token: str) -> InstanceDetail | None:
        if self._reg is None:
            return None
        r = self._reg.get_instance(instance_token)
        if r is None:
            return None
        return InstanceDetail(
            **_to_instance_summary(r).model_dump(),
            key_ref=r.key_ref,
            artifact=r.artifact,
        )

    # ── events (via the shared correlation read layer) ─────────────────────────

    async def list_events(
        self,
        *,
        bait_id: str | None = None,
        instance_token: str | None = None,
        campaign_id: str | None = None,
        sig_valid: bool | None = None,
        limit: int = settings.DEFAULT_LIMIT,
        offset: int = settings.DEFAULT_OFFSET,
    ) -> list[EventSummary]:
        if not self._dsn:
            return []
        filt = RecordFilter(
            bait_id=bait_id,
            instance_token=instance_token,
            campaign_id=campaign_id,
            sig_valid=sig_valid,
        )
        try:
            async with await psycopg.AsyncConnection.connect(self._dsn) as conn:
                rows = await reader.alist_records(conn, filt, limit=limit, offset=offset)
        except Exception:
            return []
        return [EventSummary(**asdict(r)) for r in rows]

    async def get_event(self, record_id: str) -> EventDetail | None:
        if not self._dsn:
            return None
        try:
            async with await psycopg.AsyncConnection.connect(self._dsn) as conn:
                detail = await reader.aget_record(conn, record_id)
        except Exception:
            return None
        return EventDetail(**asdict(detail)) if detail else None

    # ── sessions (read-time grouping — the seed of the Tier-2 engine) ──────────

    async def list_sessions(
        self,
        *,
        bait_id: str | None = None,
        instance_token: str | None = None,
        campaign_id: str | None = None,
        limit: int = settings.DEFAULT_LIMIT,
        offset: int = settings.DEFAULT_OFFSET,
    ) -> list[SessionSummary]:
        if not self._dsn:
            return []
        filt = RecordFilter(
            bait_id=bait_id, instance_token=instance_token, campaign_id=campaign_id
        )
        try:
            async with await psycopg.AsyncConnection.connect(self._dsn) as conn:
                rows = await reader.asession_views(conn, filt, limit=limit, offset=offset)
        except Exception:
            return []
        return [SessionSummary(**asdict(s)) for s in rows]

    # ── health (hit-rate + caution distribution) ───────────────────────────────

    async def get_health(
        self,
        *,
        bait_id: str | None = None,
        since_ms: int | None = None,
        bucket_seconds: int = settings.HEALTH_BUCKET_S,
    ) -> HealthView:
        if not self._dsn:
            return HealthView(
                bait_id=bait_id,
                bucket_seconds=bucket_seconds,
                hit_rate=[],
                caution_distribution=[],
                note="postgres not configured",
            )
        filt = RecordFilter(bait_id=bait_id, since_ms=since_ms)
        buckets: list = []
        dist: list = []
        try:
            async with await psycopg.AsyncConnection.connect(self._dsn) as conn:
                buckets = await reader.ahit_rate(conn, filt, bucket_seconds=bucket_seconds)
                dist = await reader.acaution_distribution(conn, filt)
        except Exception:
            buckets, dist = [], []
        return HealthView(
            bait_id=bait_id,
            bucket_seconds=bucket_seconds,
            hit_rate=[HitRateBucket(**asdict(b)) for b in buckets],
            caution_distribution=[CautionCount(**asdict(c)) for c in dist],
            note=_HEALTH_NOTE,
        )

    # ── stats ─────────────────────────────────────────────────────────────────

    async def get_stats(self) -> SystemStats:
        designs = self._reg.list_designs() if self._reg is not None else []
        instances = self._reg.list_instances() if self._reg is not None else []
        active = sum(1 for i in instances if i.status == "active")

        event_count = 0
        postgres_ok = False
        if self._dsn:
            try:
                async with await psycopg.AsyncConnection.connect(self._dsn) as conn:
                    event_count = await reader.acount_records(conn)
                    postgres_ok = True
            except Exception:
                pass

        return SystemStats(
            bait_count=len(designs),
            instance_count=len(instances),
            active_instance_count=active,
            event_count=event_count,
            postgres_ok=postgres_ok,
        )


# ── helpers ──────────────────────────────────────────────────────────────────


def _to_instance_summary(r: InstanceRecord) -> InstanceSummary:
    return InstanceSummary(
        instance_token=r.instance_token,
        bait_id=r.bait_id,
        bait_version=r.bait_version,
        campaign_id=r.campaign_id,
        callback_addresses=r.callback_addresses,
        status=r.status,
        built_at=r.built_at,
        approved_at=r.approved_at,
        burned_at=r.burned_at,
        retired_at=r.retired_at,
        comment=r.comment,
        artifact_dir=r.artifact_dir,
    )
