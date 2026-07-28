"""api.py — FastAPI application factory.

Thin HTTP layer: routes delegate immediately to ObserverService. No business
logic lives here. Add new endpoints by extending the service contract first
(models.py → service.py) then exposing them here.

Interactive API docs (OpenAPI) are served at ``/docs`` by FastAPI automatically.
"""

from __future__ import annotations

import os

from fastapi import FastAPI, HTTPException, Query
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse

from blacksea.config import settings

from .models import (
    BaitDetail,
    BaitSummary,
    EventDetail,
    EventSummary,
    HealthView,
    InstanceDetail,
    InstanceSummary,
    SessionSummary,
    SystemStats,
)
from .service import ObserverService

_STATIC_DIR = os.path.join(os.path.dirname(__file__), "static")


def make_app(registry_root: str, postgres_dsn: str | None) -> FastAPI:
    """Create and return the ASGI app wired to the given data sources."""
    svc = ObserverService(registry_root, postgres_dsn)

    app = FastAPI(
        title="Blacksea Observer",
        description=(
            "Read-only view over the Blacksea control plane (baits + instances) "
            "and the event store (fired records). For interactive API docs see /docs."
        ),
        version="1.0",
    )

    app.add_middleware(
        CORSMiddleware,
        allow_origins=["*"],
        allow_methods=["GET"],
        allow_headers=["*"],
    )

    # ── system ────────────────────────────────────────────────────────────────

    @app.get("/api/v1/stats", response_model=SystemStats, tags=["system"])
    async def get_stats() -> SystemStats:
        """Aggregate counts: baits, instances, events, postgres reachability."""
        return await svc.get_stats()

    # ── baits ─────────────────────────────────────────────────────────────────

    @app.get("/api/v1/baits", response_model=list[BaitSummary], tags=["baits"])
    def list_baits() -> list[BaitSummary]:
        """All registered bait designs."""
        return svc.list_baits()

    @app.get("/api/v1/baits/{bait_id}", response_model=BaitDetail, tags=["baits"])
    def get_bait(bait_id: str) -> BaitDetail:
        """Full design record including raw manifest."""
        result = svc.get_bait(bait_id)
        if result is None:
            raise HTTPException(status_code=404, detail="bait not found")
        return result

    # ── instances ─────────────────────────────────────────────────────────────

    @app.get("/api/v1/instances", response_model=list[InstanceSummary], tags=["instances"])
    def list_instances(
        bait_id: str | None = Query(default=None, description="Filter by bait_id"),
        campaign_id: str | None = Query(default=None, description="Filter by campaign_id"),
        status: str | None = Query(default=None, description="Filter by lifecycle status"),
    ) -> list[InstanceSummary]:
        """All deployed instances, optionally filtered."""
        return svc.list_instances(bait_id=bait_id, campaign_id=campaign_id, status=status)

    @app.get(
        "/api/v1/instances/{instance_token}",
        response_model=InstanceDetail,
        tags=["instances"],
    )
    def get_instance(instance_token: str) -> InstanceDetail:
        """Full instance record (key_ref, artifact descriptor, callback addresses)."""
        result = svc.get_instance(instance_token)
        if result is None:
            raise HTTPException(status_code=404, detail="instance not found")
        return result

    # ── events ────────────────────────────────────────────────────────────────

    @app.get("/api/v1/events", response_model=list[EventSummary], tags=["events"])
    async def list_events(
        bait_id: str | None = Query(default=None),
        instance_token: str | None = Query(default=None),
        campaign_id: str | None = Query(default=None),
        sig_valid: bool | None = Query(default=None, description="true = valid sig only"),
        limit: int = Query(default=settings.DEFAULT_LIMIT, ge=1, le=settings.MAX_LIMIT),
        offset: int = Query(default=settings.DEFAULT_OFFSET, ge=0),
    ) -> list[EventSummary]:
        """Recent fired events. Returns [] if Postgres is not configured."""
        return await svc.list_events(
            bait_id=bait_id,
            instance_token=instance_token,
            campaign_id=campaign_id,
            sig_valid=sig_valid,
            limit=limit,
            offset=offset,
        )

    @app.get("/api/v1/events/{record_id}", response_model=EventDetail, tags=["events"])
    async def get_event(record_id: str) -> EventDetail:
        """Full event record including signals and details."""
        result = await svc.get_event(record_id)
        if result is None:
            raise HTTPException(status_code=404, detail="event not found")
        return result

    # ── sessions ──────────────────────────────────────────────────────────────

    @app.get("/api/v1/sessions", response_model=list[SessionSummary], tags=["sessions"])
    async def list_sessions(
        bait_id: str | None = Query(default=None),
        instance_token: str | None = Query(default=None),
        campaign_id: str | None = Query(default=None),
        limit: int = Query(default=settings.DEFAULT_LIMIT, ge=1, le=settings.MAX_LIMIT),
        offset: int = Query(default=settings.DEFAULT_OFFSET, ge=0),
    ) -> list[SessionSummary]:
        """Records grouped into approximate sessions by (instance_token,
        session_id). A read-time approximation — no idle-gap/state machine yet
        (that is the Tier-2 engine, §6.2). Returns [] if Postgres is unset."""
        return await svc.list_sessions(
            bait_id=bait_id,
            instance_token=instance_token,
            campaign_id=campaign_id,
            limit=limit,
            offset=offset,
        )

    # ── health ────────────────────────────────────────────────────────────────

    @app.get("/api/v1/health", response_model=HealthView, tags=["health"])
    async def get_health(
        bait_id: str | None = Query(default=None),
        since_ms: int | None = Query(default=None, description="edge_recv_time >= this (ms epoch)"),
        bucket_seconds: int = Query(default=settings.HEALTH_BUCKET_S, ge=1, description="hit-rate bucket width"),
    ) -> HealthView:
        """Burn-detection inputs (§6.8): hit-rate over time + caution-level
        distribution. Read-only display; the closed loop is a later milestone."""
        return await svc.get_health(
            bait_id=bait_id, since_ms=since_ms, bucket_seconds=bucket_seconds
        )

    # ── static UI ─────────────────────────────────────────────────────────────

    @app.get("/", include_in_schema=False)
    def index() -> FileResponse:
        return FileResponse(os.path.join(_STATIC_DIR, "index.html"))

    return app
