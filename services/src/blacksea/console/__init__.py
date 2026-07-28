"""blacksea.console — the operator console: the `blacksea` CLI + the in-process facade.

This package's public surface is the **console facade** (`service.ConsoleService` +
`ConsoleConfig`) and the value types it returns — re-exported here so a consumer (the CLI now,
the future HTTP skin / reworked observer web UI later) imports them from one place instead of
five modules (see `console/context.md`).

Importing this package must NOT drag in click/rich (the facade-purity invariant) — so the
re-exports below pull only from `service`/`models`, never from `cli`/`commands`/`render`.
"""

from __future__ import annotations

from .models import (  # noqa: F401
    ApproveResult,
    ArtifactLocation,
    BaitShow,
    BuildResult,
    BurnResult,
    CampaignSummary,
    CautionCount,
    ComponentStatus,
    ConfigItem,
    DaemonStatus,
    DesignRecord,
    DownResult,
    ForgeResult,
    InfraStatus,
    InitResult,
    InstanceRecord,
    OtelStatus,
    RecordCursor,
    RecordDetail,
    RecordFilter,
    RecordSummary,
    RegisterResult,
    ResetResult,
    RetireResult,
    RevokeResult,
    SessionView,
    TimeBucket,
    UpResult,
)
from .service import ConsoleConfig, ConsoleService  # noqa: F401

__all__ = [
    "ConsoleService",
    "ConsoleConfig",
    # composite views
    "InfraStatus",
    "ComponentStatus",
    "BaitShow",
    "ArtifactLocation",
    "OtelStatus",
    "ConfigItem",
    "InitResult",
    # lifecycle supervisor results (up/down/reset/daemon_status)
    "DaemonStatus",
    "UpResult",
    "DownResult",
    "ResetResult",
    # pass-through value types
    "DesignRecord",
    "InstanceRecord",
    "RegisterResult",
    "BuildResult",
    "ApproveResult",
    "BurnResult",
    "RetireResult",
    "RevokeResult",
    "CampaignSummary",
    "ForgeResult",
    "RecordSummary",
    "RecordDetail",
    "RecordFilter",
    "RecordCursor",
    "SessionView",
    "TimeBucket",
    "CautionCount",
]
