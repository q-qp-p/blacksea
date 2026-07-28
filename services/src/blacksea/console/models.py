"""models.py — the console facade's **new** composite dataclasses, plus re-exports.

Per `console/context.md`'s facade contract: the facade returns the
dataclasses the underlying modules already produce (`correlation.reader`'s
`RecordSummary`/`RecordDetail`/…, `operations`' `RegisterResult`/`BuildResult`/…, `Registry`'s
`DesignRecord`/`InstanceRecord`) and defines **new** dataclasses only for composite views that
don't exist anywhere else. Those live here.

This module — like `service.py`/`probes.py`/`otel_ctl.py` — imports **no click, no rich, no
Pydantic** (the facade-purity invariant). Plain frozen dataclasses only, so the
future HTTP skin / web UI can import the facade clean.
"""

from __future__ import annotations

from dataclasses import dataclass, field

# ── pass-through re-exports (single import surface) ─────────────────────────────
# Consumers import these value types from the facade, not from five different modules. We
# re-export (never redefine) them here; the owning module stays the source of truth.
from blacksea.control_plane.operations import (  # noqa: F401
    ApproveResult,
    BuildResult,
    BurnResult,
    CampaignSummary,
    RegisterResult,
    RetireResult,
    RevokeResult,
)
from blacksea.control_plane.forge import ForgeResult  # noqa: F401
from blacksea.control_plane.registry import DesignRecord, InstanceRecord  # noqa: F401
from blacksea.correlation.models import (  # noqa: F401
    CautionCount,
    RecordCursor,
    RecordDetail,
    RecordFilter,
    RecordSummary,
    SessionView,
    TimeBucket,
)


# ── infra status ───────────────────────────────────────────────────────────────


@dataclass(frozen=True)
class ComponentStatus:
    """One row of the `blacksea status` view. ``source`` labels how the verdict was reached so
    an *inferred* green is never mistaken for proof (the false-green trap):

    * ``direct``   — authoritative (Postgres `SELECT 1`, the brain heartbeat row).
    * ``inferred`` — a liveness guess (a TCP port is listening; edge co-located).
    * ``unit``     — an OS process-manager's own report (systemd unit status).

    ``status`` is one of ``up`` / ``down`` / ``stale`` / ``unknown``.
    """

    name: str
    status: str
    source: str
    detail: str


@dataclass(frozen=True)
class InfraStatus:
    """The whole `blacksea status` roll-up: every component plus system counts, plus the
    per-daemon PID/log view (`dev-status.sh`'s report, ported to `console/supervisor.py`). The
    counts are ``None`` when Postgres is unreachable (so the view distinguishes "zero" from
    "couldn't ask"); ``daemons`` is empty on a host that has never run `blacksea up`."""

    components: list[ComponentStatus]
    bait_count: int | None = None
    instance_count: int | None = None
    event_count: int | None = None
    last_event_ms: int | None = None
    daemons: list["DaemonStatus"] = field(default_factory=list)


# ── baits show roll-up ─────────────────────────────────────────────────────────


@dataclass(frozen=True)
class BaitShow:
    """`baits show <bait_id>`: the design catalog row + its parsed manifest + its instances +
    where its build artifacts live — the "one view" O5 asked for, joined by ID."""

    bait_id: str
    version: str
    status: str
    assurance_tier: int
    deploy_class: str
    default_channel: str
    test: bool
    listener_hash: str | None
    bait_dir: str
    registered_at: str | None
    staged_at: str | None
    burned_at: str | None
    retired_at: str | None
    manifest: dict
    instances: list[InstanceRecord]
    artifacts_dir: str            # <artifacts-root>/<bait_id>/ (the per-bait build tree)


# ── instance artifact locator ──────────────────────────────────────────────────


@dataclass(frozen=True)
class ArtifactLocation:
    """`instances artifact <token>`: where the deployable `to_stage/` output lives + the
    bundler's ready-to-run one-liner. Paths are absolute **build-host** paths (they break on
    relocation to another host — same caveat as `bait_dir`)."""

    instance_token: str
    bait_id: str
    status: str
    filename: str                 # the primary deployable in to_stage/
    sha256: str
    to_stage_dir: str             # the descriptor's output_dir (what operators ship)
    output_dir_root: str          # the timestamped build root (parent of to_stage/ + bundling_outputs/)
    ready_for_vessel: str | None  # the bundler one-liner (bundling_outputs/ready_for_vessel.txt), if present
    files: dict[str, str] = field(default_factory=dict)   # every to_stage/ file → sha256


# ── otel status ────────────────────────────────────────────────────────────────


@dataclass(frozen=True)
class OtelStatus:
    """`otel config show`: the managed `secrets/otel.env` file + whether an install-unit exists.
    ``config`` is the parsed `BS_OTEL_*` key→value map from the env file (empty if it doesn't
    exist yet)."""

    env_path: str
    exists: bool
    config: dict[str, str]
    unit_installed: bool
    unit_detail: str


# ── lifecycle: `blacksea init` result ───────────────────────────────────────────


@dataclass(frozen=True)
class InitResult:
    """The outcome of ``blacksea init``: which infra ``mode`` was chosen, where the unified
    ``config/blacksea.env`` was written, non-secret summaries of the coordinates, and whether
    external connectivity was validated. ``notes`` carries human advisories (next steps, "kept
    existing credentials", …). No secret values — the file itself holds those, ``0600``."""

    mode: str                     # "docker" | "external"
    config_path: str
    created: bool
    postgres_summary: str         # non-secret, e.g. "localhost:5432/blacksea" or a redacted DSN
    nats_summary: str
    validated: bool               # external mode: connectivity checked before saving
    notes: list[str] = field(default_factory=list)


# ── lifecycle: `up` / `down` / `reset` ──────────────────────────────────────────


@dataclass(frozen=True)
class DaemonStatus:
    """One dev daemon (``edge`` / ``brain``) under the console supervisor. ``running`` +
    ``pid`` reflect the ``.dev/<name>.pid`` file; ``action`` records what the last ``up``/``down``
    did to it (``started`` / ``unchanged`` / ``restarted`` / ``stopped`` / ``not-running``)."""

    name: str
    running: bool
    pid: int | None
    log_path: str
    action: str = ""
    detail: str = ""


@dataclass(frozen=True)
class UpResult:
    """The outcome of ``blacksea up``: which infra ``mode`` ran, the ``infra`` bring-up notes
    (compose / reachability), the daemon states, and human ``notes`` (URLs, next steps). Empty
    ``daemons`` in supervised mode (``up`` started nothing — systemd/containers own them)."""

    mode: str                     # "docker" | "external"
    infra: list[str] = field(default_factory=list)   # per-service bring-up/reachability lines
    daemons: list[DaemonStatus] = field(default_factory=list)
    notes: list[str] = field(default_factory=list)


@dataclass(frozen=True)
class DownResult:
    """The outcome of ``blacksea down``: the daemons stopped, whether infra containers were also
    taken down (``--infra`` in docker mode), and human ``notes``."""

    daemons: list[DaemonStatus] = field(default_factory=list)
    infra_stopped: bool = False
    notes: list[str] = field(default_factory=list)


@dataclass(frozen=True)
class ResetResult:
    """The outcome of ``blacksea reset``: the test-state actions performed (``cleared``) and the
    ones skipped (``skipped``, e.g. Postgres unreachable), plus human ``notes``. Creds + infra
    containers are never touched — this only wipes the *data* those services hold."""

    cleared: list[str] = field(default_factory=list)
    skipped: list[str] = field(default_factory=list)
    notes: list[str] = field(default_factory=list)


# ── effective operational config ───────────────────────────────────────────────


@dataclass(frozen=True)
class ConfigItem:
    """One effective operational setting for `config show` (read-only). ``secret`` masks the
    value in rendering so a DSN password / NATS creds never print."""

    key: str
    value: str
    secret: bool = False
