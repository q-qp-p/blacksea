"""service.py — **the console facade**, the well-defined interface.

"The API" is one in-process Python facade. The CLI (`cli.py`/`commands/*`) consumes it now; a
FastAPI/HTTP skin and the reworked observer web UI layer over the *same* facade later. It:

* **calls the existing shared building blocks** — `control_plane.operations` / `forge` (writes),
  `control_plane.registry.Registry` (catalog reads), `correlation.reader` sync variants
  (records/sessions/health), `blacksea.config.settings` (config), and `otel_ctl` (otel control) —
  duplicating no leaf logic ("the API = one well-defined interface", the request's principle);
* **returns the existing module dataclasses** plus the few composite ones in `models.py`
  (`InfraStatus`, `BaitShow`, `ArtifactLocation`, `OtelStatus`) — no re-wrap layer;
* **raises typed exceptions** (`operations`' `OperationError`/`UsageError`, `forge`'s `ForgeError`,
  `registry`'s `CatalogUnavailableError`, plus read errors wrapped as `OperationError`) — it never
  swallows a failure as an empty result the way `ObserverService` does today;
* is **sync** and opens its **own** Postgres connection(s) per invocation (`Registry` opens one
  too, so ~2 sync connections; fine for a CLI — see the connection-debt note in `context.md`).

**Facade purity:** this module imports **no click, no rich, no Pydantic** — only
`cli.py`/`commands/*`/`render.py` do. It takes its config as an explicit :class:`ConsoleConfig`
(never reads click). Locked by ``tests/console/test_purity.py``.
"""

from __future__ import annotations

import os
import subprocess
import sys
from dataclasses import dataclass
from typing import Any

import psycopg

from blacksea.config import settings
from blacksea.control_plane import operations
from blacksea.control_plane.forge import (
    ForgeError,
    ForgeResult,
    forge_bait,
    load_deploy_config,
)
from blacksea.control_plane.ingestion import IngestError, load_manifest
from blacksea.control_plane.operations import (
    ApproveResult,
    BuildResult,
    BurnResult,
    CampaignSummary,
    OperationError,
    RegisterResult,
    RetireResult,
    RevokeResult,
    UsageError,
)
from blacksea.control_plane.registry import DesignRecord, InstanceRecord, Registry
from blacksea.correlation import reader
from blacksea.correlation.models import (
    CautionCount,
    RecordCursor,
    RecordDetail,
    RecordFilter,
    RecordSummary,
    SessionView,
    TimeBucket,
)

from . import lifecycle, probes, supervisor
from .models import (
    ArtifactLocation,
    BaitShow,
    ComponentStatus,
    ConfigItem,
    DaemonStatus,
    DownResult,
    InfraStatus,
    InitResult,
    OtelStatus,
    ResetResult,
    UpResult,
)
from .otel_ctl import OtelControl


# ── facade config (its own Ctx-like object — never reads click) ───────────────


@dataclass
class ConsoleConfig:
    """Everything the facade needs, resolved by the CLI from its global flags / env / defaults
    and handed in explicitly. The facade reads config from here, never from click — so the
    future web UI can construct it the same way."""

    postgres_dsn: str
    postgres_dsn_source: str | None = None   # secrets/env path if the DSN came from a file (else flag/env)
    registry_root: str = settings.BS_REGISTRY
    schema: str = settings.BS_CP_SCHEMA
    brain_keydir_path: str = settings.BRAIN_KEYDIR
    artifacts_root: str = settings.BS_ARTIFACTS_ROOT
    sdk_root: str = settings.BS_SDK_ROOT
    otel_env_path: str = "secrets/otel.env"
    otel_unit_path: str = "secrets/blacksea-otel.service"
    nats_url: str = settings.NATS_URL
    edge_dns_addr: str | None = None
    edge_https_addr: str | None = None
    edge_co_located: bool = True
    heartbeat_stale_s: float = settings.BRAIN_HEARTBEAT_STALE_S
    # ── lifecycle supervisor (blacksea up/down/logs/reset — step 3) ──
    infra_mode: str = settings.BS_INFRA               # docker | external (the BS_INFRA switch)
    daemons_mode: str = settings.BS_DAEMONS           # blacksea | supervised (external mode)
    config_path: str | None = settings.BS_CONFIG_PATH  # the loaded config/blacksea.env (for compose --env-file)
    dev_dir: str = settings.BS_DEV_DIR                 # .dev/ supervisor state dir
    edge_dir: str = settings.EDGE_DIR                  # edge Go module dir (for `go build`)
    edge_bin: str = settings.EDGE_BIN                  # built edge binary path
    edge_id: str = settings.EDGE_ID
    edge_dns_zones: str = settings.EDGE_DNS_ZONES
    nats_user: str | None = settings.NATS_USER
    nats_pass: str | None = settings.NATS_PASS
    nats_stream: str = settings.NATS_STREAM

    @classmethod
    def from_settings(cls, **overrides: Any) -> "ConsoleConfig":
        """Build from `blacksea.config.settings` defaults, with explicit overrides on top."""
        base = dict(
            postgres_dsn=settings.POSTGRES_DSN or "",
            registry_root=settings.BS_REGISTRY,
            schema=settings.BS_CP_SCHEMA,
            brain_keydir_path=settings.BRAIN_KEYDIR,
            artifacts_root=settings.BS_ARTIFACTS_ROOT,
            sdk_root=settings.BS_SDK_ROOT,
            nats_url=settings.NATS_URL,
        )
        base.update({k: v for k, v in overrides.items() if v is not None})
        return cls(**base)


class ConsoleService:
    """The in-process facade. Construct with a :class:`ConsoleConfig`, call methods, then
    :meth:`close`. Not thread-safe (a CLI invocation is single-threaded); one instance per
    invocation."""

    def __init__(self, config: ConsoleConfig) -> None:
        self.config = config
        self._registry = Registry(
            config.postgres_dsn, registry_root=config.registry_root, schema=config.schema,
            auto_ensure=True)
        self._ctx = operations.Ctx(
            registry=self._registry,
            brain_keydir_path=config.brain_keydir_path,
            sdk_root=config.sdk_root,
            artifacts_root=config.artifacts_root,
        )
        self._conn: psycopg.Connection | None = None
        self._attribution_present: bool | None = None

    # ── connection lifecycle ────────────────────────────────────────────────────

    def _read_conn(self) -> psycopg.Connection:
        """The facade's own read connection (records/sessions/health/status), opened lazily and
        reused for the invocation. Raises :class:`OperationError` (exit 1) if Postgres is
        unreachable — so a read failure is a non-zero exit with a clear message, never an empty
        table."""
        if not self.config.postgres_dsn:
            raise OperationError(
                "no Postgres DSN — pass --postgres, set POSTGRES_DSN, or run `make init` "
                "(writes config/blacksea.env)")
        if self._conn is None or self._conn.closed:
            try:
                self._conn = psycopg.connect(self.config.postgres_dsn, autocommit=True)
            except psycopg.Error as exc:
                raise OperationError(f"cannot connect to Postgres: {exc}") from exc
        return self._conn

    def _try_read_conn(self) -> tuple["psycopg.Connection | None", Exception | None]:
        """Best-effort connection for :meth:`infra_status` — returns ``(conn, None)`` or
        ``(None, exc)`` instead of raising, so status can *report* Postgres down."""
        try:
            return self._read_conn(), None
        except OperationError as exc:
            return None, exc

    def close(self) -> None:
        if self._conn is not None and not self._conn.closed:
            self._conn.close()
        self._conn = None
        self._registry.close()

    def __enter__(self) -> "ConsoleService":
        return self

    def __exit__(self, *exc: object) -> None:
        self.close()

    # ── lifecycle writes (delegate to operations / forge) ───────────────────────

    def register(
        self, manifest_or_dir: str, *, refresh: bool = False, ack: bool = False,
    ) -> RegisterResult:
        """Ingest + validate + golden-test a bait, then stage it. Accepts either a
        ``manifest.yaml`` path or the bait directory containing it (mirrors `forge`)."""
        bait_dir = _resolve_bait_dir(manifest_or_dir)
        return operations.register_bait(self._ctx, bait_dir, refresh=refresh, ack=ack)

    def build(
        self, *, bait_id: str, campaign: str, callbacks: dict[str, str],
        build_vars: dict[str, str] | None = None, out: str | None = None,
        comment: str | None = None,
    ) -> BuildResult:
        return operations.build_instance_op(
            self._ctx, bait_id=bait_id, campaign=campaign, callbacks=callbacks,
            build_vars=build_vars, out=out, comment=comment)

    def approve(self, instance_token: str) -> ApproveResult:
        return operations.approve_instance_op(self._ctx, instance_token)

    def burn(self, *, design: str | None = None, instance: str | None = None,
             reason: str = "operator") -> BurnResult:
        return operations.burn(self._ctx, design=design, instance=instance, reason=reason)

    def retire(self, *, design: str | None = None, instance: str | None = None) -> RetireResult:
        return operations.retire(self._ctx, design=design, instance=instance)

    def revoke(self, instance_token: str) -> RevokeResult:
        return operations.revoke(self._ctx, instance_token)

    def forge(
        self, manifest_or_dir: str, *, campaign: str | None = None,
        callbacks: dict[str, str] | None = None, build_vars: dict[str, str] | None = None,
        comment: str | None = None, no_approve: bool = False, ack: bool = False,
    ) -> ForgeResult:
        """One-shot register → build → approve from a manifest. Loads the manifest's
        ``deploy:`` block and layers the CLI overrides on top, then drives `forge_bait`. ``comment``
        is an optional free-text operator note stored on the forged instance (descriptive only).
        Raises `ForgeError` (blocking) / `UsageError` (bad deploy config)."""
        bait_dir = _resolve_bait_dir(manifest_or_dir)
        try:
            manifest = load_manifest(bait_dir)
        except IngestError as exc:
            raise UsageError(f"cannot read manifest in {bait_dir!r}: {exc}") from exc
        try:
            deploy = load_deploy_config(
                manifest, cli_campaign=campaign, cli_callbacks=callbacks,
                cli_set=build_vars, cli_comment=comment, no_approve=no_approve)
        except ForgeError as exc:
            raise UsageError(str(exc)) from exc
        return forge_bait(self._ctx, bait_dir, deploy, ack=ack)

    # ── catalog reads (delegate to Registry) ────────────────────────────────────

    def list_baits(self) -> list[DesignRecord]:
        return self._registry.list_designs()

    def get_bait(self, bait_id: str) -> BaitShow:
        design = self._registry.get_design(bait_id)
        if design is None:
            raise OperationError(f"no such bait {bait_id!r}")
        instances = self._registry.list_instances(bait_id=bait_id)
        return BaitShow(
            bait_id=design.bait_id,
            version=design.version,
            status=design.status,
            assurance_tier=design.assurance_tier,
            deploy_class=design.deploy_class,
            default_channel=design.default_channel,
            test=design.test,
            listener_hash=design.listener_hash,
            bait_dir=design.bait_dir,
            registered_at=design.registered_at,
            staged_at=design.staged_at,
            burned_at=design.burned_at,
            retired_at=design.retired_at,
            manifest=design.manifest,
            instances=instances,
            artifacts_dir=os.path.join(self.config.artifacts_root, design.bait_id),
        )

    def list_instances(
        self, *, bait_id: str | None = None, campaign: str | None = None,
        status: str | None = None,
    ) -> list[InstanceRecord]:
        rows = self._registry.list_instances(bait_id=bait_id)
        if campaign is not None:
            rows = [i for i in rows if i.campaign_id == campaign]
        if status is not None:
            rows = [i for i in rows if i.status == status]
        return rows

    def get_instance(self, instance_token: str) -> InstanceRecord:
        inst = self._registry.get_instance(instance_token)
        if inst is None:
            raise OperationError(f"no such instance {instance_token!r}")
        return inst

    def list_campaigns(self) -> list[CampaignSummary]:
        return operations.list_campaigns(self._registry)

    def instance_artifact(self, instance_token: str) -> ArtifactLocation:
        """Locate an instance's deployable `to_stage/` output + the bundler one-liner."""
        inst = self.get_instance(instance_token)
        raw = inst.artifact or {}
        # The instance stores the full Artifact envelope ({artifact_type, descriptor}); unwrap to
        # the descriptor, but tolerate a bare descriptor too.
        desc = raw.get("descriptor", raw) if isinstance(raw, dict) else {}
        if not desc:
            raise OperationError(
                f"instance {instance_token!r} has no artifact descriptor "
                f"(status {inst.status!r}) — build it first")
        output_dir_root = str(desc.get("output_dir_root", ""))
        ready = _read_ready_for_vessel(output_dir_root)
        return ArtifactLocation(
            instance_token=inst.instance_token,
            bait_id=inst.bait_id,
            status=inst.status,
            filename=str(desc.get("filename", "")),
            sha256=str(desc.get("sha256", "")),
            to_stage_dir=str(desc.get("output_dir", "")),
            output_dir_root=output_dir_root,
            ready_for_vessel=ready,
            files=dict(desc.get("files", {})),
        )

    # ── record / session / health reads (delegate to correlation.reader) ────────

    def list_events(
        self, filt: RecordFilter | None = None, *,
        limit: int = settings.DEFAULT_LIMIT, offset: int = settings.DEFAULT_OFFSET,
    ) -> list[RecordSummary]:
        with _wrap_read("list events"):
            return reader.list_records(self._read_conn(), filt, limit=limit, offset=offset)

    def get_event(self, record_id: str) -> RecordDetail:
        with _wrap_read("get event"):
            rec = reader.get_record(self._read_conn(), record_id)
        if rec is None:
            raise OperationError(f"no such record {record_id!r}")
        return rec

    def events_after(
        self, cursor: RecordCursor, filt: RecordFilter | None = None, *,
        limit: int = settings.DEFAULT_LIMIT,
    ) -> list[RecordDetail]:
        """The keyset tail for `events tail` — gap-free, duplicate-free (same reader
        the otel emitter uses)."""
        with _wrap_read("tail events"):
            return reader.records_after(self._read_conn(), cursor, filt, limit=limit)

    def sessions(
        self, filt: RecordFilter | None = None, *,
        limit: int = settings.DEFAULT_LIMIT, offset: int = settings.DEFAULT_OFFSET,
    ) -> list[SessionView]:
        with _wrap_read("list sessions"):
            return reader.session_views(self._read_conn(), filt, limit=limit, offset=offset)

    def hit_rate(
        self, filt: RecordFilter | None = None, *, bucket_seconds: int = settings.HEALTH_BUCKET_S,
    ) -> list[TimeBucket]:
        with _wrap_read("hit-rate"):
            return reader.hit_rate(self._read_conn(), filt, bucket_seconds=bucket_seconds)

    def caution_distribution(self, filt: RecordFilter | None = None) -> list[CautionCount]:
        with _wrap_read("caution distribution"):
            return reader.caution_distribution(self._read_conn(), filt)

    # ── infra status ────────────────────────────────────────────────────────────

    def infra_status(self) -> InfraStatus:
        """The `blacksea status` roll-up. Never raises — a dead component becomes a
        ``down``/``unknown`` row. ``daemons`` is the per-daemon PID/log view
        (`dev-status.sh`'s report) — empty where this host has never run `blacksea up`."""
        conn, exc = self._try_read_conn()
        components: list[ComponentStatus] = [
            probes.probe_postgres(conn, exc),
            probes.probe_brain(conn, self.config.heartbeat_stale_s),
            probes.probe_nats(self.config.nats_url),
            probes.probe_edge(
                self.config.edge_dns_addr, self.config.edge_https_addr,
                self.config.edge_co_located),
            self._otel_control().status_component(),
        ]
        baits, instances, events, last_ms = probes.gather_counts(conn, self.config.schema)
        return InfraStatus(
            components=components,
            bait_count=baits, instance_count=instances,
            event_count=events, last_event_ms=last_ms,
            daemons=self.daemon_status())

    # ── lifecycle: init ──────────────────────────────────────────────────────────

    def init(
        self, *, mode: str, config_path: str | None = None, force: bool = False,
        postgres_dsn: str | None = None, nats_url: str | None = None,
        nats_user: str | None = None, nats_pass: str | None = None,
        tls_ca: str | None = None, tls_cert: str | None = None, tls_key: str | None = None,
        validate: bool = True,
    ) -> InitResult:
        """Write the unified ``config/blacksea.env`` for the chosen infra ``mode`` (``docker`` or
        ``external``). Pure file I/O + (external) a connectivity pre-check — it needs no database, so
        it works on a fresh checkout before anything is provisioned. The CLI resolves the values
        (prompting interactively); this facade method takes them explicitly. Raises
        :class:`lifecycle.InitError`."""
        mgr = lifecycle.Initializer(config_path)
        if mode == "docker":
            return mgr.init_docker(force=force)
        if mode == "external":
            return mgr.init_external(
                postgres_dsn=postgres_dsn or "", nats_url=nats_url or "",
                nats_user=nats_user, nats_pass=nats_pass,
                tls_ca=tls_ca, tls_cert=tls_cert, tls_key=tls_key,
                force=force, validate=validate)
        raise UsageError(f"unknown infra mode {mode!r} — expected 'docker' or 'external'")

    # ── lifecycle: up / down / logs / reset ──────────────────────────────────────

    def _supervisor(self) -> "supervisor.Supervisor":
        """Build the local process/infra supervisor from the resolved config. Pure construction —
        it opens no connection (the reset DB step reuses the facade's connection)."""
        c = self.config
        return supervisor.Supervisor(
            dev_dir=c.dev_dir, edge_dir=c.edge_dir, edge_bin=c.edge_bin,
            python_exe=sys.executable,
            infra_mode=c.infra_mode, daemons_mode=c.daemons_mode,
            config_path=c.config_path,
            compose_env_file=c.config_path or os.path.join(
                settings.BS_PROJECT_ROOT or ".", "config", "blacksea.env"),
            compose_file=settings.BS_COMPOSE_FILE,
            registry_root=c.registry_root, artifacts_root=c.artifacts_root, schema=c.schema,
            brain_keydir=c.brain_keydir_path,
            default_brain_keydir=settings.BRAIN_KEYDIR,  # the configured default (reset owns only this)
            nats_url=c.nats_url, nats_user=c.nats_user, nats_pass=c.nats_pass,
            nats_stream=c.nats_stream,
            edge_id=c.edge_id,
            edge_dns_addr=c.edge_dns_addr or settings.EDGE_DNS_ADDR,
            edge_dns_zones=c.edge_dns_zones,
            edge_https_addr=c.edge_https_addr or settings.EDGE_HTTPS_ADDR,
            edge_co_located=c.edge_co_located,
        )

    def _up_targets(self, edge_only: bool) -> tuple[str, ...]:
        """Which daemons THIS host brings up. Edge-only (the edge host) → just the edge; a brain
        host with the edge on a separate network (``edge_co_located=False``) → just the brain;
        co-located dev → both. Mirrors how `blacksea status` refuses to probe a separate-network
        edge — the console consistently manages only what this host owns."""
        if edge_only:
            return (supervisor.EDGE,)
        if not self.config.edge_co_located:
            return (supervisor.BRAIN,)
        return (supervisor.EDGE, supervisor.BRAIN)

    def up(self, *, infra: bool = True, rebuild_edge: bool = True, edge_only: bool = False,
           infra_only: bool = False) -> UpResult:
        """Bring up the stack: docker mode drives compose for Postgres + NATS then starts the
        daemons; external mode verifies reachability and starts nothing if it fails. ``infra_only``
        brings up just Postgres + NATS and no daemons (the lightweight path for the unit suites).
        Raises :class:`supervisor.SupervisorError`."""
        if infra_only:
            return self._supervisor().up(
                targets=(), infra=True, rebuild_edge=False, infra_only=True)
        return self._supervisor().up(
            targets=self._up_targets(edge_only), infra=infra, rebuild_edge=rebuild_edge)

    def down(self, *, infra: bool = False) -> DownResult:
        """Stop the daemons this host started; ``infra=True`` also stops the docker containers."""
        return self._supervisor().down(infra=infra)

    def daemon_status(self) -> list[DaemonStatus]:
        """The daemon-level (PID) view for a supervised host — complements `status`'s infra pane."""
        return self._supervisor().status()

    def log_files(self) -> list[str]:
        """The existing ``.dev/*.log`` files `blacksea logs` would tail (empty if nothing ran)."""
        return self._supervisor().log_files()

    def logs(self, *, follow: bool = True) -> int:
        """Tail the dev daemons' logs together (`blacksea logs`), the `docker logs -f` analogue.
        Spawns ``tail`` over the ``.dev/*.log`` files and blocks until Ctrl-C (mirrors
        `observer_serve`'s isolation). Returns the child exit code; ``0`` if there are no logs."""
        files = self.log_files()
        if not files:
            return 0
        cmd = ["tail", "-n", "+1", *(["-f"] if follow else []), *files]
        try:
            return subprocess.run(cmd).returncode  # noqa: S603 — fixed argv, resolved log paths
        except KeyboardInterrupt:
            return 0
        except FileNotFoundError as exc:
            raise OperationError("`tail` not found — cannot follow logs") from exc

    def reset(self, *, purge_nats: bool = True) -> ResetResult:
        """Wipe all test-generated state (records/catalog/material store/keydir/NATS backlog),
        keeping creds + infra (the containers and ``config/blacksea.env`` are untouched). Reuses the
        facade's Postgres connection for the DB steps (``None`` if unreachable → those steps are
        skipped, reported)."""
        conn, _ = self._try_read_conn()
        return self._supervisor().reset(conn, purge_nats=purge_nats)

    # ── otel control ────────────────────────────────────────────────────────────

    def _otel_control(self) -> OtelControl:
        return OtelControl(
            env_path=self.config.otel_env_path,
            postgres_dsn=self.config.postgres_dsn,
            unit_path=self.config.otel_unit_path,
        )

    def otel_status(self) -> OtelStatus:
        return self._otel_control().status()

    def otel_config_set(self, updates: dict[str, str]) -> OtelStatus:
        ctl = self._otel_control()
        ctl.set_values(updates)
        return ctl.status()

    def otel_run(self) -> int:
        return self._otel_control().run_foreground()

    def otel_install_unit(self, *, flavor: str = "systemd") -> str:
        return self._otel_control().install_unit(flavor=flavor)

    # ── observer web UI (TEMPORARY foreground launcher) ─────────────────────────

    def observer_serve(self, *, host: str, port: int) -> int:
        """Run the read-only observer web UI in the foreground and block until Ctrl-C.

        **Temporary stopgap.** The observer is no longer part of `blacksea up`; this lets an
        operator bring it up on demand from the one console front door until the real web UI
        (which will layer over this facade) lands. Spawns ``python -m blacksea.observer`` as a
        fresh subprocess with the console's ``POSTGRES_DSN`` + ``BS_REGISTRY`` injected — mirroring
        how `otel run` isolates the emitter — streams its logs, and returns the child's exit code.
        SIGINT reaches the child in the same process group, so Ctrl-C stops it cleanly."""
        env = dict(os.environ)
        if self.config.postgres_dsn:
            env["POSTGRES_DSN"] = self.config.postgres_dsn
        env["BS_REGISTRY"] = self.config.registry_root
        # `blacksea.observer` is importable from the editable install (`pip install -e .`); we still
        # forward THIS process's sys.path to the child via PYTHONPATH so the freshly-spawned
        # `python -m blacksea.observer` runs with the exact same import environment, even when the
        # console is invoked from an unusual interpreter/venv.
        env["PYTHONPATH"] = os.pathsep.join(p for p in sys.path if p)
        cmd = [sys.executable, "-m", "blacksea.observer",
               "--host", str(host), "--port", str(port)]
        try:
            completed = subprocess.run(cmd, env=env)  # noqa: S603 — fixed argv, no shell
        except KeyboardInterrupt:
            # The child got the same SIGINT and is shutting down; treat as a clean stop.
            return 0
        return completed.returncode

    # ── effective config ────────────────────────────────────────────────────────

    def effective_config(self) -> list[ConfigItem]:
        """The effective operational settings for `config show` — read-only (no
        general `config set`; most of `settings` is import-time and needs a restart). Secrets are
        masked."""
        c = self.config
        return [
            ConfigItem("BS_INFRA", settings.BS_INFRA),
            ConfigItem("BS_PROJECT_ROOT",
                       settings.BS_PROJECT_ROOT or "(none — not an editable install)"),
            ConfigItem("BS_CONFIG_PATH", settings.BS_CONFIG_PATH or "(none — run `make init`)"),
            ConfigItem("POSTGRES_DSN", c.postgres_dsn, secret=True),
            ConfigItem("POSTGRES_DSN_source", c.postgres_dsn_source or "flag/env"),
            ConfigItem("BS_CP_SCHEMA", c.schema),
            ConfigItem("BS_REGISTRY", c.registry_root),
            ConfigItem("BS_ARTIFACTS_ROOT", c.artifacts_root),
            ConfigItem("BS_BRAIN_KEYDIR", c.brain_keydir_path),
            ConfigItem("BS_SDK_ROOT", c.sdk_root),
            ConfigItem("NATS_URL", c.nats_url),
            ConfigItem("NATS_USER", settings.NATS_USER or "", secret=True),
            ConfigItem("NATS_PASS", "***" if settings.NATS_PASS else "", secret=True),
            ConfigItem("otel_env_path", c.otel_env_path),
            ConfigItem("BRAIN_HEARTBEAT_STALE_S", str(c.heartbeat_stale_s)),
            ConfigItem("DEFAULT_LIMIT", str(settings.DEFAULT_LIMIT)),
            ConfigItem("HEALTH_BUCKET_S", str(settings.HEALTH_BUCKET_S)),
        ]

    # ── attribution gate ────────────────────────────────────────────────────────

    def attribution_tables_present(self) -> bool:
        """Probe once whether the correlation engine's tables exist, so the CLI registers the
        `actors`/`drafts`/`replay` commands only when they can actually work. Gated
        on `session_records`; cached per invocation. Any probe failure (incl. Postgres down) →
        ``False`` — the commands stay hidden, disambiguated by `blacksea status`."""
        if self._attribution_present is not None:
            return self._attribution_present
        present = False
        conn, _ = self._try_read_conn()
        if conn is not None:
            try:
                with conn.cursor() as cur:
                    cur.execute(
                        "SELECT to_regclass('public.session_records') IS NOT NULL")
                    row = cur.fetchone()
                present = bool(row and row[0])
            except Exception:  # noqa: BLE001 — a failed probe just keeps the commands hidden
                present = False
        self._attribution_present = present
        return present


# ── module helpers ─────────────────────────────────────────────────────────────


def _resolve_bait_dir(manifest_arg: str) -> str:
    """Accept either a ``manifest.yaml`` path or the bait directory containing it (mirrors
    ``forge._resolve_bait_dir``)."""
    if os.path.isdir(manifest_arg):
        return manifest_arg
    return os.path.dirname(os.path.abspath(manifest_arg))


def _read_ready_for_vessel(output_dir_root: str) -> str | None:
    """The bundler's ready-to-run one-liner lives at
    ``<output_dir_root>/bundling_outputs/ready_for_vessel.txt`` — read it if present."""
    if not output_dir_root:
        return None
    path = os.path.join(output_dir_root, "bundling_outputs", "ready_for_vessel.txt")
    try:
        with open(path, encoding="utf-8") as fh:
            return fh.read().strip()
    except OSError:
        return None


class _wrap_read:
    """Context manager: map a psycopg read error into an `OperationError` with a clear message
    (a failed read is a non-zero exit, never a silently-empty table). Re-raises
    `OperationError` untouched (e.g. the 'no such record' from a caller)."""

    def __init__(self, what: str) -> None:
        self._what = what

    def __enter__(self) -> "_wrap_read":
        return self

    def __exit__(self, exc_type, exc, tb) -> bool:
        if exc_type is None or issubclass(exc_type, OperationError):
            return False
        if issubclass(exc_type, psycopg.Error):
            raise OperationError(f"{self._what} failed: {exc}") from exc
        return False
