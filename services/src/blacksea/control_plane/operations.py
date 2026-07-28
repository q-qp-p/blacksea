"""operations.py — the CLI-agnostic lifecycle operations shared library (D2).

Every operator lifecycle verb — ``register``, ``build``, ``approve``, ``burn``, ``retire``,
``revoke`` — plus the ``list-campaigns`` aggregation lives here as a plain function that takes
a :class:`Ctx`, does the orchestration the control-plane primitives require (``ingestion`` / ``factory`` /
``lifecycle`` / ``brain_keydir``), and **returns a small result dataclass or raises a typed
error — it never prints**.

The ``blacksea`` operator console (click + rich) calls these functions and owns all human/JSON
formatting, rendering each result / typed error through its own ``render.py``. (The legacy
argparse ``python -m blacksea.control_plane`` shim that was the second frontend has been removed;
the console is the sole frontend now.)

This is the "unify without duplicating logic" rule: one implementation, one frontend.
``forge.forge_bait()`` fits the same shape (register→build→approve in one call) and is reused
as-is by the console's ``forge`` command.

Error model — the ``exit_code`` on the exception is the process exit status a frontend returns
(the console's ``render.py`` surfaces it), following the convention ``0`` ok, ``1`` operational
failure, ``2`` usage/validation:

* :class:`UsageError` (``exit_code == 2``) — bad input the operator can fix (unknown ``--refresh``
  target, un-ingestable bait dir, both/neither of ``--design``/``--instance``).
* :class:`OperationError` (``exit_code == 1``) — the request was well-formed but could not be
  applied (ingest validation errors, missing ack, no such design, illegal lifecycle transition,
  a failed build).
"""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from datetime import datetime, timezone

from blacksea.control_plane import brain_keydir, factory, lifecycle, listeners
from blacksea.control_plane.ingestion import IngestError, ingest, load_manifest
from blacksea.control_plane.registry import (
    DesignRecord,
    Registry,
    replace,
)
from blacksea.sdk.exceptions import BuildError


# ── errors ─────────────────────────────────────────────────────────────────────


class OperationError(Exception):
    """A well-formed request that could not be applied — CLI exit code 1.

    ``issues`` carries diagnostic strings a frontend should echo *before* the error
    message (used by ``register_bait`` to surface the ingest validation issues a
    frontend echoes to stderr)."""

    exit_code = 1

    def __init__(self, message: str, *, issues: list[str] | None = None) -> None:
        super().__init__(message)
        self.issues: list[str] = list(issues or [])


class UsageError(OperationError):
    """Bad operator input the caller can fix — CLI exit code 2."""

    exit_code = 2


# ── shared context ───────────────────────────────────────────────────────────


class Ctx:
    """Resolved config the ops need: the registry plus the brain key-directory / bundler paths.
    Constructed with explicit paths — the console does this from its click flags, and
    ``forge_bait`` takes the same object. There is no edge directory anymore — the edge is a dumb
    dead-drop; the brain key directory is the sole key directory."""

    def __init__(
        self,
        *,
        registry: Registry,
        brain_keydir_path: str,
        sdk_root: str,
        artifacts_root: str,
    ) -> None:
        self.registry = registry
        self.brain_keydir_path = brain_keydir_path
        self.sdk_root = sdk_root
        self.artifacts_root = artifacts_root

    def publisher(self):
        """A publish callback for the lifecycle transitions: refresh the brain key directory's
        routing fields (status/bait_id/campaign_id/... — never ``key``) after commit, so a
        burn/retire/revoke is reflected to the brain. There is no edge directory to write — the
        edge is a dumb dead-drop that resolves routing from ``tok`` itself."""

        def _publish():
            brain_keydir.sync_routing_fields(self.brain_keydir_path, self.registry)

        return _publish


# ── result dataclasses ─────────────────────────────────────────────────────────


@dataclass
class RegisterResult:
    bait_id: str
    version: str
    tier: int
    deploy_class: str
    test: bool                               # true: example/reference bait, not real intel
    refreshed: bool                          # True: reloaded manifest; False: newly staged
    warnings: list[str] = field(default_factory=list)
    issues: list[str] = field(default_factory=list)   # all ingest issues (echo to stderr)


@dataclass
class BuildResult:
    instance_token: str
    bait_id: str
    campaign: str
    status: str                              # "pending"
    artifact_filename: str
    artifact_sha256: str
    output_dir: str                          # the timestamped build root
    artifact_dir: str | None = None          # staged deployable dir (to_stage/) in the registry material store
    comment: str | None = None               # free-text operator note (descriptive only)
    warnings: list[str] = field(default_factory=list)


@dataclass
class ApproveResult:
    instance_token: str
    status: str                              # "active"
    brain_keydir_path: str                   # the brain key directory refreshed on approve


@dataclass
class BurnResult:
    kind: str                                # "design" | "instance"
    id: str
    reason: str


@dataclass
class RetireResult:
    kind: str                                # "design" | "instance"
    id: str


@dataclass
class RevokeResult:
    instance_token: str


@dataclass
class CampaignSummary:
    campaign: str
    instance_count: int
    bait_ids: list[str]                      # sorted


# ── ops ────────────────────────────────────────────────────────────────────────


def register_bait(
    ctx: Ctx,
    bait_dir: str,
    *,
    refresh: bool = False,
    ack: bool = False,
    now_iso: str | None = None,
) -> RegisterResult:
    """Ingest + validate + golden-test a bait dir, then stage it (or, with ``refresh``,
    reload the manifest for an already-registered ``bait_id``). Returns a
    ``RegisterResult`` / raises a typed error — never prints."""
    now_iso = now_iso or _now_iso()
    bait_dir = os.path.abspath(bait_dir)
    existing = {d.bait_id for d in ctx.registry.list_designs()}

    refresh_bait_id: str | None = None
    if refresh:
        try:
            refresh_bait_id = str(load_manifest(bait_dir).get("bait_id", "")) or None
        except IngestError:
            refresh_bait_id = None
        if refresh_bait_id is None or refresh_bait_id not in existing:
            raise UsageError(
                f"--refresh requires an already-registered bait_id at {bait_dir!r}")

    try:
        result = ingest(bait_dir, existing, refresh_bait_id=refresh_bait_id)
    except IngestError as exc:
        raise UsageError(f"cannot ingest {bait_dir!r}: {exc}") from exc

    issues = [str(i) for i in result.issues]
    warnings = [str(i) for i in result.warnings]

    if not result.ok:
        raise OperationError(
            f"{result.bait_id!r} blocked by {len(result.errors)} error(s)", issues=issues)

    if result.requires_ack and not ack:
        raise OperationError(
            "interactive_service requires ack (segmentation review, inv 14) — not staged",
            issues=issues)

    # Freeze the listener into the material store + hash it (O10/O11), enforcing
    # version-immutability — the brain's future code source (Phase 3).
    version = str(result.manifest.get("version", ""))
    try:
        listener_hash = listeners.freeze_and_check(
            ctx.registry, artifacts_root=ctx.artifacts_root, bait_id=result.bait_id,
            version=version, bait_dir=bait_dir, manifest=result.manifest)
    except listeners.ListenerError as exc:
        raise OperationError(str(exc), issues=issues) from exc

    if refresh:
        assert refresh_bait_id is not None
        prior = ctx.registry.get_design(refresh_bait_id)
        assert prior is not None
        design = replace(
            prior, manifest=result.manifest, bait_dir=bait_dir, listener_hash=listener_hash)
        ctx.registry.put_design(design)
        refreshed = True
    else:
        design = DesignRecord(
            bait_id=result.bait_id,
            manifest=result.manifest,
            bait_dir=bait_dir,
            status="draft",
            registered_at=now_iso,
            listener_hash=listener_hash,
        )
        ctx.registry.put_design(design)
        lifecycle.stage_design(ctx.registry, result.bait_id, now=now_iso)
        refreshed = False

    return RegisterResult(
        bait_id=result.bait_id,
        version=design.version,
        tier=design.assurance_tier,
        deploy_class=design.deploy_class,
        test=design.test,
        refreshed=refreshed,
        warnings=warnings,
        issues=issues,
    )


def build_instance_op(
    ctx: Ctx,
    *,
    bait_id: str,
    campaign: str,
    callbacks: dict[str, str],
    build_vars: dict[str, str] | None = None,
    out: str | None = None,
    comment: str | None = None,
    now_iso: str | None = None,
) -> BuildResult:
    """Factory-build a per-instance artifact (status ``pending``); persist the instance
    record and write ``_KEY`` to the brain key directory (see context.md's "Brain key
    directory — write side" section).

    ``callbacks`` and ``build_vars`` arrive already parsed (the frontend owns KEY=VALUE
    parsing so a malformed flag is a frontend usage error). ``comment`` is an optional
    free-text operator note stored on the instance (descriptive metadata only)."""
    now_iso = now_iso or _now_iso()
    design = ctx.registry.get_design(bait_id)
    if design is None:
        raise OperationError(f"no such design {bait_id!r} — register it first")
    if design.status not in ("staged", "deployed"):
        hint = (" — burned designs accept no new instances; hot-wire a new bait_id"
                if design.status == "burned" else "")
        raise OperationError(f"design {bait_id!r} is {design.status!r}, cannot build{hint}")

    # Timestamp-based artifact directory: <artifacts-root>/<bait_id>/<YYYYMMDD-HHMMSS-us>/
    timestamp = datetime.now(timezone.utc).strftime("%Y%m%d-%H%M%S-%f")
    output_dir_root = os.path.abspath(out) if out else os.path.join(
        ctx.artifacts_root, bait_id, timestamp
    )

    try:
        outcome = factory.build_instance(
            design,
            campaign_id=campaign,
            callback_addresses=callbacks,
            sdk_root=ctx.sdk_root,
            output_dir_root=output_dir_root,
            now_iso=now_iso,
            var_overrides=build_vars or {},
            comment=comment,
        )
    except BuildError as exc:
        raise OperationError(f"failed: {exc}") from exc

    ctx.registry.put_instance(outcome.instance)
    inst = outcome.instance
    # Write `_KEY` straight to the brain's key directory (see context.md's "Brain key
    # directory — write side" section) — the only place besides the
    # artifact it will ever exist. `outcome.key_hex` goes out of scope after this call.
    brain_keydir.upsert_key_entry(
        ctx.brain_keydir_path,
        instance_token_hex=inst.instance_token,
        key_hex=outcome.key_hex,
        status=inst.status,
        bait_id=inst.bait_id,
        campaign_id=inst.campaign_id,
        assurance_tier=design.assurance_tier,
        default_channel=design.default_channel,
        valid_from=0,
    )
    desc = outcome.artifact.descriptor
    return BuildResult(
        instance_token=inst.instance_token,
        bait_id=inst.bait_id,
        campaign=inst.campaign_id,
        status=inst.status,
        artifact_filename=str(desc.get("filename", "")),
        artifact_sha256=str(desc.get("sha256", "")),
        output_dir=outcome.output_dir,
        artifact_dir=inst.artifact_dir,
        comment=inst.comment,
        warnings=outcome.warnings,
    )


def approve_instance_op(
    ctx: Ctx,
    instance_token: str,
    *,
    now_iso: str | None = None,
) -> ApproveResult:
    """Approve a pending instance → active, then refresh the brain key directory: the
    instance-activate + design-promote commit atomically (O3), and the publish callback refreshes
    the brain key directory after commit (no edge snapshot anymore)."""
    now_iso = now_iso or _now_iso()

    def _publish() -> None:
        brain_keydir.sync_routing_fields(ctx.brain_keydir_path, ctx.registry)

    try:
        lifecycle.approve_instance(ctx.registry, instance_token, now=now_iso, publish=_publish)
    except lifecycle.TransitionError as exc:
        raise OperationError(str(exc)) from exc
    return ApproveResult(
        instance_token=instance_token,
        status="active",
        brain_keydir_path=ctx.brain_keydir_path,
    )


def burn(
    ctx: Ctx,
    *,
    design: str | None = None,
    instance: str | None = None,
    reason: str = "operator",
    now_iso: str | None = None,
) -> BurnResult:
    """Mark a design *or* an instance burned (key/pool kept, inv 6). Exactly one of
    ``design``/``instance`` must be given."""
    now_iso = now_iso or _now_iso()
    kind, target = _require_design_xor_instance(design, instance)
    try:
        if kind == "design":
            lifecycle.burn_design(
                ctx.registry, target, reason=reason, now=now_iso, publish=ctx.publisher())
        else:
            lifecycle.burn_instance(
                ctx.registry, target, reason=reason, now=now_iso, publish=ctx.publisher())
    except lifecycle.TransitionError as exc:
        raise OperationError(str(exc)) from exc
    return BurnResult(kind=kind, id=target, reason=reason)


def retire(
    ctx: Ctx,
    *,
    design: str | None = None,
    instance: str | None = None,
    now_iso: str | None = None,
) -> RetireResult:
    """Retire a design *or* an instance (irreversible). Exactly one of
    ``design``/``instance`` must be given."""
    now_iso = now_iso or _now_iso()
    kind, target = _require_design_xor_instance(design, instance)
    try:
        if kind == "design":
            lifecycle.retire_design(
                ctx.registry, target, now=now_iso, publish=ctx.publisher())
        else:
            lifecycle.retire_instance(
                ctx.registry, target, now=now_iso, publish=ctx.publisher())
    except lifecycle.TransitionError as exc:
        raise OperationError(str(exc)) from exc
    return RetireResult(kind=kind, id=target)


def revoke(
    ctx: Ctx,
    instance_token: str,
    *,
    now_iso: str | None = None,
) -> RevokeResult:
    """Revoke an instance key (weaponized; heavy-sample + alert at brain)."""
    now_iso = now_iso or _now_iso()
    try:
        lifecycle.revoke_instance(
            ctx.registry, instance_token, now=now_iso, publish=ctx.publisher())
    except lifecycle.TransitionError as exc:
        raise OperationError(str(exc)) from exc
    return RevokeResult(instance_token=instance_token)


def list_campaigns(registry: Registry) -> list[CampaignSummary]:
    """Derive per-campaign summaries from the instance records (there is no campaign
    record; ``campaign_id`` stays backend-only). Returned sorted by campaign."""
    by_campaign: dict[str, dict[str, object]] = {}
    for i in registry.list_instances():
        agg = by_campaign.setdefault(i.campaign_id, {"count": 0, "baits": set()})
        agg["count"] = int(agg["count"]) + 1                # type: ignore[arg-type]
        agg["baits"].add(i.bait_id)                         # type: ignore[union-attr]
    return [
        CampaignSummary(
            campaign=campaign,
            instance_count=int(agg["count"]),               # type: ignore[arg-type]
            bait_ids=sorted(agg["baits"]),                  # type: ignore[arg-type]
        )
        for campaign, agg in sorted(by_campaign.items())
    ]


# ── helpers ──────────────────────────────────────────────────────────────────


def _require_design_xor_instance(design: str | None, instance: str | None) -> tuple[str, str]:
    """Return ``("design", bait_id)`` or ``("instance", token)``; raise ``UsageError``
    unless exactly one of the two is provided (burn/retire take one target)."""
    if bool(design) == bool(instance):
        raise UsageError("specify exactly one of --design or --instance")
    if design:
        return "design", design
    assert instance is not None
    return "instance", instance


def parse_kv(items: list[str] | None, flag: str) -> dict[str, str]:
    """Parse repeated ``KEY=VALUE`` flag values into a dict. Raises ``ValueError`` on a
    malformed item (the frontend maps that to its usage-error exit code). Shared by both
    frontends so ``--callback`` / ``--set`` parse identically."""
    out: dict[str, str] = {}
    for item in items or []:
        if "=" not in item:
            raise ValueError(f"{flag} must be KEY=VALUE, got {item!r}")
        key, _, value = item.partition("=")
        key = key.strip()
        if not key:
            raise ValueError(f"{flag} has empty key in {item!r}")
        out[key] = value
    return out


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()
