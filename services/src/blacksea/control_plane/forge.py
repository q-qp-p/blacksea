"""forge.py — one-shot ``register → build → approve`` from a self-sufficient manifest.

``forge`` collapses the three lifecycle steps a bait needs to become a live, deployable
instance into a single call driven entirely by ``manifest.yaml`` — no per-bait shell script
hand-rolling that chain (manual testing just runs ``blacksea forge <manifest>`` directly). The
deploy-time parameters that used to be supplied out-of-band on the ``build`` command
line (``campaign``, ``--callback``, ``--set``) now live in a ``deploy:`` block in the manifest,
so ``forge manifest.yaml`` is self-sufficient; CLI flags still override the block for local
testing.

The orchestration lives in the CLI-agnostic ``forge_bait()`` library function — no argparse,
no printing — so the ``blacksea`` operator console (``blacksea/console/``) wraps it with a thin
``forge`` command instead of re-implementing the chain (console context.md: "delegate to
control_plane/, never duplicate logic"). ``forge_bait`` is the *sole* forge entry point: there
is no standalone argparse script anymore — run it via ``blacksea forge``. It
reuses the same primitives ``operations.py`` drives: ``ingestion.ingest`` →
``factory.build_instance`` → ``brain_keydir.upsert_key_entry`` → ``lifecycle.approve_instance``
→ ``brain_keydir.sync_routing_fields``, and takes the same ``operations.Ctx`` the console builds.
"""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from datetime import datetime, timezone

from blacksea.control_plane import brain_keydir, factory, lifecycle, listeners
from blacksea.control_plane.ingestion import IngestError, ingest, load_manifest
from blacksea.control_plane.operations import Ctx
from blacksea.control_plane.registry import DesignRecord, replace
from blacksea.sdk.exceptions import BuildError


class ForgeError(Exception):
    """A blocking failure while forging — bad deploy config, ingest errors, a
    failed build, or a lifecycle transition that could not be applied."""


# ── deploy config ──────────────────────────────────────────────────────────────


@dataclass
class DeployConfig:
    """The deploy-time parameters ``forge`` needs beyond the design manifest.

    Sourced from the manifest's ``deploy:`` block, with any CLI overrides layered
    on top (CLI wins). ``callbacks`` maps channel → callback address (feeds the
    factory's standard ``_ZONE``/``_SERVER_URL`` build vars); ``build_vars`` are
    overrides for author-chosen names the factory cannot auto-resolve (== ``--set``)."""

    campaign: str
    callbacks: dict[str, str]
    build_vars: dict[str, str] = field(default_factory=dict)
    approve: bool = True
    comment: str | None = None               # free-text operator note (descriptive only)


def load_deploy_config(
    manifest: dict,
    *,
    cli_campaign: str | None = None,
    cli_callbacks: dict[str, str] | None = None,
    cli_set: dict[str, str] | None = None,
    cli_comment: str | None = None,
    no_approve: bool = False,
) -> DeployConfig:
    """Build (and validate) a ``DeployConfig`` from the manifest's ``deploy:`` block,
    with CLI overrides layered on top. Raises ``ForgeError`` on any missing required
    field — never a silent pass (mirrors ``ingestion.py``)."""
    deploy = manifest.get("deploy") or {}
    if not isinstance(deploy, dict):
        raise ForgeError("manifest `deploy:` must be a mapping")

    campaign = cli_campaign or deploy.get("campaign")
    # CLI callbacks override the manifest per channel (so e2e can repoint https at
    # 127.0.0.1 without editing the manifest).
    callbacks = {**(deploy.get("callbacks") or {}), **(cli_callbacks or {})}
    build_vars = {**(deploy.get("build_vars") or {}), **(cli_set or {})}
    approve = False if no_approve else bool(deploy.get("approve", True))
    # CLI comment overrides a manifest `deploy.comment` (an explicit empty string wins too).
    comment = cli_comment if cli_comment is not None else deploy.get("comment")

    if not campaign:
        raise ForgeError(
            "no campaign — declare `deploy.campaign` in the manifest or pass --campaign")

    channels = manifest.get("channels") or {}
    missing = [ch for ch in channels if ch not in callbacks]
    if missing:
        raise ForgeError(
            f"no callback address for declared channel(s) {sorted(missing)} — add them under "
            f"`deploy.callbacks` or pass --callback CH=ADDR")

    return DeployConfig(
        campaign=str(campaign),
        callbacks=dict(callbacks),
        build_vars=dict(build_vars),
        approve=approve,
        comment=(str(comment) if comment else None),
    )


# ── result ─────────────────────────────────────────────────────────────────────


@dataclass
class ForgeResult:
    bait_id: str
    instance_token: str
    campaign: str
    status: str                 # "active" (approved) or "pending" (--no-approve)
    artifact_path: str          # primary artifact in to_stage/, ready to deploy
    output_dir: str             # the timestamped build root
    comment: str | None = None  # free-text operator note (descriptive only)
    warnings: list[str] = field(default_factory=list)


# ── orchestration (library — no argparse, no print) ─────────────────────────────


def forge_bait(
    ctx: Ctx,
    bait_dir: str,
    deploy: DeployConfig,
    *,
    ack: bool = False,
    now_iso: str | None = None,
) -> ForgeResult:
    """Register-or-refresh, build a fresh instance, and (unless ``deploy.approve`` is
    False) approve + publish it — the full hot-deploy chain in one call.

    Reuses the same module primitives ``operations.py`` drives, so behavior matches the
    piecewise ``register``/``build``/``approve`` ops exactly. Returns a ``ForgeResult``;
    raises ``ForgeError`` on any blocking failure."""
    now_iso = now_iso or _now_iso()
    bait_dir = os.path.abspath(bait_dir)

    # ── register-or-refresh (mirrors operations.register_bait) ──────────────────
    existing = {d.bait_id for d in ctx.registry.list_designs()}
    try:
        bait_id = str(load_manifest(bait_dir).get("bait_id", "")) or None
    except IngestError as exc:
        raise ForgeError(f"cannot read manifest in {bait_dir!r}: {exc}") from exc
    if bait_id is None:
        raise ForgeError(f"manifest in {bait_dir!r} has no bait_id")

    is_refresh = bait_id in existing
    try:
        result = ingest(bait_dir, existing, refresh_bait_id=bait_id if is_refresh else None)
    except IngestError as exc:
        raise ForgeError(f"cannot ingest {bait_dir!r}: {exc}") from exc

    warnings = [str(i) for i in result.warnings]
    if not result.ok:
        errs = "\n".join(str(i) for i in result.errors)
        raise ForgeError(f"{result.bait_id!r} blocked by {len(result.errors)} error(s):\n{errs}")
    if result.requires_ack and not ack:
        raise ForgeError(
            "interactive_service requires ack (segmentation review, inv 14) — pass ack=True")

    # Freeze the listener into the material store + hash it (O10/O11), enforcing
    # version-immutability — the brain's future code source (Phase 3).
    version = str(result.manifest.get("version", ""))
    try:
        listener_hash = listeners.freeze_and_check(
            ctx.registry, artifacts_root=ctx.artifacts_root, bait_id=result.bait_id,
            version=version, bait_dir=bait_dir, manifest=result.manifest)
    except listeners.ListenerError as exc:
        raise ForgeError(str(exc)) from exc

    if is_refresh:
        prior = ctx.registry.get_design(result.bait_id)
        assert prior is not None
        ctx.registry.put_design(replace(
            prior, manifest=result.manifest, bait_dir=bait_dir, listener_hash=listener_hash))
    else:
        ctx.registry.put_design(DesignRecord(
            bait_id=result.bait_id,
            manifest=result.manifest,
            bait_dir=bait_dir,
            status="draft",
            registered_at=now_iso,
            listener_hash=listener_hash,
        ))
        lifecycle.stage_design(ctx.registry, result.bait_id, now=now_iso)

    design = ctx.registry.get_design(result.bait_id)
    assert design is not None

    # ── build (mirrors operations.build_instance_op) ────────────────────────────
    timestamp = datetime.now(timezone.utc).strftime("%Y%m%d-%H%M%S-%f")
    output_dir_root = os.path.join(ctx.artifacts_root, design.bait_id, timestamp)
    try:
        outcome = factory.build_instance(
            design,
            campaign_id=deploy.campaign,
            callback_addresses=deploy.callbacks,
            sdk_root=ctx.sdk_root,
            output_dir_root=output_dir_root,
            now_iso=now_iso,
            var_overrides=deploy.build_vars,
            comment=deploy.comment,
        )
    except BuildError as exc:
        raise ForgeError(f"build failed: {exc}") from exc
    warnings.extend(outcome.warnings)

    ctx.registry.put_instance(outcome.instance)
    inst = outcome.instance
    # Write `_KEY` straight to the brain's key directory (see context.md's "Brain key directory —
    # write side" section) — same call the build op makes.
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
    artifact_path = os.path.join(str(desc.get("output_dir", "")), str(desc.get("filename", "")))
    status = inst.status

    # ── approve + publish (mirrors operations.approve_instance_op) ──────────────
    if deploy.approve:
        def _publish() -> None:
            brain_keydir.sync_routing_fields(ctx.brain_keydir_path, ctx.registry)

        try:
            lifecycle.approve_instance(
                ctx.registry, inst.instance_token, now=now_iso, publish=_publish)
        except lifecycle.TransitionError as exc:
            raise ForgeError(f"approve failed: {exc}") from exc
        status = "active"

    return ForgeResult(
        bait_id=design.bait_id,
        instance_token=inst.instance_token,
        campaign=inst.campaign_id,
        status=status,
        artifact_path=artifact_path,
        output_dir=outcome.output_dir,
        comment=inst.comment,
        warnings=warnings,
    )


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()
