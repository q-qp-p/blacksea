"""baits — designs: ls / show / register."""

from __future__ import annotations

import click

from .. import render

_LS_COLUMNS = [
    ("BAIT_ID", "bait_id"),
    ("VER", "version"),
    ("STATUS", "status"),
    ("TIER", "assurance_tier"),
    ("TEST", "test"),
    ("DEPLOY_CLASS", "deploy_class"),
]


@click.group("baits")
def baits() -> None:
    """List and register bait designs (the control-plane catalog)."""


@baits.command("ls")
@render.json_flag
@click.pass_obj
def baits_ls(app) -> None:
    """List registered designs."""
    with app.service() as svc:
        rows = svc.list_baits()
    render.table(app.render, rows, _LS_COLUMNS, empty="(no baits registered)")


@baits.command("show")
@render.json_flag
@click.argument("bait_id")
@click.pass_obj
def baits_show(app, bait_id) -> None:
    """Roll-up for one design: catalog row + manifest + instances + artifacts dir."""
    with app.service() as svc:
        show = svc.get_bait(bait_id)
    if app.render.json:
        render.print_json(show)
        return
    render.detail(app.render, show, [
        ("bait_id", "bait_id"),
        ("version", "version"),
        ("status", "status"),
        ("tier", "assurance_tier"),
        ("deploy_class", "deploy_class"),
        ("default_channel", "default_channel"),
        ("test", "test"),
        ("listener_hash", "listener_hash"),
        ("bait_dir", "bait_dir"),
        ("artifacts_dir", "artifacts_dir"),
        ("registered_at", "registered_at"),
        ("staged_at", "staged_at"),
        ("burned_at", "burned_at"),
        ("retired_at", "retired_at"),
    ], title=f"bait {show.bait_id}")
    render.table(app.render, show.instances, [
        ("INSTANCE_TOKEN", "instance_token"),
        ("STATUS", "status"),
        ("CAMPAIGN", "campaign_id"),
        ("VER", "bait_version"),
        ("COMMENT", "comment"),
        ("TO_STAGE_DIR", "artifact_dir"),
    ], title="instances", empty="(no instances)")


@baits.command("register")
@render.json_flag
@click.argument("manifest")
@click.option("--refresh", is_flag=True,
              help="reload manifest from disk for an already-registered bait_id")
@click.option("--ack", is_flag=True,
              help="acknowledge interactive_service segmentation (inv 14)")
@click.pass_obj
def baits_register(app, manifest, refresh, ack) -> None:
    """Ingest + validate + golden-test a bait MANIFEST (path to manifest.yaml or its
    directory), then stage it."""
    with app.service() as svc:
        result = svc.register(manifest, refresh=refresh, ack=ack)
    for w in result.warnings:
        render.note(app.render, w)
    verb = "refreshed" if result.refreshed else "registered + staged"
    tag = ", TEST BAIT" if result.test else ""
    render.message(
        app.render, result,
        f"{verb} [bold]{result.bait_id}[/bold] v{result.version} "
        f"(tier {result.tier}, {result.deploy_class}{tag})")
