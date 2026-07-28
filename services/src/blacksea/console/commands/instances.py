"""instances — per-deployment lifecycle: ls / show / build / approve / burn / retire / revoke /
artifact. Lifecycle writes delegate to `control_plane.operations`."""

from __future__ import annotations

import click

from .. import render
from ._common import kv, resolve_comment, show_artifact_after

_LS_COLUMNS = [
    ("INSTANCE_TOKEN", "instance_token"),
    ("BAIT_ID", "bait_id"),
    ("STATUS", "status"),
    ("CAMPAIGN", "campaign_id"),
    ("VER", "bait_version"),
    ("COMMENT", "comment"),
]


@click.group("instances")
def instances() -> None:
    """List, build, approve, and change the state of deployed instances."""


@instances.command("ls")
@render.json_flag
@click.option("--bait", help="filter by bait_id")
@click.option("--campaign", help="filter by campaign_id")
@click.option("--status", "status_", help="filter by lifecycle status")
@click.pass_obj
def instances_ls(app, bait, campaign, status_) -> None:
    """List instances."""
    with app.service() as svc:
        rows = svc.list_instances(bait_id=bait, campaign=campaign, status=status_)
    render.table(app.render, rows, _LS_COLUMNS, empty="(no instances)")


@instances.command("show")
@render.json_flag
@click.argument("token")
@click.pass_obj
def instances_show(app, token) -> None:
    """Show one instance."""
    with app.service() as svc:
        inst = svc.get_instance(token)
    render.detail(app.render, inst, [
        ("instance_token", "instance_token"),
        ("bait_id", "bait_id"),
        ("bait_version", "bait_version"),
        ("status", "status"),
        ("campaign_id", "campaign_id"),
        ("comment", "comment"),
        ("callback_addresses", lambda i: ", ".join(f"{k}={v}" for k, v in i.callback_addresses.items())),
        ("to_stage_dir", "artifact_dir"),
        ("key_ref", "key_ref"),
        ("listener_hash", "listener_hash"),
        ("built_at", "built_at"),
        ("approved_at", "approved_at"),
        ("burned_at", "burned_at"),
        ("retired_at", "retired_at"),
    ], title=f"instance {inst.instance_token}")


@instances.command("build")
@render.json_flag
@click.argument("bait_id")
@click.option("--campaign", required=True, help="campaign_id (compartment scope, inv 15)")
@click.option("--callback", "callbacks", multiple=True, metavar="CHANNEL=ADDR",
              help="campaign callback address, e.g. https=https://cb/beacon or dns=cb.zone")
@click.option("--set", "set_vars", multiple=True, metavar="NAME=VALUE",
              help="override/supply a build_var the factory can't auto-resolve")
@click.option("--comment", default=None,
              help="free-text note stored on the instance (descriptive only). Omit to be prompted; "
                   "empty is fine")
@click.option("--out", help="artifact output dir (default: <artifacts-root>/<bait>/<timestamp>/)")
@click.pass_obj
def instances_build(app, bait_id, campaign, callbacks, set_vars, comment, out) -> None:
    """Factory-build a per-instance artifact (status pending)."""
    cb = kv(list(callbacks), "--callback")
    sv = kv(list(set_vars), "--set")
    note = resolve_comment(comment, json_mode=app.render.json)
    with app.service() as svc:
        result = svc.build(
            bait_id=bait_id, campaign=campaign, callbacks=cb, build_vars=sv, comment=note, out=out)
        for w in result.warnings:
            render.note(app.render, w)
        comment_line = f"\n  comment: {result.comment}" if result.comment else ""
        render.message(
            app.render, result,
            f"built instance [bold]{result.instance_token}[/bold] of {result.bait_id!r} "
            f"(campaign {result.campaign!r}, status {result.status}){comment_line}")
        show_artifact_after(app, svc, result.instance_token)
        if not app.render.json:
            app.render.out.print(
                f"  approve with:  blacksea instances approve {result.instance_token}")


@instances.command("approve")
@render.json_flag
@click.argument("token")
@click.pass_obj
def instances_approve(app, token) -> None:
    """Approve a pending instance → active; refresh the brain key directory."""
    with app.service() as svc:
        result = svc.approve(token)
    render.message(
        app.render, result,
        f"approved [bold]{result.instance_token}[/bold] → active\n"
        f"  brain key directory refreshed: {result.brain_keydir_path}")


@instances.command("burn")
@render.json_flag
@click.option("--design", help="bait_id")
@click.option("--instance", help="instance token")
@click.option("--reason", default="operator", help="burn reason (for the on_burn hook)")
@click.pass_obj
def instances_burn(app, design, instance, reason) -> None:
    """Mark a design or instance burned (key/pool kept, inv 6). Give exactly one target."""
    with app.service() as svc:
        result = svc.burn(design=design, instance=instance, reason=reason)
    render.message(app.render, result, f"burned {result.kind} {result.id!r}")


@instances.command("retire")
@render.json_flag
@click.option("--design", help="bait_id")
@click.option("--instance", help="instance token")
@click.pass_obj
def instances_retire(app, design, instance) -> None:
    """Retire a design or instance (irreversible). Give exactly one target."""
    with app.service() as svc:
        result = svc.retire(design=design, instance=instance)
    render.message(app.render, result, f"retired {result.kind} {result.id!r}")


@instances.command("revoke")
@render.json_flag
@click.argument("token")
@click.pass_obj
def instances_revoke(app, token) -> None:
    """Revoke an instance key (weaponized; heavy-sample + alert at brain)."""
    with app.service() as svc:
        result = svc.revoke(token)
    render.message(
        app.render, result,
        f"revoked instance [bold]{result.instance_token}[/bold] "
        "(heavy-sample + alert at brain)")


@instances.command("artifact")
@render.json_flag
@click.argument("token")
@click.pass_obj
def instances_artifact(app, token) -> None:
    """Locate an instance's deployable to_stage/ output + the bundler one-liner."""
    with app.service() as svc:
        art = svc.instance_artifact(token)
    render.artifact_detail(app.render, art)
