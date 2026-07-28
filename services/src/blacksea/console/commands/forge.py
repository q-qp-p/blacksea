"""forge — one-shot register → build → approve from a manifest.

``--json`` preserves ``artifact_path`` — the e2e harness (`e2e_tests/lib.sh`)
parses a ``^{``-anchored line for it. In human mode, the summary is followed by the same
``instances artifact <token>`` detail (every staged file, not just the primary one) so an
operator never has to run a follow-up command to see it.
"""

from __future__ import annotations

import click

from .. import render
from ._common import kv, resolve_comment, show_artifact_after


@click.command("forge")
@render.json_flag
@click.argument("manifest")
@click.option("--campaign", help="override deploy.campaign")
@click.option("--callback", "callbacks", multiple=True, metavar="CH=ADDR",
              help="override a deploy.callbacks channel, e.g. https=http://127.0.0.1:8443")
@click.option("--set", "set_vars", multiple=True, metavar="NAME=VALUE",
              help="override/supply a build_var (== control-plane build --set)")
@click.option("--comment", default=None,
              help="free-text note stored on the instance (descriptive only). Omit to be prompted; "
                   "empty is fine")
@click.option("--no-approve", is_flag=True,
              help="stop at a pending instance instead of approving + publishing")
@click.option("--ack", is_flag=True, help="acknowledge interactive_service segmentation (inv 14)")
@click.pass_obj
def forge(app, manifest, campaign, callbacks, set_vars, comment, no_approve, ack) -> None:
    """Forge a deployable instance from a MANIFEST (path to manifest.yaml or its directory)."""
    cb = kv(list(callbacks), "--callback")
    sv = kv(list(set_vars), "--set")
    note = resolve_comment(comment, json_mode=app.render.json)
    with app.service() as svc:
        result = svc.forge(
            manifest, campaign=campaign, callbacks=cb, build_vars=sv, comment=note,
            no_approve=no_approve, ack=ack)
        for w in result.warnings:
            render.note(app.render, w)
        comment_line = f"\n  comment: {result.comment}" if result.comment else ""
        render.message(
            app.render, result,
            f"forged instance [bold]{result.instance_token}[/bold] of {result.bait_id!r} "
            f"(campaign {result.campaign!r}, status {result.status}){comment_line}")
        show_artifact_after(app, svc, result.instance_token)
