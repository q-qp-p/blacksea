"""campaigns — list/aggregate by campaign_id."""

from __future__ import annotations

import click

from .. import render


@click.group("campaigns")
def campaigns() -> None:
    """List campaigns and their instances."""


@campaigns.command("ls")
@render.json_flag
@click.pass_obj
def campaigns_ls(app) -> None:
    """List campaigns (derived from instance records — there is no campaign table)."""
    with app.service() as svc:
        rows = svc.list_campaigns()
    render.table(app.render, rows, [
        ("CAMPAIGN", "campaign"),
        ("INSTANCES", "instance_count"),
        ("BAITS", lambda c: ", ".join(c.bait_ids)),
    ], empty="(no campaigns)")
