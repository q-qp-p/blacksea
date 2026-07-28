"""sessions — read-time session grouping.

**Always registered** (unlike actors/drafts/replay): `sessions ls` works today off
`reader.session_views` (a best-effort SQL `GROUP BY (instance_token, session_id)`), and upgrades
to read `session_records` once the stateful correlation engine lands — no command-surface change.
"""

from __future__ import annotations

import click

from .. import render
from ._common import record_filter


@click.group("sessions")
def sessions() -> None:
    """List read-time session groupings."""


@sessions.command("ls")
@render.json_flag
@click.option("--bait", help="filter by bait_id")
@click.option("--instance", help="filter by instance_token")
@click.option("--campaign", help="filter by campaign_id")
@click.option("--limit", type=int, default=100, show_default=True)
@click.option("--offset", type=int, default=0, show_default=True)
@click.pass_obj
def sessions_ls(app, bait, instance, campaign, limit, offset) -> None:
    """List sessions (read-time grouping of records sharing instance_token + session_id)."""
    filt = record_filter(bait_id=bait, instance_token=instance, campaign_id=campaign)
    with app.service() as svc:
        rows = svc.sessions(filt, limit=limit, offset=offset)
    render.table(app.render, rows, [
        ("SESSION", "session_record_id"),
        ("BAIT", "bait_id"),
        ("CAMPAIGN", "campaign_id"),
        ("EVENTS", "event_count"),
        ("CAUTION", "caution_level"),
        ("SRC_IPS", lambda s: ", ".join(s.source_ips)),
        ("SIG_ALL", "sig_valid_all"),
    ], empty="(no sessions)")
