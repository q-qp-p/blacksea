"""events — records: ls / show / tail.

`tail` is the `docker logs -f` analogue: it seeds a keyset cursor from "now" and polls the shared
`reader.records_after` (gap-free, duplicate-free — the same tail the otel emitter uses). A record's
``details`` is attacker-controlled diagnostic data — rendered as **data**, never interpreted (inv 12).
"""

from __future__ import annotations

import json
import time
from datetime import datetime, timezone

import click

from .. import render
from ._common import record_filter

_LS_COLUMNS = [
    ("TIME", lambda r: _fmt_ms(r.edge_recv_time)),
    ("RECORD_ID", "record_id"),
    ("BAIT", "bait_id"),
    ("EVENT", "event_type"),
    ("SRC_IP", "source_ip"),
    ("SIG", lambda r: "ok" if r.sig_valid else "BAD"),
    ("CH", "channel"),
    ("TEST", "test"),
]


def _fmt_ms(ms: int | None) -> str:
    if not ms:
        return ""
    return datetime.fromtimestamp(ms / 1000, tz=timezone.utc).strftime("%Y-%m-%d %H:%M:%S")


@click.group("events")
def events() -> None:
    """List, show, and follow event records."""


@events.command("ls")
@render.json_flag
@click.option("--bait", help="filter by bait_id")
@click.option("--instance", help="filter by instance_token")
@click.option("--campaign", help="filter by campaign_id")
@click.option("--sig-valid/--no-sig-valid", "sig_valid", default=None,
              help="filter on signature validity")
@click.option("--limit", type=int, default=100, show_default=True)
@click.option("--offset", type=int, default=0, show_default=True)
@click.pass_obj
def events_ls(app, bait, instance, campaign, sig_valid, limit, offset) -> None:
    """List event records (newest first)."""
    filt = record_filter(
        bait_id=bait, instance_token=instance, campaign_id=campaign, sig_valid=sig_valid)
    with app.service() as svc:
        rows = svc.list_events(filt, limit=limit, offset=offset)
    render.table(app.render, rows, _LS_COLUMNS, empty="(no records)")


@events.command("show")
@render.json_flag
@click.argument("record_id")
@click.pass_obj
def events_show(app, record_id) -> None:
    """Show one record in full (including details, rendered as data — inv 12)."""
    with app.service() as svc:
        rec = svc.get_event(record_id)
    render.detail(app.render, rec, [
        ("record_id", "record_id"),
        ("edge_recv_time", lambda r: _fmt_ms(r.edge_recv_time)),
        ("bait_id", "bait_id"),
        ("bait_version", "bait_version"),
        ("instance_token", "instance_token"),
        ("campaign_id", "campaign_id"),
        ("session_id", "session_id"),
        ("seq_no", "seq_no"),
        ("event_type", "event_type"),
        ("source_ip", "source_ip"),
        ("source_type", "source_type"),
        ("source_ja3", "source_ja3"),
        ("channel", "channel"),
        ("sig_valid", "sig_valid"),
        ("orphan", "orphan"),
        ("instance_status", "instance_status"),
        ("design_status", "design_status"),
        ("deploy_class", "deploy_class"),
        ("assurance_tier", "assurance_tier"),
        ("test", "test"),
        ("signals", lambda r: json.dumps(r.signals) if r.signals else ""),
        ("details", lambda r: json.dumps(r.details) if r.details else ""),
        ("details_truncated", "details_truncated"),
    ], title=f"record {rec.record_id}")


@events.command("tail")
@render.json_flag
@click.option("--bait", help="filter by bait_id")
@click.option("--instance", help="filter by instance_token")
@click.option("--campaign", help="filter by campaign_id")
@click.option("--interval", type=float, default=2.0, show_default=True,
              help="poll interval in seconds")
@click.pass_obj
def events_tail(app, bait, instance, campaign, interval) -> None:
    """Follow new records live (Ctrl-C to stop). Seeds from now; prints each new record as it lands."""
    from blacksea.console.models import RecordCursor  # local import keeps facade out of module import
    filt = record_filter(bait_id=bait, instance_token=instance, campaign_id=campaign)
    cursor = RecordCursor(int(time.time() * 1000), "")
    with app.service() as svc:
        render.note(app.render, "[dim]tailing new records (Ctrl-C to stop)…[/dim]")
        try:
            while True:
                batch = svc.events_after(cursor, filt, limit=500)
                for rec in batch:
                    _print_tail_line(app, rec)
                if batch:
                    last = batch[-1]
                    cursor = RecordCursor(last.edge_recv_time, last.record_id)
                time.sleep(interval)
        except KeyboardInterrupt:
            render.note(app.render, "[dim]stopped[/dim]")


def _print_tail_line(app, rec) -> None:
    if app.render.json:
        render.print_json(rec)
        return
    sig = "[green]ok[/green]" if rec.sig_valid else "[red]BAD[/red]"
    app.render.out.print(
        f"{_fmt_ms(rec.edge_recv_time)}  {rec.record_id}  "
        f"[cyan]{rec.bait_id}[/cyan]  {rec.event_type}  {rec.source_ip}  {sig}  {rec.channel}")
