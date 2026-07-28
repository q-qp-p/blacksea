"""health — hit-rate + caution-level distribution (burn-detection input)."""

from __future__ import annotations

import time
from datetime import datetime, timezone

import click

from .. import render
from ._common import record_filter


def _parse_since(since: str | None) -> int | None:
    """Parse ``--since`` as a duration (``24h`` / ``90m`` / ``3600s`` / bare seconds) into a
    ``since_ms`` = now - duration. ``None`` → no lower bound."""
    if not since:
        return None
    s = since.strip().lower()
    units = {"s": 1, "m": 60, "h": 3600, "d": 86400}
    mult = units.get(s[-1:], None)
    try:
        value = float(s[:-1]) if mult else float(s)
    except ValueError as exc:
        from blacksea.control_plane.operations import UsageError
        raise UsageError(f"--since must be like 24h / 90m / 3600s, got {since!r}") from exc
    seconds = value * (mult or 1)
    return int((time.time() - seconds) * 1000)


def _fmt_ms(ms: int) -> str:
    return datetime.fromtimestamp(ms / 1000, tz=timezone.utc).strftime("%Y-%m-%d %H:%M")


@click.command("health")
@render.json_flag
@click.option("--bait", help="scope to one bait_id")
@click.option("--since", help="lower time bound as a duration, e.g. 24h / 90m / 3600s")
@click.option("--bucket", type=int, default=3600, show_default=True,
              help="hit-rate bucket width in seconds")
@click.pass_obj
def health(app, bait, since, bucket) -> None:
    """Show hit-rate over time and the caution-level distribution (burn-detection input)."""
    filt = record_filter(bait_id=bait, since_ms=_parse_since(since))
    with app.service() as svc:
        buckets = svc.hit_rate(filt, bucket_seconds=bucket)
        caution = svc.caution_distribution(filt)
    if app.render.json:
        render.print_json({
            "hit_rate": [render.to_jsonable(b) for b in buckets],
            "caution_distribution": [render.to_jsonable(c) for c in caution],
        })
        return
    render.table(app.render, buckets, [
        ("BUCKET_START", lambda b: _fmt_ms(b.bucket_start_ms)),
        ("COUNT", "count"),
    ], title=f"hit-rate ({bucket}s buckets)", empty="(no hits in range)")
    render.table(app.render, caution, [
        ("CAUTION", "caution_level"),
        ("COUNT", "count"),
    ], title="caution distribution", empty="(no records)")
