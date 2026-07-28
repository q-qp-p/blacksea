"""status — the infra-status view, the Docker-`ps` analogue."""

from __future__ import annotations

import click

from .. import render


@click.command("status")
@render.json_flag
@click.pass_obj
def status(app) -> None:
    """Show whether the core infra is up and healthy.

    Reports Postgres, the brain (via its heartbeat), NATS, the edge, and the otel emitter, each
    labeled by how the verdict was reached (direct / inferred / unit) — an inferred green is never
    shown as proof. Never fails: a dead component is a red/unknown row.
    """
    with app.service() as svc:
        result = svc.infra_status()
    render.infra_status(app.render, result)
