"""up — bring the stack up, the sole stack bring-up entry point.

Docker mode drives `docker compose` for Postgres + NATS (waiting until Postgres is ready), then
starts the edge + brain as detached daemons under `.dev/`. External mode verifies the operator's
Postgres + NATS are reachable and starts nothing if they are not. Idempotent — safe to re-run.

`--infra-only` brings up just Postgres + NATS and starts no daemons — the lightweight path for
running the unit suites (`make test`), which only need a reachable database.
"""

from __future__ import annotations

import click

from .. import render


@click.command("up")
@render.json_flag
@click.option("--no-infra", "infra", flag_value=False, default=True,
              help="assume Postgres + NATS are already up; only (re)start the daemons")
@click.option("--no-build-edge", "rebuild_edge", flag_value=False, default=True,
              help="use the existing edge binary instead of rebuilding it")
@click.option("--edge-only", is_flag=True,
              help="bring up ONLY the edge (the edge host in a separate-network deploy): "
                   "no infra, no brain — the edge needs only NATS reachability")
@click.option("--infra-only", is_flag=True,
              help="bring up ONLY Postgres + NATS (no edge, no brain) — the lightweight path for "
                   "`make test`")
@click.pass_obj
def up(app, infra, rebuild_edge, edge_only, infra_only) -> None:
    """Start the stack: Postgres + NATS (docker mode) plus the edge + brain daemons.

    On a brain host with the edge on a separate network (`--edge-separate`), `up` manages the brain
    only; on the edge host, `up --edge-only` starts just the edge pointed at the remote NATS.
    `up --infra-only` starts just Postgres + NATS.
    """
    if edge_only and infra_only:
        raise click.UsageError("--edge-only and --infra-only are mutually exclusive")
    with app.service() as svc:
        result = svc.up(
            infra=infra, rebuild_edge=rebuild_edge, edge_only=edge_only, infra_only=infra_only)
    render.lifecycle_up(app.render, result)
