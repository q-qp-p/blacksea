"""down — stop the app daemons this host started.

Leaves infra (Postgres/NATS) and all state untouched by default; `--infra` also takes the docker
containers down (data volume preserved). Stops the edge + brain daemons this host started.
"""

from __future__ import annotations

import click

from .. import render


@click.command("down")
@render.json_flag
@click.option("--infra", is_flag=True,
              help="also stop the Postgres + NATS containers (docker mode; data volume preserved)")
@click.pass_obj
def down(app, infra) -> None:
    """Stop the edge + brain daemons. `--infra` also stops the docker containers."""
    with app.service() as svc:
        result = svc.down(infra=infra)
    render.lifecycle_down(app.render, result)
