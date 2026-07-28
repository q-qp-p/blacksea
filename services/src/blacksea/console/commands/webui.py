"""web-ui — run the read-only observer web UI in the foreground (TEMPORARY stopgap).

The observer is no longer started by `blacksea up`; this top-level command lets an operator bring
it up on demand from the one `blacksea` front door. It is deliberately kept out of the user
guide (`docs/console.md`) and the README: it's a placeholder until the real web UI — which will
layer over the console facade — replaces both this command and the standalone observer module.
Facade side: `ConsoleService.observer_serve` (spawns `python -m blacksea.observer`).
"""

from __future__ import annotations

import click

from blacksea.config import settings

from .. import render


@click.command("web-ui")
@click.option("--host", default=settings.OBSERVER_HOST, show_default=True,
              help="bind address (or $OBSERVER_HOST)")
@click.option("--port", type=int, default=settings.OBSERVER_PORT, show_default=True,
              help="listen port (or $OBSERVER_PORT)")
@click.pass_obj
def web_ui(app, host, port) -> None:
    """Serve the read-only observer web UI in the foreground (Ctrl-C to stop).

    TEMPORARY: a stopgap launcher for the existing observer, kept only until the full
    console-facade-backed web UI lands. Not part of `blacksea up` — run it when you want the UI.
    """
    render.note(app.render, f"[dim]serving observer web UI on http://{host}:{port} "
                            f"(Ctrl-C to stop)…[/dim]")
    with app.service() as svc:
        code = svc.observer_serve(host=host, port=port)
    raise SystemExit(code)
