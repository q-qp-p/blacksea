"""logs — tail the edge + brain daemon logs together, the `docker logs -f` analogue.
Blocks and follows until Ctrl-C."""

from __future__ import annotations

import sys

import click

from .. import render


@click.command("logs")
@render.json_flag
@click.option("--no-follow", "follow", flag_value=False, default=True,
              help="print the current logs and exit instead of following")
@click.pass_obj
def logs(app, follow) -> None:
    """Tail the edge + brain logs under .dev/ together (Ctrl-C to stop).

    ``--json`` prints the log file paths as a JSON array instead of streaming — there is no
    JSON form of a live tail.
    """
    with app.service() as svc:
        files = svc.log_files()
        if not files:
            if app.render.json:
                render.print_json([])
            else:
                render.note(app.render, "[dim]no dev daemon logs yet — run `blacksea up` first[/dim]")
            return
        if app.render.json:
            render.print_json(files)
            return
        code = svc.logs(follow=follow)
    if code:
        sys.exit(code)
