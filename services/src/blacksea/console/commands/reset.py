"""reset — wipe all test-generated state. Clears records, the
control-plane catalog, the material store, the brain key
directory, and the NATS backlog — but never the creds (config/blacksea.env) or the infra
containers, so there's no re-provisioning step afterward: just `blacksea up` again.

Destructive, so it confirms first. `--yes`/`-y` skips the prompt (required under `--json` or a
non-TTY, so automation never blocks on the confirmation).
"""

from __future__ import annotations

import sys

import click

from blacksea.control_plane.operations import UsageError

from .. import render


@click.command("reset")
@render.json_flag
@click.option("--yes", "-y", "assume_yes", is_flag=True,
              help="skip the confirmation prompt (required under --json / no TTY)")
@click.option("--no-purge-nats", "purge_nats", flag_value=False, default=True,
              help="leave the NATS backlog in place (only wipe Postgres + the on-disk state)")
@click.pass_obj
def reset(app, assume_yes, purge_nats) -> None:
    """Wipe registered baits + events (registry, brain key directory, Postgres, NATS backlog).

    Keeps the config/blacksea.env credentials and the Postgres/NATS containers — this only clears
    the *data* those services hold. Distinct from destroying the Postgres volume
    (`docker compose down -v`), which wipes the database itself.
    """
    interactive = not assume_yes and not app.render.json and sys.stdin.isatty()
    if not assume_yes:
        if not interactive:
            raise UsageError("reset is destructive — pass --yes to confirm (required under --json / no TTY)")
        click.echo("This permanently deletes the registry (baits/instances/artifacts), the brain "
                   "key directory,\nall Postgres records, and the NATS backlog. Creds + infra "
                   "containers are kept.")
        # Require the exact literal "yes" (matches the retired reset-state.sh's
        # `[ "$reply" != "yes" ]`) — click.confirm's y/n prompt would accept a bare "y", too
        # thin a safety net for an irreversible destructive action.
        reply = click.prompt("Type 'yes' to continue", default="", show_default=False)
        if reply != "yes":
            render.note(app.render, "aborted — nothing was changed")
            return
    with app.service() as svc:
        result = svc.reset(purge_nats=purge_nats)
    render.lifecycle_reset(app.render, result)
