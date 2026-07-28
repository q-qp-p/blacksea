"""init — choose the infra mode once and write the unified config file.

**Entry point:** this command is `hidden=True` — the *documented* first-run entry is
**`make init`** (a thin Makefile wrapper over it). It stays a registered, invocable console command
so `make init` can call it and so a source-less (`pip`-only, no Makefile) install can still configure
itself with a direct `blacksea init`; it just no longer appears in `blacksea --help`.

``blacksea init`` picks the infra mode once: it asks the single question that forks the system —
*how should Blacksea get its Postgres + NATS?* — and writes ``config/blacksea.env`` (the one file
Make, the Python apps, docker-compose, and the console supervisor — ``blacksea up`` — all read):

* **docker** — Blacksea runs them in containers; generates (or reuses) credentials.
* **external** — connect to ones the operator runs; takes a DSN/URL/creds, validates connectivity,
  and never overwrites those credentials.

Interactive by default, but every input is flag-overridable for CI (``--docker`` / ``--external`` /
``--postgres-dsn`` / … / ``--yes``). The prompting lives here (UI); the file-writing + validation is
in the pure ``lifecycle`` module behind the facade.
"""

from __future__ import annotations

import sys

import click

from blacksea.control_plane.operations import UsageError

from .. import render


@click.command("init", hidden=True)
@render.json_flag
@click.option("--docker", "mode", flag_value="docker", default=None,
              help="Blacksea runs Postgres + NATS in containers (quickstart / dev)")
@click.option("--external", "mode", flag_value="external",
              help="connect to Postgres + NATS you run yourself (production)")
@click.option("--force", is_flag=True, help="overwrite an existing config/blacksea.env")
@click.option("--config", "config_path", default=None,
              help="config file to write (default: config/blacksea.env under the project root)")
@click.option("--yes", "-y", "assume_yes", is_flag=True,
              help="non-interactive: default to docker, never prompt")
@click.option("--postgres-dsn", "postgres_dsn", default=None, help="[external] Postgres libpq DSN")
@click.option("--nats-url", "nats_url", default=None, help="[external] NATS URL")
@click.option("--nats-user", "nats_user", default=None, help="[external] NATS username")
@click.option("--nats-pass", "nats_pass", default=None, help="[external] NATS password")
@click.option("--nats-ca", "nats_ca", default=None, help="[external] NATS TLS CA bundle path")
@click.option("--nats-cert", "nats_cert", default=None, help="[external] NATS client cert path (mTLS)")
@click.option("--nats-key", "nats_key", default=None, help="[external] NATS client key path (mTLS)")
@click.option("--no-validate", "validate", flag_value=False, default=True,
              help="[external] skip the Postgres/NATS connectivity pre-check")
@click.pass_obj
def init(app, mode, force, config_path, assume_yes, postgres_dsn, nats_url, nats_user, nats_pass,
         nats_ca, nats_cert, nats_key, validate) -> None:
    """Pick how Blacksea gets Postgres + NATS and write config/blacksea.env (run once)."""
    rctx = app.render
    interactive = not assume_yes and not rctx.json and sys.stdin.isatty()
    mode = mode or _prompt_mode(interactive)

    if mode == "external":
        postgres_dsn, nats_url, nats_user, nats_pass = _resolve_external(
            interactive, postgres_dsn, nats_url, nats_user, nats_pass)
        if not postgres_dsn or not nats_url:
            raise UsageError(
                "external mode needs --postgres-dsn and --nats-url (or run init interactively)")

    with app.service() as svc:
        result = svc.init(
            mode=mode, config_path=config_path, force=force,
            postgres_dsn=postgres_dsn, nats_url=nats_url, nats_user=nats_user, nats_pass=nats_pass,
            tls_ca=nats_ca, tls_cert=nats_cert, tls_key=nats_key, validate=validate)

    if rctx.json:
        render.print_json(result)
        return
    rctx.out.print(f"[green]wrote[/green] [bold]{result.config_path}[/bold]  "
                   f"[dim](mode: {result.mode})[/dim]")
    render.detail(rctx, result, [
        ("mode", "mode"),
        ("config", "config_path"),
        ("postgres", "postgres_summary"),
        ("nats", "nats_summary"),
        ("validated", "validated"),
    ], title="blacksea init")
    for note in result.notes:
        rctx.out.print(f"[dim]• {note}[/dim]")


def _prompt_mode(interactive: bool) -> str:
    """The one forking question. Non-interactive (``--yes``/``--json``/no TTY) defaults to docker."""
    if not interactive:
        return "docker"
    click.echo("How should Blacksea get its Postgres + NATS?")
    click.echo("  docker    — I'll run them for you (quickstart / dev)")
    click.echo("  external  — I'll connect to ones you already run (production)")
    return click.prompt("mode", type=click.Choice(["docker", "external"]), default="docker")


def _resolve_external(
    interactive: bool, postgres_dsn: str | None, nats_url: str | None,
    nats_user: str | None, nats_pass: str | None,
) -> tuple[str | None, str | None, str | None, str | None]:
    """Fill any external-mode value not passed as a flag by prompting (interactive only). A NATS
    user/pass left blank stays ``None`` (anonymous NATS)."""
    if interactive and not postgres_dsn:
        postgres_dsn = click.prompt(
            "Postgres DSN (e.g. host=db port=5432 dbname=blacksea user=bs password=…)")
    if interactive and not nats_url:
        nats_url = click.prompt("NATS URL", default="nats://localhost:4222")
    if interactive and nats_user is None:
        nats_user = click.prompt("NATS username (blank if none)", default="", show_default=False) or None
    if interactive and nats_pass is None:
        nats_pass = click.prompt(
            "NATS password (blank if none)", default="", hide_input=True, show_default=False) or None
    return postgres_dsn, nats_url, nats_user, nats_pass
