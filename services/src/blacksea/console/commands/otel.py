"""otel — telemetry emitter control: run / config show|set / install-unit.

The console owns the config (`secrets/otel.env`) and runs the emitter in the foreground; durable
always-on is the OS's job via the emitted unit. `config set` never affects a *running* emitter —
`settings.py` resolves BS_OTEL_* at import and the emitter reads them once at startup — so it
prints "restart to apply."
"""

from __future__ import annotations

import click

from .. import render
from ._common import kv


@click.group("otel")
def otel() -> None:
    """Configure and run the OTLP telemetry emitter."""


@otel.command("run")
@render.json_flag
@click.pass_obj
def otel_run(app) -> None:
    """Run the emitter in the foreground (loads secrets/otel.env; Ctrl-C stops)."""
    render.note(app.render, "[dim]starting otel emitter (Ctrl-C to stop)…[/dim]")
    with app.service() as svc:
        code = svc.otel_run()
    raise SystemExit(code)


@otel.group("config")
def otel_config() -> None:
    """Manage the emitter's BS_OTEL_* configuration (secrets/otel.env)."""


@otel_config.command("show")
@render.json_flag
@click.pass_obj
def otel_config_show(app) -> None:
    """Show the managed otel config file + install-unit state."""
    with app.service() as svc:
        status = svc.otel_status()
    if app.render.json:
        render.print_json(status)
        return
    render.detail(app.render, status, [
        ("env_path", "env_path"),
        ("exists", "exists"),
        ("unit_installed", "unit_installed"),
        ("unit", "unit_detail"),
    ], title="otel config")
    if status.config:
        render.table(
            app.render,
            [_KV(k, v) for k, v in status.config.items()],
            [("KEY", "key"), ("VALUE", "value")], title="BS_OTEL_*")
    else:
        app.render.out.print("[dim](no BS_OTEL_* set yet — use `blacksea otel config set K=V`)[/dim]")


@otel_config.command("set")
@render.json_flag
@click.argument("assignments", nargs=-1, required=True, metavar="KEY=VALUE...")
@click.pass_obj
def otel_config_set(app, assignments) -> None:
    """Set one or more BS_OTEL_* keys (validated) in secrets/otel.env."""
    updates = kv(list(assignments), "otel config set")
    with app.service() as svc:
        status = svc.otel_config_set(updates)
    render.note(
        app.render,
        "[yellow]note:[/yellow] applies to the NEXT `blacksea otel run` / unit start — "
        "a running emitter reads BS_OTEL_* once at startup; restart it to apply.")
    if app.render.json:
        render.print_json(status)
    else:
        for k in updates:
            app.render.out.print(f"set {k}={status.config.get(k, '')}")


@otel.command("install-unit")
@render.json_flag
@click.option("--flavor", type=click.Choice(["systemd", "compose"]), default="systemd",
              show_default=True, help="emit a systemd unit or a docker-compose snippet")
@click.pass_obj
def otel_install_unit(app, flavor) -> None:
    """Emit an OS unit (systemd / compose) with EnvironmentFile=secrets/otel.env for always-on."""
    with app.service() as svc:
        path = svc.otel_install_unit(flavor=flavor)
    if app.render.json:
        render.print_json({"flavor": flavor, "unit_path": path})
        return
    app.render.out.print(f"wrote {flavor} unit to [bold]{path}[/bold]")
    if flavor == "systemd":
        app.render.out.print(
            "[dim]install with:  sudo cp "
            f"{path} /etc/systemd/system/  &&  sudo systemctl enable --now "
            f"{path.rsplit('/', 1)[-1]}[/dim]")


class _KV:
    """Row adapter so `render.table` can show the config dict as KEY/VALUE."""

    __slots__ = ("key", "value")

    def __init__(self, key: str, value: str) -> None:
        self.key = key
        self.value = value
