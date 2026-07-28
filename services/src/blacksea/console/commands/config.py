"""config — inspect effective operational settings.

There is **no general `config set`**: most of `blacksea.config.settings` is import-time /
deploy-time and needs a process restart, so a live `set` would imply an effect it can't deliver.
Only `otel config set` exists. Secret values are redacted here.
"""

from __future__ import annotations

import re

import click

from .. import render


def _redact(item) -> str:
    if not item.secret or not item.value:
        return item.value
    # Keep a DSN's non-secret shape (host/db) but strip the password; fully mask anything else.
    if "password=" in item.value:
        return re.sub(r"password=\S+", "password=***", item.value)
    return "***"


@click.group("config")
def config() -> None:
    """Inspect effective operational configuration."""


@config.command("show")
@render.json_flag
@click.pass_obj
def config_show(app) -> None:
    """Show the effective operational settings (read-only; secrets redacted)."""
    with app.service() as svc:
        items = svc.effective_config()
    if app.render.json:
        render.print_json([{"key": i.key, "value": _redact(i)} for i in items])
        return
    render.table(app.render, items, [
        ("KEY", "key"),
        ("VALUE", _redact),
    ])
