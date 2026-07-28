"""The dynamic attribution gate: `actors`/`drafts`/`replay` are registered only when
the correlation engine's tables exist; `sessions` is always registered. We drive the gate directly (monkeypatching
the DB probe) so the test needs no Postgres."""

from __future__ import annotations

import click

from blacksea.console import cli as cli_mod


def _list(monkeypatch, open_: bool) -> set[str]:
    monkeypatch.setattr(cli_mod, "_attribution_open", lambda dsn: open_)
    ctx = click.Context(cli_mod.cli)
    return set(cli_mod.cli.list_commands(ctx))


def test_attribution_hidden_when_tables_absent(monkeypatch) -> None:
    cmds = _list(monkeypatch, open_=False)
    assert {"actors", "drafts", "replay"}.isdisjoint(cmds)
    # the always-on surface is still there
    assert {"status", "forge", "baits", "instances", "events", "health", "sessions"} <= cmds


def test_attribution_visible_when_tables_present(monkeypatch) -> None:
    cmds = _list(monkeypatch, open_=True)
    assert {"actors", "drafts", "replay"} <= cmds


def test_gated_command_gives_hint_when_hidden(monkeypatch) -> None:
    monkeypatch.setattr(cli_mod, "_attribution_open", lambda dsn: False)
    ctx = click.Context(cli_mod.cli)
    try:
        cli_mod.cli.get_command(ctx, "actors")
    except click.UsageError as exc:
        assert "correlation engine" in str(exc)
    else:
        raise AssertionError("expected a UsageError hint for the hidden `actors` command")
