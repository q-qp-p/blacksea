"""commands/reset.py's confirmation gate — the exact-literal-"yes" requirement.

Regression test: the interactive confirmation used to be `click.confirm("Continue?",
default=False)`, which accepts a bare "y"/"Y" — narrower than the retired reset-state.sh's
`[ "$reply" != "yes" ]`, too thin a safety net for an irreversible destructive action. Invokes
the command's callback directly through a synthetic click.Context (rather than CliRunner, whose
simulated stdin never reports isatty()==True, so the interactive branch is otherwise
unreachable in tests).
"""

from __future__ import annotations

import contextlib

import click
import pytest

from blacksea.console.commands import reset as reset_mod
from blacksea.console.models import ResetResult


class _FakeRenderContext:
    def __init__(self) -> None:
        self.json = False
        self.notes: list[str] = []


class _FakeService:
    def reset(self, *, purge_nats: bool) -> ResetResult:
        return ResetResult(cleared=["ok"], skipped=[], notes=[])


class _FakeApp:
    def __init__(self) -> None:
        self.render = _FakeRenderContext()
        self.service_called = False

    def service(self):
        self.service_called = True
        return contextlib.nullcontext(_FakeService())


@pytest.fixture(autouse=True)
def _interactive(monkeypatch):
    # Force the `interactive` branch (assume_yes=False, --json off, a TTY) without needing a
    # real terminal.
    monkeypatch.setattr(reset_mod.sys.stdin, "isatty", lambda: True)
    monkeypatch.setattr(reset_mod.click, "echo", lambda *a, **k: None)
    monkeypatch.setattr(reset_mod.render, "note", lambda rctx, text: rctx.notes.append(text))
    monkeypatch.setattr(reset_mod.render, "lifecycle_reset", lambda rctx, result: None)


def _invoke(app: _FakeApp, *, prompt_reply: str, monkeypatch) -> None:
    monkeypatch.setattr(reset_mod.click, "prompt", lambda *a, **k: prompt_reply)
    ctx = click.Context(reset_mod.reset)
    ctx.obj = app
    with ctx:
        reset_mod.reset.callback(assume_yes=False, purge_nats=True)


def test_bare_y_is_not_confirmation(monkeypatch):
    app = _FakeApp()
    _invoke(app, prompt_reply="y", monkeypatch=monkeypatch)
    assert not app.service_called
    assert any("aborted" in n for n in app.render.notes)


def test_uppercase_yes_is_not_confirmation(monkeypatch):
    # Only the exact literal "yes" — not case-insensitive, matching the old script precisely.
    app = _FakeApp()
    _invoke(app, prompt_reply="Yes", monkeypatch=monkeypatch)
    assert not app.service_called


def test_literal_yes_proceeds(monkeypatch):
    app = _FakeApp()
    _invoke(app, prompt_reply="yes", monkeypatch=monkeypatch)
    assert app.service_called
