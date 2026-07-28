"""CLI smoke tests — help surface, the read-only `config show` (needs no DB), the universal
`--json` (global *and* trailing), and the error model (a read with no DSN → non-zero, never an
empty table). The attribution DB probe is monkeypatched off so these run without Postgres."""

from __future__ import annotations

import json
import subprocess
import sys

import pytest
from click.testing import CliRunner

from blacksea.console import cli as cli_mod


@pytest.fixture(autouse=True)
def _no_db_probe(monkeypatch):
    # Keep the gate closed without a DB round-trip, so help/dispatch don't hang on connect.
    monkeypatch.setattr(cli_mod, "_attribution_open", lambda dsn: False)


def test_help_lists_core_commands() -> None:
    result = CliRunner().invoke(cli_mod.cli, ["--help"])
    assert result.exit_code == 0
    for name in ("status", "forge", "baits", "instances", "events", "health",
                 "otel", "config", "sessions", "campaigns"):
        assert name in result.output
    # gated commands are hidden
    assert "actors" not in result.output


def test_help_groups_commands_semantically() -> None:
    # The top-level help splits commands into ordered semantic groups (cli._COMMAND_GROUPS),
    # not one flat alphabetical list.
    result = CliRunner().invoke(cli_mod.cli, ["--help"])
    assert result.exit_code == 0
    # scope to the Commands section — command names like `up`/`forge` also appear in the
    # description's first-run block above it.
    cmds = result.output[result.output.index("Commands:"):]
    for header in ("Setup & infra:", "Baits & instances:", "Intel & attribution:",
                   "Telemetry & UI:", "Config:"):
        assert header in cmds, header
    # groups render in declared order, and each command sits under its group's header
    assert cmds.index("Setup & infra:") < cmds.index("Baits & instances:") < cmds.index("Config:")
    # `up` (not `init` — that's hidden now, `make init` is the entry) leads the Setup & infra group
    assert cmds.index("Setup & infra:") < cmds.index("up") < cmds.index("Baits & instances:")
    assert "init" not in cmds                                  # the hidden command never renders
    assert cmds.index("Baits & instances:") < cmds.index("forge") < cmds.index("Intel & attribution:")


def test_attribution_commands_appear_under_intel_group_when_gate_open(monkeypatch) -> None:
    # With the correlation-engine tables present, the gate opens and actors/drafts/replay render
    # inside the Intel & attribution group (they stay hidden otherwise — see the autouse fixture).
    monkeypatch.setattr(cli_mod, "_attribution_open", lambda dsn: True)
    result = CliRunner().invoke(cli_mod.cli, ["--help"])
    assert result.exit_code == 0
    cmds = result.output[result.output.index("Commands:"):]
    for name in ("actors", "drafts", "replay"):
        assert name in cmds, name
    assert cmds.index("Intel & attribution:") < cmds.index("actors")


def test_root_help_shows_banner_but_subcommands_dont() -> None:
    runner = CliRunner()
    root = runner.invoke(cli_mod.cli, ["--help"])
    assert root.exit_code == 0
    assert "(by Cracken)" in root.output          # ASCII banner rendered atop the root help
    # the banner is scoped to the root group only — subcommand help stays clean
    sub = runner.invoke(cli_mod.cli, ["baits", "--help"])
    assert sub.exit_code == 0
    assert "Cracken" not in sub.output


def test_web_ui_is_top_level_and_marked_temporary() -> None:
    runner = CliRunner()
    top = runner.invoke(cli_mod.cli, ["--help"])
    assert top.exit_code == 0
    assert "web-ui" in top.output
    sub = runner.invoke(cli_mod.cli, ["web-ui", "--help"])
    assert sub.exit_code == 0, sub.output
    assert "--host" in sub.output and "--port" in sub.output
    # the command's help must flag it as a stopgap (the only place it's documented)
    assert "TEMPORARY" in sub.output


def test_config_show_json_needs_no_db() -> None:
    result = CliRunner().invoke(cli_mod.cli, ["config", "show", "--json"])
    assert result.exit_code == 0, result.output
    data = json.loads(result.output)
    assert isinstance(data, list)
    keys = {item["key"] for item in data}
    assert "BS_CP_SCHEMA" in keys and "BS_REGISTRY" in keys


def test_trailing_json_equals_global_json() -> None:
    runner = CliRunner()
    trailing = runner.invoke(cli_mod.cli, ["config", "show", "--json"])
    globalf = runner.invoke(cli_mod.cli, ["--json", "config", "show"])
    assert trailing.exit_code == 0 and globalf.exit_code == 0
    assert json.loads(trailing.output) == json.loads(globalf.output)


def test_read_without_dsn_is_nonzero_not_empty() -> None:
    # A read with no Postgres is a non-zero exit with a message — never a silently empty table.
    code = cli_mod.main(["--postgres", "", "events", "ls"])
    assert code == 1


def test_forge_and_build_advertise_comment_flag() -> None:
    runner = CliRunner()
    for args in (["forge", "--help"], ["instances", "build", "--help"]):
        result = runner.invoke(cli_mod.cli, args)
        assert result.exit_code == 0, result.output
        assert "--comment" in result.output


def test_edge_dns_https_defaults_honor_env_override() -> None:
    """`DNS_ADDR`/`HTTPS_ADDR` (what `blacksea up` / a direct env var passes) must reach the
    `--edge-dns`/`--edge-https` global defaults, not a hardcoded literal — regression test for
    the console context.md contract item 4 (the edge's launch address silently ignoring an
    env-var override). Run in a fresh subprocess since `settings`/`cli.py` resolve the default
    at import time, same pattern as test_purity.py."""
    code = (
        "import os;"
        "os.environ['DNS_ADDR'] = ':19999';"
        "os.environ['HTTPS_ADDR'] = ':19443';"
        "from blacksea.console import cli as cli_mod;"
        "params = {p.name: p.default for p in cli_mod.cli.params};"
        "assert params['edge_dns'] == ':19999', params['edge_dns'];"
        "assert params['edge_https'] == ':19443', params['edge_https'];"
        "print('OK')"
    )
    proc = subprocess.run([sys.executable, "-c", code], capture_output=True, text=True)
    assert proc.returncode == 0, proc.stderr
    assert "OK" in proc.stdout


def test_logs_json_flag_is_accepted_and_prints_an_array() -> None:
    # Regression: `commands/logs.py` was missing @render.json_flag, so `blacksea logs --json`
    # failed with a click UsageError while every sibling lifecycle command accepted it.
    result = CliRunner().invoke(cli_mod.cli, ["logs", "--json"])
    assert result.exit_code == 0, result.output
    data = json.loads(result.output)
    assert isinstance(data, list)   # no .dev/*.log in this test env → empty array, not an error


def test_resolve_comment_never_blocks_noninteractive() -> None:
    # The create-a-bait prompt must never fire under --json or without a TTY (scriptable runs,
    # the e2e harness, tests) — otherwise automation would hang waiting on stdin.
    from blacksea.console.commands._common import resolve_comment
    assert resolve_comment("  field-2026q3  ", json_mode=False) == "field-2026q3"  # explicit, trimmed
    assert resolve_comment("   ", json_mode=False) is None                          # explicit-empty → None
    assert resolve_comment(None, json_mode=True) is None                            # --json → no prompt
    assert resolve_comment(None, json_mode=False) is None                          # no TTY under pytest
