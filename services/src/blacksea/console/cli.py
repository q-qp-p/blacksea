"""cli.py — the `blacksea` console root. The installed console-script
entry point (`pyproject.toml` → `[project.scripts] blacksea = "blacksea.console.cli:main"`).

Responsibilities:

* the **noun-verb command tree** — object groups (`baits`/`instances`/`events`/…)
  plus the promoted top-level verbs (`status`/`forge`/`health`);
* the **global flags** that build the facade's :class:`ConsoleConfig` (`--postgres`/`--registry`/
  `--brain-keydir`/`--artifacts-root`/`--sdk-root`/`--schema`/`--nats`/`--otel-env`) + the
  universal `--json`;
* the **dynamic attribution gate** — `actors`/`drafts`/`replay` are registered **only
  when** the correlation engine's tables exist, probed once per invocation (cached), so the help surface
  advertises only what actually works;
* the top-level **error model** — typed exceptions → stderr + the exception's exit
  code, via `render.handle_exception`.

click + rich appear here and in `commands/*`/`render.py` only — never in the facade (purity).
"""

from __future__ import annotations

from pathlib import Path

import click

from blacksea.config import settings

from . import render
from .envfile import resolve_postgres_dsn
from .render import RenderContext
from .service import ConsoleConfig, ConsoleService
from .commands import (
    attribution,
    baits,
    campaigns,
    config as config_cmd,
    down as down_cmd,
    events,
    forge,
    health,
    init as init_cmd,
    instances,
    logs as logs_cmd,
    otel,
    reset as reset_cmd,
    sessions,
    status,
    up as up_cmd,
    webui,
)

# ── banner (ASCII art by Cracken, stored in banner.txt) ────────────────────────


def _load_banner() -> str:
    """The ASCII logo shown atop `blacksea --help`. Kept in a sibling ``banner.txt`` (art by
    Cracken). Defensive: an unreadable/missing file just yields no banner — never breaks the CLI."""
    try:
        return Path(__file__).with_name("banner.txt").read_text(encoding="utf-8").rstrip("\n")
    except OSError:
        return ""


_BANNER = _load_banner()


# ── semantic command grouping for `blacksea --help` ────────────────────────────
# The top-level help lists commands in these ordered groups (instead of one flat
# alphabetical list), each with a crisp one-liner. Attribution commands
# (`actors`/`drafts`/`replay`) only render when the correlation engine's tables
# exist — they're listed here but filtered to what's actually present.
# A command not named here still shows up (under "Other"), so nothing vanishes.
_COMMAND_GROUPS: list[tuple[str, list[tuple[str, str]]]] = [
    ("Setup & infra", [
        # `init` is intentionally absent: it's a hidden command (`make init` is the documented
        # first-run entry — see the group docstring/epilog), so it never renders in `--help`.
        ("up",     "bring up Postgres + NATS + the edge + brain  (up --infra-only = DB only)"),
        ("status", "is the stack up and healthy? (Postgres / brain / NATS / edge / otel)"),
        ("logs",   "tail the edge + brain daemon logs together"),
        ("down",   "stop the edge + brain daemons  (--infra also stops the containers)"),
        ("reset",  "wipe all test-generated state; keeps creds + infra"),
    ]),
    ("Baits & instances", [
        ("forge",     "register → build → approve a bait from its manifest, in one call"),
        ("baits",     "list + register bait designs (the catalog)"),
        ("instances", "build / approve / burn / retire / revoke per-deployment instances"),
        ("campaigns", "list campaigns and their instances"),
    ]),
    ("Intel & attribution", [
        ("events",   "list / show / tail the intel records the brain assembles from hits"),
        ("sessions", "read-time session groupings over records"),
        ("health",   "hit-rate over time + caution-level distribution"),
        ("actors",   "attributed actors (correlation engine)"),
        ("drafts",   "actor-attribution drafts to confirm / reject (correlation engine)"),
        ("replay",   "replay a session's records (correlation engine)"),
    ]),
    ("Telemetry & UI", [
        ("otel",   "configure + run the OTLP telemetry emitter (records → your SIEM)"),
        ("web-ui", "serve the read-only observer web UI (temporary stopgap)"),
    ]),
    ("Config", [
        ("config", "show the effective operational config + where each value resolved from"),
    ]),
]


# ── attribution gate — probe once per DSN, cached ─────────────────

_attribution_cache: dict[str, bool] = {}


def _attribution_open(dsn: str) -> bool:
    """True iff the correlation engine's tables exist (gated on ``session_records``). Cheap
    ``information_schema`` probe, cached per DSN. Any failure (Postgres down, no table) → False,
    so the commands stay hidden — disambiguated by `blacksea status`."""
    if not dsn:
        return False
    if dsn in _attribution_cache:
        return _attribution_cache[dsn]
    present = False
    try:
        import psycopg
        with psycopg.connect(dsn, autocommit=True, connect_timeout=2) as conn:
            with conn.cursor() as cur:
                cur.execute("SELECT to_regclass('public.session_records') IS NOT NULL")
                row = cur.fetchone()
                present = bool(row and row[0])
    except Exception:  # noqa: BLE001 — a failed probe keeps the commands hidden
        present = False
    _attribution_cache[dsn] = present
    return present


class ConsoleGroup(click.Group):
    """Root group that registers the attribution commands lazily: they appear in
    `--help` and resolve only when the correlation engine's tables exist."""

    def format_help(self, ctx: click.Context, formatter: click.HelpFormatter) -> None:
        # Write the ASCII banner verbatim (formatter.write does no wrapping, so the art keeps its
        # alignment) above the usual usage/options/commands help.
        if _BANNER:
            formatter.write(_BANNER + "\n\n")
        super().format_help(ctx, formatter)

    def format_commands(self, ctx: click.Context, formatter: click.HelpFormatter) -> None:
        """Render the command list split into the semantic groups in ``_COMMAND_GROUPS``
        (instead of click's one flat alphabetical list), each with a crisp one-liner. Only
        commands actually available are shown — so the attribution commands appear here only when
        their tables exist — and any command not named in a group falls through to an
        "Other" section so nothing silently disappears from help."""
        available = {}
        for name in self.list_commands(ctx):
            cmd = self.get_command(ctx, name)
            if cmd is not None and not getattr(cmd, "hidden", False):
                available[name] = cmd
        if not available:
            return

        grouped: set[str] = set()
        sections: list[tuple[str, list[tuple[str, str]]]] = []
        for title, entries in _COMMAND_GROUPS:
            rows = [(name, blurb) for name, blurb in entries if name in available]
            grouped.update(name for name, _ in rows)
            if rows:
                sections.append((title, rows))
        leftover = sorted(
            (name, available[name].get_short_help_str()) for name in available if name not in grouped)
        if leftover:
            sections.append(("Other", leftover))

        with formatter.section("Commands"):
            for idx, (title, rows) in enumerate(sections):
                if idx:
                    formatter.write_paragraph()
                formatter.write_text(f"{title}:")
                with formatter.indentation():
                    formatter.write_dl(rows)

    def _resolve_dsn(self, ctx: click.Context) -> str:
        # `--postgres` may not be parsed yet during eager `--help`; the resolver falls back to
        # $POSTGRES_DSN then secrets/env, so the gate sees the same DB the commands will.
        params = ctx.params or {}
        dsn, _ = resolve_postgres_dsn(params.get("postgres"), params.get("secrets"))
        return dsn

    def list_commands(self, ctx: click.Context):
        names = set(super().list_commands(ctx))
        if _attribution_open(self._resolve_dsn(ctx)):
            names.update(cmd.name for cmd in attribution.ATTRIBUTION_COMMANDS)
        return sorted(names)

    def get_command(self, ctx: click.Context, name: str):
        gated = {cmd.name: cmd for cmd in attribution.ATTRIBUTION_COMMANDS}
        if name in gated:
            if _attribution_open(self._resolve_dsn(ctx)):
                return gated[name]
            # Known-but-not-yet-available: a friendlier hint than "no such command".
            ctx.fail(
                f"`{name}` requires the correlation engine — its session/actor tables are not "
                f"deployed yet. `blacksea sessions ls` works today; see `blacksea status`.")
        return super().get_command(ctx, name)


# ── app context carried on ctx.obj ─────────────────────────────────────────────


class AppContext:
    """Bridges the CLI to the facade: holds the resolved :class:`ConsoleConfig` and the
    :class:`RenderContext`, and mints a fresh :class:`ConsoleService` per command (one Postgres
    connection per invocation)."""

    def __init__(self, config: ConsoleConfig, render_ctx: RenderContext) -> None:
        self.config = config
        self.render = render_ctx

    def service(self) -> ConsoleService:
        return ConsoleService(self.config)


# ── root group + global flags ──────────────────────────────────────────────────


@click.command(cls=ConsoleGroup, name="blacksea", no_args_is_help=True)
@click.option("--postgres", default=None,
              help="Postgres DSN for the catalog + event store "
                   "(else $POSTGRES_DSN, else built from secrets/env)")
@click.option("--secrets", default=None,
              help="path to the secrets env file the DSN falls back to (default: secrets/env, "
                   "searched from the CWD upward)")
@click.option("--registry", default=settings.BS_REGISTRY,
              help="registry filesystem root — parent of artifacts/ (or $BS_REGISTRY)")
@click.option("--schema", default=settings.BS_CP_SCHEMA,
              help="control-plane catalog schema (or $BS_CP_SCHEMA)")
@click.option("--artifacts-root", "artifacts_root", default=settings.BS_ARTIFACTS_ROOT,
              help="artifact output root (or $BS_ARTIFACTS_ROOT)")
@click.option("--brain-keydir", "brain_keydir", default=settings.BRAIN_KEYDIR,
              help="brain key directory — the sole key directory (or $BS_BRAIN_KEYDIR)")
@click.option("--sdk-root", "sdk_root", default=settings.BS_SDK_ROOT,
              help="bundler vendor root (or $BS_SDK_ROOT)")
@click.option("--nats", default=settings.NATS_URL, help="NATS URL for the status probe")
@click.option("--otel-env", "otel_env", default="secrets/otel.env",
              help="otel emitter config file (BS_OTEL_*)")
@click.option("--otel-unit", "otel_unit", default="secrets/blacksea-otel.service",
              help="where `otel install-unit` writes the OS unit")
@click.option("--edge-dns", "edge_dns", default=settings.EDGE_DNS_ADDR,
              help="edge DNS addr for the status probe + `up`'s launched edge (or $DNS_ADDR)")
@click.option("--edge-https", "edge_https", default=settings.EDGE_HTTPS_ADDR,
              help="edge HTTPS addr for the status probe + `up`'s launched edge (or $HTTPS_ADDR)")
@click.option("--edge-separate", is_flag=True, default=False,
              help="the edge runs on a separate network (don't probe it locally)")
@click.option("--json", "json_mode", is_flag=True, default=False,
              help="emit raw JSON (list→array, show→object); disables tables")
@click.pass_context
def cli(ctx, postgres, secrets, registry, schema, artifacts_root, brain_keydir, sdk_root, nats,
        otel_env, otel_unit, edge_dns, edge_https, edge_separate, json_mode) -> None:
    """Blacksea operator console — the single entry point to run and operate the honeypot.

    Bring the stack up, forge and manage baits, and read the intel it collects — all from this one
    command. First run, in order:

    \b
      make init                choose how Blacksea gets Postgres + NATS (writes config/blacksea.env)
      blacksea up              start the stack (Postgres + NATS + the edge + brain)
      blacksea forge <manif>   deploy a bait (register → build → approve)
      blacksea events tail     watch hits land

    `blacksea status` reports whether the stack is up. Add `--json` to any command for scripting.
    """
    # Resolve the DSN: --postgres > $POSTGRES_DSN > secrets/env (dev convenience) — so a bare
    # `blacksea` from a checkout works without exporting POSTGRES_DSN by hand.
    dsn, dsn_source = resolve_postgres_dsn(postgres, secrets)
    config = ConsoleConfig(
        postgres_dsn=dsn,
        postgres_dsn_source=dsn_source,
        registry_root=registry,
        schema=schema,
        artifacts_root=artifacts_root,
        brain_keydir_path=brain_keydir,
        sdk_root=sdk_root,
        nats_url=nats,
        otel_env_path=otel_env,
        otel_unit_path=otel_unit,
        edge_dns_addr=edge_dns,
        edge_https_addr=edge_https,
        edge_co_located=not edge_separate,
    )
    ctx.obj = AppContext(config, RenderContext(json_mode))


# ── register the noun-verb tree ────────────────────────────────────────────────

cli.add_command(init_cmd.init)              # lifecycle: choose infra mode + write config/blacksea.env (hidden — `make init` is the documented entry; still invocable for pip-only installs)
cli.add_command(up_cmd.up)                  # lifecycle: bring the stack up (infra + daemons)
cli.add_command(down_cmd.down)              # lifecycle: stop the daemons (+ --infra containers)
cli.add_command(logs_cmd.logs)              # lifecycle: tail the daemon logs together
cli.add_command(reset_cmd.reset)            # lifecycle: wipe test state (keeps creds + infra)
cli.add_command(status.status)              # top-level: infra "ps" view
cli.add_command(forge.forge)                # top-level: register→build→approve
cli.add_command(health.health)              # top-level: hit-rate + caution
cli.add_command(baits.baits)
cli.add_command(instances.instances)
cli.add_command(campaigns.campaigns)
cli.add_command(events.events)
cli.add_command(otel.otel)
cli.add_command(config_cmd.config)
cli.add_command(sessions.sessions)          # always registered (read-time grouping)
cli.add_command(webui.web_ui)               # top-level: TEMPORARY foreground observer launcher
# actors / drafts / replay are added dynamically by ConsoleGroup when the correlation tables exist.


# ── entry point ────────────────────────────────────────────────────────────────


def main(argv: list[str] | None = None) -> int:
    """The `blacksea` entry point. Runs the CLI with click's standalone mode off so typed
    exceptions surface to `render.handle_exception` (stderr + the right exit code), never
    swallowed as an empty result."""
    try:
        cli.main(args=argv, standalone_mode=False)
        return 0
    except SystemExit as exc:  # click `--help`, ctx.exit(), or a command's raise SystemExit(code)
        return int(exc.code) if isinstance(exc.code, int) else (0 if exc.code is None else 1)
    except BaseException as exc:  # noqa: BLE001 — the single top-level error boundary
        return render.handle_exception(exc)


if __name__ == "__main__":
    raise SystemExit(main())
