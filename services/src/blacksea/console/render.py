"""render.py — the single rendering seam. click + rich live **only** here
(and in `cli.py`/`commands/*`); the facade never imports them (the facade-purity invariant).

One seam, two modes:

* **human** — a result dataclass → a rich table / key-value panel (rich auto-detects the TTY);
* **`--json`** — `json.dumps` of the dataclass fields, with rich disabled. **List** commands emit
  a JSON **array**, **show** commands a JSON **object**, no wrapper — so `jq` pipelines stay clean
  (`blacksea events ls --json | jq '.[].source_ip'`). Success → stdout.

Error model: the facade raises typed exceptions; :func:`handle_exception` prints the
message to **stderr**, echoes any ingest ``issues``, and returns the exception's ``exit_code``
(reusing `operations.py`'s convention — ``0`` ok / ``1`` operational / ``2`` usage). No swallowing.
"""

from __future__ import annotations

import dataclasses
import json
import sys
from typing import Any, Callable, Sequence

import click
from rich.console import Console
from rich.panel import Panel
from rich.table import Table

from blacksea.control_plane.operations import OperationError
from blacksea.control_plane.registry import CatalogUnavailableError
from blacksea.control_plane.forge import ForgeError

from .lifecycle import InitError
from .models import ArtifactLocation, InfraStatus
from .supervisor import SupervisorError

# Column = (header, accessor). The accessor is a field name (looked up on the row) or a callable
# row -> str. Kept deliberately small so each command declares its own columns inline.
Column = tuple[str, "str | Callable[[Any], Any]"]


class RenderContext:
    """Carried on the click context (``ctx.obj.render``). Holds the ``--json`` flag and the two
    rich consoles (stdout for data, stderr for status/errors)."""

    def __init__(self, json_mode: bool) -> None:
        self.json = json_mode
        self.out = Console()
        self.err = Console(stderr=True)


def _json_callback(ctx: click.Context, param: click.Parameter, value: bool) -> bool:
    # Flip the shared RenderContext when `--json` is given *after* the subcommand, so the
    # universal `--json` works trailing — `blacksea events ls --json` — not only as
    # the pre-command global (`blacksea --json events ls`). expose_value=False → no signature churn.
    if value and ctx.obj is not None:
        ctx.obj.render.json = True
    return value


#: Decorator applied to every leaf command so `--json` is accepted trailing as well as globally.
json_flag = click.option(
    "--json", is_flag=True, expose_value=False, callback=_json_callback,
    help="emit raw JSON (list→array, show→object); disables tables")


# ── JSON path ──────────────────────────────────────────────────────────────────


def to_jsonable(obj: Any) -> Any:
    """Recursively convert dataclasses / lists / dicts into JSON-native values."""
    if dataclasses.is_dataclass(obj) and not isinstance(obj, type):
        return {k: to_jsonable(v) for k, v in dataclasses.asdict(obj).items()}
    if isinstance(obj, (list, tuple)):
        return [to_jsonable(v) for v in obj]
    if isinstance(obj, dict):
        return {k: to_jsonable(v) for k, v in obj.items()}
    return obj


def print_json(obj: Any) -> None:
    """Emit ``obj`` as a JSON document to stdout (list → array, single → object).

    Explicitly flushed: `events_tail` calls this repeatedly from a long-running loop with
    stdout often redirected to a file/pipe, where Python block-buffers by default — without an
    explicit flush, a process stopped via SIGTERM (the default OS shutdown signal; only Ctrl-C's
    SIGINT is caught below) loses its most recently written, still-buffered record."""
    sys.stdout.write(json.dumps(to_jsonable(obj), default=str) + "\n")
    sys.stdout.flush()


# ── human path ─────────────────────────────────────────────────────────────────


def _cell(row: Any, accessor: "str | Callable[[Any], Any]") -> str:
    value = accessor(row) if callable(accessor) else getattr(row, accessor, "")
    if value is None:
        return ""
    if isinstance(value, bool):
        return "yes" if value else ""
    if isinstance(value, (list, tuple)):
        return ", ".join(str(v) for v in value)
    return str(value)


def table(
    rctx: RenderContext, rows: Sequence[Any], columns: Sequence[Column], *,
    title: str | None = None, empty: str = "(none)",
) -> None:
    """Render a list of rows as a rich table (human) or a JSON array (``--json``)."""
    if rctx.json:
        print_json(list(rows))
        return
    if not rows:
        rctx.out.print(f"[dim]{empty}[/dim]")
        return
    tbl = Table(title=title, header_style="bold", show_edge=False, pad_edge=False)
    for header, _ in columns:
        tbl.add_column(header)
    for row in rows:
        tbl.add_row(*[_cell(row, acc) for _, acc in columns])
    rctx.out.print(tbl)


def detail(
    rctx: RenderContext, obj: Any, fields: Sequence[Column], *, title: str | None = None,
) -> None:
    """Render one object as a key/value panel (human) or a JSON object (``--json``)."""
    if rctx.json:
        print_json(obj)
        return
    tbl = Table(show_header=False, show_edge=False, pad_edge=False, box=None)
    tbl.add_column("field", style="bold cyan", no_wrap=True)
    tbl.add_column("value", overflow="fold")
    for header, acc in fields:
        tbl.add_row(header, _cell(obj, acc))
    rctx.out.print(Panel(tbl, title=title, title_align="left", expand=False))


def message(rctx: RenderContext, result: Any, human: str) -> None:
    """A write-op result: the ``human`` one-liner in human mode, the result dataclass as a JSON
    object under ``--json``."""
    if rctx.json:
        print_json(result)
    else:
        rctx.out.print(human)


def note(rctx: RenderContext, text: str) -> None:
    """A human-only status line (suppressed under ``--json`` so stdout stays a clean document)."""
    if not rctx.json:
        rctx.err.print(text)


# ── infra status — its own renderer (labeled, colored, never a false green) ──

_STATUS_STYLE = {"up": "green", "down": "red", "stale": "yellow", "unknown": "dim yellow"}


def infra_status(rctx: RenderContext, status: InfraStatus) -> None:
    if rctx.json:
        print_json(status)
        return
    tbl = Table(title="infra status", header_style="bold", show_edge=False, pad_edge=False)
    tbl.add_column("component")
    tbl.add_column("status")
    tbl.add_column("source")
    tbl.add_column("detail", overflow="fold")
    for c in status.components:
        style = _STATUS_STYLE.get(c.status, "white")
        tbl.add_row(c.name, f"[{style}]{c.status}[/{style}]", c.source, c.detail)
    rctx.out.print(tbl)
    counts = (
        f"baits={_count(status.bait_count)}  "
        f"instances={_count(status.instance_count)}  "
        f"events={_count(status.event_count)}"
    )
    if status.last_event_ms:
        counts += f"  last_event_ms={status.last_event_ms}"
    rctx.out.print(f"[dim]{counts}[/dim]")
    _daemons(rctx, status.daemons)


def _count(n: int | None) -> str:
    return "?" if n is None else str(n)


# ── lifecycle: up / down / reset ─────────────────────────────────────────────────

_DAEMON_STYLE = {
    "started": "green", "restarted": "yellow", "unchanged": "dim green",
    "stopped": "yellow", "not-running": "dim", "not-stopped": "red", "": "white",
}


def _daemons(rctx: RenderContext, daemons: Sequence[Any]) -> None:
    if not daemons:
        return
    tbl = Table(header_style="bold", show_edge=False, pad_edge=False)
    for header in ("daemon", "pid", "state"):
        tbl.add_column(header)
    for d in daemons:
        style = _DAEMON_STYLE.get(d.action, "white")
        tbl.add_row(d.name, str(d.pid or ""), f"[{style}]{d.detail or d.action}[/{style}]")
    rctx.out.print(tbl)


def lifecycle_up(rctx: RenderContext, result: Any) -> None:
    if rctx.json:
        print_json(result)
        return
    rctx.out.print(f"[bold]mode:[/bold] {result.mode}")
    for line in result.infra:
        rctx.out.print(f"  [cyan]infra[/cyan]  {line}")
    _daemons(rctx, result.daemons)
    for note_line in result.notes:
        rctx.out.print(f"[dim]  {note_line}[/dim]")


def lifecycle_down(rctx: RenderContext, result: Any) -> None:
    if rctx.json:
        print_json(result)
        return
    _daemons(rctx, result.daemons)
    for note_line in result.notes:
        rctx.out.print(f"[dim]• {note_line}[/dim]")


def lifecycle_reset(rctx: RenderContext, result: Any) -> None:
    if rctx.json:
        print_json(result)
        return
    for done in result.cleared:
        rctx.out.print(f"[green]✓[/green] {done}")
    for skip in result.skipped:
        rctx.out.print(f"[yellow]•[/yellow] {skip}")
    for note_line in result.notes:
        rctx.out.print(f"[dim]{note_line}[/dim]")


# ── artifact location ────────────────────────────────────────────────────────

_ARTIFACT_DETAIL_COLUMNS: list[Column] = [
    ("instance_token", "instance_token"),
    ("bait_id", "bait_id"),
    ("status", "status"),
    ("primary_file", "filename"),
    ("sha256", "sha256"),
    ("to_stage_dir", "to_stage_dir"),
    ("output_dir_root", "output_dir_root"),
    ("ready_for_vessel", "ready_for_vessel"),
]


def artifact_detail(rctx: RenderContext, art: ArtifactLocation) -> None:
    """The full to_stage/ picture for one instance — every staged file, not just the primary
    one (a vessel like pwcrypt stages several equally-valid binaries). Shared by `instances
    artifact` and, so an operator never has to run a follow-up command to see it, `forge`/
    `instances build`'s own summary (callers there skip this entirely under --json — see their
    own comments)."""
    if rctx.json:
        print_json(art)
        return
    detail(rctx, art, _ARTIFACT_DETAIL_COLUMNS, title=f"artifact for {art.instance_token}")
    if art.files:
        rctx.out.print("[bold]to_stage/ files[/bold]")
        for name, digest in sorted(art.files.items()):
            rctx.out.print(f"  {name}  [dim]{digest}[/dim]")


# ── error handling ─────────────────────────────────────────────────────────────


def handle_exception(exc: BaseException) -> int:
    """Map a facade/CLI exception to a stderr message + an exit code. Echoes any ingest
    ``issues`` before the message (as the argparse CLI always did). Returns the exit code."""
    err = Console(stderr=True)
    if isinstance(exc, (ForgeError, InitError, SupervisorError)):
        err.print(f"[red]error:[/red] {exc}")
        return getattr(exc, "exit_code", 1)
    if isinstance(exc, OperationError):        # includes UsageError
        for issue in getattr(exc, "issues", []) or []:
            err.print(issue)
        err.print(f"[red]error:[/red] {exc}")
        return exc.exit_code
    if isinstance(exc, CatalogUnavailableError):
        err.print(f"[red]error:[/red] {exc}")
        return 1
    if isinstance(exc, click.ClickException):
        exc.show()
        return exc.exit_code
    if isinstance(exc, (click.Abort, KeyboardInterrupt)):
        err.print("aborted")
        return 130
    # Anything else has a code path bug — surface it loudly rather than an empty table.
    err.print(f"[red]unexpected error:[/red] {exc.__class__.__name__}: {exc}")
    return 1
