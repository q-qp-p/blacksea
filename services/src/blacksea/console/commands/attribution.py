"""attribution — actors / drafts / replay. **Not implemented yet.**

These commands are registered by `cli.py` **only when the correlation engine's tables**
(`session_records` / `actor_*` / `confirmation_log`) exist — probed at CLI construction (dynamic
registration). Until the stateful correlation engine lands, they are absent from
`--help`, and the command set auto-expands the moment those tables are deployed.

**Why this is a skeleton:** the schema above is still a strawman, "to ratify jointly when
correlation's engine is designed" (`blacksea/correlation/context.md`). This module therefore ships
as the command *skeleton* only — the real query bodies land with that engine, against the ratified
schema. Each command below states that plainly rather than guessing at columns that may change.

**Resolver-linkage invariant (correlation/context.md):** when these bodies are filled in, an
`actors`/`drafts` linkage that rests solely on a shared resolver IP MUST be flagged as needing
JA3/fingerprint corroboration — it must not read as confirmable on its own.
"""

from __future__ import annotations

import click

from blacksea.control_plane.operations import OperationError

from .. import render

_NOT_IMPLEMENTED = (
    "attribution query bodies are not implemented yet: the correlation tables exist, but the "
    "console's readers/writers land with the stateful engine (see console/context.md). "
    "`blacksea sessions ls` works today off read-time grouping."
)


def _pending() -> None:
    raise OperationError(_NOT_IMPLEMENTED)


@click.group("actors")
def actors() -> None:
    """Actor graph views (not implemented yet — lands with the correlation engine)."""


@actors.command("ls")
@render.json_flag
@click.pass_obj
def actors_ls(app) -> None:
    """List actors (not implemented yet)."""
    _pending()


@click.group("drafts")
def drafts() -> None:
    """Class-B draft merges + confirmation log (not implemented yet — lands with the correlation engine)."""


@drafts.command("ls")
@render.json_flag
@click.pass_obj
def drafts_ls(app) -> None:
    """List pending draft merges (not implemented yet)."""
    _pending()


@drafts.command("confirm")
@render.json_flag
@click.argument("draft_id")
@click.pass_obj
def drafts_confirm(app, draft_id) -> None:
    """Confirm a draft merge (not implemented yet)."""
    _pending()


@drafts.command("reject")
@render.json_flag
@click.argument("draft_id")
@click.pass_obj
def drafts_reject(app, draft_id) -> None:
    """Reject a draft merge (not implemented yet)."""
    _pending()


@click.command("replay")
@render.json_flag
@click.pass_obj
def replay(app) -> None:
    """Replay-materialize session/actor state (not implemented yet)."""
    _pending()


# The command objects `cli.py` registers when the gate opens.
ATTRIBUTION_COMMANDS = (actors, drafts, replay)
