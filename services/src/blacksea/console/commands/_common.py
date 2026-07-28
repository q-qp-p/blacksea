"""_common.py — helpers shared across the command modules (KV parsing, filter building).

Kept tiny and click-free-ish (it only raises the facade's typed errors) so the JSON/human split
and the error model stay uniform across every command.
"""

from __future__ import annotations

import sys

import click

from blacksea.control_plane.operations import UsageError, parse_kv
from blacksea.correlation.models import RecordFilter

from .. import render


def resolve_comment(comment: str | None, *, json_mode: bool) -> str | None:
    """Resolve the free-text operator note for a create-a-bait command (`forge` / `instances
    build`).

    * ``--comment`` given → use it (empty string normalises to ``None``);
    * otherwise, when running interactively → **prompt** for one (empty = no comment, which is fine);
    * under ``--json`` or when stdin isn't a TTY (scriptable runs, the e2e harness, tests) →
      never prompt, stay ``None`` — so automation never blocks on input.
    """
    if comment is not None:
        return comment.strip() or None
    if json_mode or not sys.stdin.isatty():
        return None
    entered = click.prompt(
        "Comment for this bait (optional, press Enter to skip)", default="", show_default=False)
    return entered.strip() or None


def show_artifact_after(app, svc, instance_token: str) -> None:
    """Best-effort ``instances artifact`` detail shown right after a successful `forge`/
    `instances build`, so an operator never has to run a follow-up command to see it.

    Deliberately isolated from the forge/build result it follows: `svc.forge()`/`svc.build()`
    have already fully committed (register/build/approve, key written to the brain key
    directory) by the time this runs, so a failure here (a transient DB read, a future change
    to `instance_artifact`) must never be allowed to make an already-successful operation look
    like it failed — this is why the exception is caught broadly rather than left to propagate
    to the command's top-level error handler. Skipped entirely under `--json`, where printing a
    second JSON object would corrupt the e2e harness's single-object `artifact_path` parsing
    (`e2e_tests/lib.sh::bs_forge`'s `grep '^{' | tail -1`)."""
    if app.render.json:
        return
    try:
        art = svc.instance_artifact(instance_token)
    except Exception as exc:
        render.note(
            app.render,
            f"(artifact detail unavailable: {exc} — try `instances artifact {instance_token}`)")
        return
    render.artifact_detail(app.render, art)


def kv(items: list[str] | None, flag: str) -> dict[str, str]:
    """Parse repeated ``KEY=VALUE`` flag values, mapping the shared parser's ``ValueError`` to a
    console `UsageError` (exit 2) so a malformed flag reports as usage, not a crash."""
    try:
        return parse_kv(items, flag)
    except ValueError as exc:
        raise UsageError(str(exc)) from exc


def record_filter(
    *,
    bait_id: str | None = None,
    instance_token: str | None = None,
    campaign_id: str | None = None,
    session_id: str | None = None,
    event_type: str | None = None,
    source_type: str | None = None,
    channel: str | None = None,
    sig_valid: bool | None = None,
    since_ms: int | None = None,
    until_ms: int | None = None,
) -> RecordFilter:
    """Build a `RecordFilter` from the common event/health/session flags (all optional)."""
    return RecordFilter(
        bait_id=bait_id,
        instance_token=instance_token,
        campaign_id=campaign_id,
        session_id=session_id,
        event_type=event_type,
        source_type=source_type,
        channel=channel,
        sig_valid=sig_valid,
        since_ms=since_ms,
        until_ms=until_ms,
    )
