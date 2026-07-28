"""brain_keydir.py — writer for the brain's key directory (see control_plane/context.md and
src/blacksea/brain/context.md).

This is the **sole** key directory in the system now that the edge is a dumb dead-drop (it holds
no directory of its own — see ``edge/context.md``). It carries ``key`` (the per-instance
HMAC-SHA256 master key) and stays on brain-controlled infra, never crossing the edge-facing diode.
The factory generates ``_KEY`` at ``build()`` time and it is only ever in memory transiently
(``BuildOutcome.key_hex``); the caller (``operations.build_instance_op`` / ``forge.forge_bait``)
writes it here immediately, in the same step, so the key never round-trips through the registry
(inv 16).

Lifecycle transitions (approve/burn/retire/revoke) call ``sync_routing_fields`` to refresh the
non-key fields from the registry — a merge against existing entries rather than a full rebuild,
since the registry never stores ``key`` to rebuild it from.
"""

from __future__ import annotations

import json
import os
import tempfile

from blacksea.control_plane.registry import DesignRecord, Registry


def upsert_key_entry(
    path: str,
    *,
    instance_token_hex: str,
    key_hex: str,
    status: str,
    bait_id: str,
    campaign_id: str,
    assurance_tier: int,
    default_channel: str,
    valid_from: int,
    valid_until: int | None = None,
) -> None:
    """Insert or replace one instance's entry, keyed by instance_token.

    Called by the CLI immediately after ``factory.build_instance()`` returns — the only
    window in which ``_KEY`` bytes exist outside the built artifact (inv 16)."""
    entries = _read(path)
    entries = [e for e in entries if e["instance_token"] != instance_token_hex]
    entry = {
        "instance_token": instance_token_hex,
        "key": key_hex,
        "status": status,
        "bait_id": bait_id,
        "campaign_id": campaign_id,
        "assurance_tier": assurance_tier,
        "default_channel": default_channel,
        "valid_from": valid_from,
    }
    if valid_until is not None:
        entry["valid_until"] = valid_until
    entries.append(entry)
    entries.sort(key=lambda e: e["instance_token"])
    _write(path, entries)


def sync_routing_fields(path: str, registry: Registry) -> None:
    """Refresh status/bait_id/campaign_id/assurance_tier/default_channel for every entry
    already present in the brain keydir, from the current registry state.

    Never touches ``key`` — this file is the only server-side place that value lives,
    and the registry never stored it to refresh from in the first place. An
    instance_token with no matching registry record (shouldn't happen) is left untouched
    rather than dropped, so a late hit can still decrypt (inv 6)."""
    entries = _read(path)
    if not entries:
        return
    designs: dict[str, DesignRecord] = {d.bait_id: d for d in registry.list_designs()}
    instances = {i.instance_token: i for i in registry.list_instances()}
    for e in entries:
        inst = instances.get(e["instance_token"])
        if inst is None:
            continue
        design = designs.get(inst.bait_id)
        e["status"] = inst.status
        e["bait_id"] = inst.bait_id
        e["campaign_id"] = inst.campaign_id
        if design is not None:
            e["assurance_tier"] = design.assurance_tier
            e["default_channel"] = design.default_channel
    _write(path, entries)


def _read(path: str) -> list[dict]:
    if not os.path.exists(path):
        return []
    with open(path) as f:
        return json.load(f)


def _write(path: str, entries: list[dict]) -> None:
    directory = os.path.dirname(os.path.abspath(path)) or "."
    # This file carries per-instance `_KEY`, so a freshly-created key directory (e.g.
    # secrets/keys/) must not be world-traversable — create it 0700. A pre-existing directory
    # (the cwd for a legacy path, or an already-0700 secrets/) is left as-is: `mode` is ignored
    # under `exist_ok=True`, so we never chmod a dir we didn't create. The file itself is 0600
    # (mkstemp default), preserved across the os.replace below.
    os.makedirs(directory, mode=0o700, exist_ok=True)
    fd, tmp = tempfile.mkstemp(dir=directory, suffix=".tmp")
    try:
        with os.fdopen(fd, "w") as f:
            json.dump(entries, f, indent=2)
            f.write("\n")
            f.flush()
            os.fsync(f.fileno())
        os.replace(tmp, path)
    except BaseException:
        try:
            os.unlink(tmp)
        except FileNotFoundError:
            pass
        raise
