"""lifecycle.py — the design + instance state machines (see context.md's "Lifecycle
state machines" section).

Each transition runs its mutation(s) inside **one** ``Registry.transaction()`` (O3):
it reads the record(s) ``FOR UPDATE`` (so racing transitions serialize — Motivation
#2), validates the current state, applies the new state (+ its timestamp), and writes
the record(s) back. Illegal transitions raise ``TransitionError`` and change nothing.
A crash mid-transition rolls the whole block back to *neither* write (Motivation #1).
``approve``'s instance-activate + design-promote are a single atomic commit, killing
the old two-file-write window.

A ``publish`` callback is injected so this module stays decoupled from the key
directory (and tests can assert "publish was called" without writing files). It runs
**after commit** and refreshes the brain key directory's routing fields so a
burn/retire/revoke is reflected to the brain. There is no edge directory or snapshot
``seq`` anymore — the edge is a dumb dead-drop that holds no directory (see
``edge/context.md``); the brain resolves all routing from ``tok``.
"""

from __future__ import annotations

from typing import Callable

from blacksea.control_plane.registry import (
    DesignRecord,
    InstanceRecord,
    Registry,
    replace,
)

# Allowed transitions. Key = current state; value = set of legal next
# states. ``revoked`` is reachable only by explicit operator command (burn ≠
# revoke) — never from automation.
_DESIGN_TRANSITIONS = {
    "draft": {"staged"},
    "staged": {"deployed", "burned", "retired"},
    "deployed": {"burned", "retired"},
    "burned": {"retired"},
    "retired": set(),
}
_INSTANCE_TRANSITIONS = {
    "pending": {"active"},
    "active": {"burned", "retired", "revoked"},
    "burned": {"retired", "revoked"},
    "retired": set(),
    "revoked": {"retired"},
}

# The publish callback runs after the transaction commits and refreshes the brain key
# directory's routing fields. No arguments: there is no snapshot seq to pass anymore.
Publish = Callable[[], object]


class TransitionError(Exception):
    """An illegal lifecycle transition, or a missing record."""


# ── design-level transitions ─────────────────────────────────────────────────


def stage_design(registry: Registry, bait_id: str, *, now: str,
                 publish: Publish | None = None) -> DesignRecord:
    """draft → staged: control-plane reconciliation (pool module loaded)."""
    with registry.transaction() as tx:
        design = _require_design(tx, bait_id)
        _check(_DESIGN_TRANSITIONS, design.status, "staged", f"design {bait_id!r}")
        design = replace(design, status="staged", staged_at=now)
        tx.put_design(design)
    _publish(publish)
    return design


def burn_design(registry: Registry, bait_id: str, *, reason: str, now: str,
                publish: Publish | None = None) -> DesignRecord:
    """staged|deployed → burned: pattern recognized; stop accepting new instances
    but keep the pool worker running for late hits (inv 6)."""
    with registry.transaction() as tx:
        design = _require_design(tx, bait_id)
        _check(_DESIGN_TRANSITIONS, design.status, "burned", f"design {bait_id!r}")
        design = replace(design, status="burned", burned_at=now)
        tx.put_design(design)
    _publish(publish)
    return design


def retire_design(registry: Registry, bait_id: str, *, now: str,
                  publish: Publish | None = None) -> DesignRecord:
    """deployed|burned|staged → retired: irreversible operator decision."""
    with registry.transaction() as tx:
        design = _require_design(tx, bait_id)
        _check(_DESIGN_TRANSITIONS, design.status, "retired", f"design {bait_id!r}")
        design = replace(design, status="retired", retired_at=now)
        tx.put_design(design)
    _publish(publish)
    return design


# ── instance-level transitions ───────────────────────────────────────────────


def approve_instance(registry: Registry, instance_token: str, *, now: str,
                     publish: Publish | None = None) -> InstanceRecord:
    """pending → active: the human approval gate. Sets ``approved_at``
    (which becomes the directory entry's ``valid_from`` — see context.md's "Brain key
    directory — write side" section) and promotes the
    parent design ``staged → deployed`` on its first active instance — **atomically**
    (the instance-activate and the design-promote commit together, O3/Motivation #1)."""
    with registry.transaction() as tx:
        inst = _require_instance(tx, instance_token)
        _check(_INSTANCE_TRANSITIONS, inst.status, "active", f"instance {instance_token!r}")
        inst = replace(inst, status="active", approved_at=now)
        tx.put_instance(inst)

        # staged → deployed on the first active instance, in the same transaction.
        design = tx.get_design(inst.bait_id)
        if design is not None and design.status == "staged":
            tx.put_design(replace(design, status="deployed"))

    _publish(publish)
    return inst


def burn_instance(registry: Registry, instance_token: str, *, reason: str, now: str,
                  publish: Publish | None = None) -> InstanceRecord:
    """active|burned → burned: token recognized; key stays in the directory so
    late hits are stored + tagged (inv 6)."""
    with registry.transaction() as tx:
        inst = _require_instance(tx, instance_token)
        _check(_INSTANCE_TRANSITIONS, inst.status, "burned", f"instance {instance_token!r}")
        inst = replace(inst, status="burned", burned_at=now)
        tx.put_instance(inst)
    _publish(publish)
    return inst


def retire_instance(registry: Registry, instance_token: str, *, now: str,
                    publish: Publish | None = None) -> InstanceRecord:
    """active|burned|revoked → retired: stood down, not replaced. Key kept for
    late hits, tagged orphan (inv 6)."""
    with registry.transaction() as tx:
        inst = _require_instance(tx, instance_token)
        _check(_INSTANCE_TRANSITIONS, inst.status, "retired", f"instance {instance_token!r}")
        inst = replace(inst, status="retired", retired_at=now)
        tx.put_instance(inst)
    _publish(publish)
    return inst


def revoke_instance(registry: Registry, instance_token: str, *, now: str,
                    publish: Publish | None = None) -> InstanceRecord:
    """active|burned → revoked: key weaponized (DoS/poisoning replay). The brain
    decrypts-to-identify, then heavy-samples + alerts. Operator-only."""
    with registry.transaction() as tx:
        inst = _require_instance(tx, instance_token)
        _check(_INSTANCE_TRANSITIONS, inst.status, "revoked", f"instance {instance_token!r}")
        inst = replace(inst, status="revoked")
        tx.put_instance(inst)
    _publish(publish)
    return inst


# ── helpers ──────────────────────────────────────────────────────────────────


def _require_design(tx, bait_id: str) -> DesignRecord:
    design = tx.get_design(bait_id)
    if design is None:
        raise TransitionError(f"no such design: {bait_id!r}")
    return design


def _require_instance(tx, instance_token: str) -> InstanceRecord:
    inst = tx.get_instance(instance_token)
    if inst is None:
        raise TransitionError(f"no such instance: {instance_token!r}")
    return inst


def _check(table: dict[str, set[str]], current: str, target: str, what: str) -> None:
    allowed = table.get(current)
    if allowed is None:
        raise TransitionError(f"{what}: unknown current state {current!r}")
    if target not in allowed:
        legal = sorted(allowed) or ["(terminal)"]
        raise TransitionError(
            f"{what}: cannot go {current!r} → {target!r}; legal from {current!r}: {legal}"
        )


def _publish(publish: Publish | None) -> None:
    """Invoke the publish callback after the transaction has committed (it refreshes the
    brain key directory). Guarded so transitions without a publisher — e.g. unit tests —
    commit their state without touching the key directory."""
    if publish is not None:
        publish()
