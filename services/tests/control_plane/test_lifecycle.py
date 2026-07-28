"""Lifecycle state machines (see context.md's "Lifecycle state machines" section; now over
the Postgres catalog, in transactions)."""

from __future__ import annotations

import pytest

from blacksea.control_plane import lifecycle
from blacksea.control_plane.registry import DesignRecord, InstanceRecord


def _seed(registry, *, design_status="staged", instance_status="pending"):
    registry.put_design(DesignRecord(
        bait_id="b", manifest={"version": "1.0.0", "channels": {"dns": {}},
                               "assurance_tier": 0, "deploy_class": "portable_artifact"},
        bait_dir="/x", status=design_status,
    ))
    registry.put_instance(InstanceRecord(
        instance_token="aabbccddeeff0011", bait_id="b", bait_version="1.0.0",
        key_ref="r", campaign_id="C", callback_addresses={},
        status=instance_status,
    ))
    return registry


def test_approve_promotes_design_to_deployed(registry):
    _seed(registry)
    published = []
    lifecycle.approve_instance(registry, "aabbccddeeff0011", now="t1",
                               publish=lambda: published.append(True))
    assert registry.get_instance("aabbccddeeff0011").status == "active"
    assert registry.get_instance("aabbccddeeff0011").approved_at == "t1"
    assert registry.get_design("b").status == "deployed"   # staged → deployed
    assert published == [True]                             # publish ran after commit


def test_publish_omitted_still_commits_state(registry):
    """A transition with no publisher (e.g. a test) commits its mutation without touching the
    brain key directory — the publish callback is what refreshes it."""
    _seed(registry)
    lifecycle.approve_instance(registry, "aabbccddeeff0011", now="t1")
    assert registry.get_instance("aabbccddeeff0011").status == "active"


def test_cannot_approve_twice(registry):
    _seed(registry, instance_status="active")
    with pytest.raises(lifecycle.TransitionError):
        lifecycle.approve_instance(registry, "aabbccddeeff0011", now="t2")


def test_burn_then_retire_instance(registry):
    _seed(registry, instance_status="active")
    lifecycle.burn_instance(registry, "aabbccddeeff0011", reason="seen", now="t1")
    assert registry.get_instance("aabbccddeeff0011").status == "burned"
    lifecycle.retire_instance(registry, "aabbccddeeff0011", now="t2")
    assert registry.get_instance("aabbccddeeff0011").status == "retired"


def test_retired_is_terminal(registry):
    _seed(registry, instance_status="retired")
    with pytest.raises(lifecycle.TransitionError):
        lifecycle.burn_instance(registry, "aabbccddeeff0011", reason="x", now="t3")


def test_revoke_only_from_active_or_burned(registry):
    _seed(registry, instance_status="active")
    lifecycle.revoke_instance(registry, "aabbccddeeff0011", now="t1")
    assert registry.get_instance("aabbccddeeff0011").status == "revoked"


def test_burned_design_blocks_no_transition_back(registry):
    _seed(registry, design_status="deployed")
    lifecycle.burn_design(registry, "b", reason="pattern", now="t1")
    assert registry.get_design("b").status == "burned"
    # burned → staged is illegal
    with pytest.raises(lifecycle.TransitionError):
        lifecycle.stage_design(registry, "b", now="t2")


def test_unknown_record_raises(registry):
    with pytest.raises(lifecycle.TransitionError):
        lifecycle.approve_instance(registry, "deadbeefdeadbeef", now="t1")
