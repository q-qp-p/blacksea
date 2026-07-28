"""Brain key directory (see context.md's "Brain key directory — write side" section): the
sole key directory, carrying `_KEY`, on brain-controlled
infra (the edge is a dumb dead-drop with no directory of its own)."""

from __future__ import annotations

import json

from blacksea.brain.verifier import KeyDirectory  # the real brain-side consumer
from blacksea.control_plane import brain_keydir
from blacksea.control_plane.registry import DesignRecord, InstanceRecord, Registry

_KEY_HEX = "11" * 32


def _registry_with(reg: Registry, instances) -> Registry:
    reg.put_design(DesignRecord(
        bait_id="hostname-probe",
        manifest={"version": "1.0.0", "assurance_tier": 2,
                  "deploy_class": "portable_artifact", "channels": {"https": {}}},
        bait_dir="/x", status="deployed",
    ))
    for inst in instances:
        reg.put_instance(inst)
    return reg


def _inst(token, status="active", **kw):
    return InstanceRecord(
        instance_token=token, bait_id="hostname-probe", bait_version="1.0.0",
        key_ref="artifact-embedded", campaign_id="C-T",
        callback_addresses={"https": "z"}, status=status, **kw,
    )


def test_upsert_is_consumable_by_brain(tmp_path):
    """The factory's write path: upsert_key_entry() writes `key`, which the brain's
    real KeyDirectory.from_file() consumer can then decrypt with."""
    path = str(tmp_path / "brain_keydir.json")
    brain_keydir.upsert_key_entry(
        path,
        instance_token_hex="aabbccddeeff0011",
        key_hex=_KEY_HEX,
        status="pending",
        bait_id="hostname-probe",
        campaign_id="C-T",
        assurance_tier=2,
        default_channel="https",
        valid_from=0,
    )
    kd = KeyDirectory.from_file(path)
    entry = kd.lookup(bytes.fromhex("aabbccddeeff0011"))
    assert entry is not None
    assert entry.key_bytes == bytes.fromhex(_KEY_HEX)
    assert entry.status == "pending"
    assert entry.bait_id == "hostname-probe"


def test_upsert_replaces_existing_entry(tmp_path):
    path = str(tmp_path / "brain_keydir.json")
    brain_keydir.upsert_key_entry(
        path, instance_token_hex="aabbccddeeff0011", key_hex=_KEY_HEX,
        status="pending", bait_id="hostname-probe", campaign_id="C-T",
        assurance_tier=2, default_channel="https", valid_from=0,
    )
    brain_keydir.upsert_key_entry(
        path, instance_token_hex="aabbccddeeff0011", key_hex="22" * 32,
        status="active", bait_id="hostname-probe", campaign_id="C-T",
        assurance_tier=2, default_channel="https", valid_from=100,
    )
    arr = json.load(open(path))
    assert len(arr) == 1
    assert arr[0]["key"] == "22" * 32
    assert arr[0]["status"] == "active"


def test_sync_routing_fields_updates_status_without_touching_key(registry, tmp_path):
    """A lifecycle refresh merges routing fields against existing entries instead of
    rebuilding — the registry never stored `key` to rebuild from."""
    path = str(tmp_path / "brain_keydir.json")
    brain_keydir.upsert_key_entry(
        path, instance_token_hex="aabbccddeeff0011", key_hex=_KEY_HEX,
        status="pending", bait_id="hostname-probe", campaign_id="C-T",
        assurance_tier=2, default_channel="https", valid_from=0,
    )
    reg = _registry_with(registry, [_inst("aabbccddeeff0011", status="active")])

    brain_keydir.sync_routing_fields(path, reg)

    arr = json.load(open(path))
    assert len(arr) == 1
    assert arr[0]["status"] == "active"          # refreshed from the registry
    assert arr[0]["key"] == _KEY_HEX             # untouched — registry never had it


def test_sync_routing_fields_leaves_unknown_tokens_alone(tmp_path, registry):
    """A token with no matching registry record is left as-is (not dropped) — a late
    hit must still be able to decrypt (inv 6)."""
    path = str(tmp_path / "brain_keydir.json")
    brain_keydir.upsert_key_entry(
        path, instance_token_hex="deadbeefdeadbeef", key_hex=_KEY_HEX,
        status="retired", bait_id="hostname-probe", campaign_id="C-T",
        assurance_tier=2, default_channel="https", valid_from=0,
    )
    # `registry` is empty — no matching instance record.
    brain_keydir.sync_routing_fields(path, registry)

    arr = json.load(open(path))
    assert arr[0]["status"] == "retired"
    assert arr[0]["key"] == _KEY_HEX


def test_sync_routing_fields_noop_on_empty_file(tmp_path, registry):
    path = str(tmp_path / "brain_keydir.json")  # never created
    brain_keydir.sync_routing_fields(path, registry)  # must not raise or create the file
    import os
    assert not os.path.exists(path)
