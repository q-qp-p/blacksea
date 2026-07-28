"""Phase 2/3 — listener freeze (O10), content hash + version-immutability (O11), and the
brain-side hash-verified load."""

from __future__ import annotations

import os

import pytest

from blacksea.control_plane import listeners
from blacksea.control_plane.registry import DesignRecord

_LISTENER_A = "class MyListener:\n    def interpret(self, envelope, body):\n        return None\n"
_LISTENER_B = "class MyListener:\n    def interpret(self, envelope, body):\n        return 'CHANGED'\n"


def _bait(tmp_path, src, name="a"):
    d = tmp_path / f"bait_{name}"
    d.mkdir(exist_ok=True)
    (d / "listener.py").write_text(src)
    return str(d), {"listener_class": "listener.MyListener", "version": "1.0.0"}


def test_freeze_writes_closure_and_hash_matches_source(tmp_path):
    bait_dir, manifest = _bait(tmp_path, _LISTENER_A)
    artifacts = str(tmp_path / "artifacts")
    h = listeners.freeze_listener(
        bait_dir, manifest, artifacts_root=artifacts, bait_id="x", version="1.0.0")
    frozen = listeners.frozen_listener_dir(artifacts, "x", "1.0.0")
    assert os.path.isfile(os.path.join(frozen, "listener.py"))
    # The frozen hash equals the pre-freeze source hash (freeze copies verbatim).
    assert h == listeners.compute_listener_hash(bait_dir, manifest)


def test_immutability_same_version_changed_listener_errors(registry, tmp_path):
    artifacts = str(tmp_path / "artifacts")
    bait_dir, manifest = _bait(tmp_path, _LISTENER_A)
    h1 = listeners.freeze_and_check(
        registry, artifacts_root=artifacts, bait_id="x", version="1.0.0",
        bait_dir=bait_dir, manifest=manifest)
    registry.put_design(DesignRecord(
        bait_id="x", manifest=manifest, bait_dir=bait_dir, listener_hash=h1))

    # Edit the listener but keep the same version → must error (O11 #1).
    (tmp_path / "bait_a" / "listener.py").write_text(_LISTENER_B)
    with pytest.raises(listeners.ListenerImmutabilityError):
        listeners.freeze_and_check(
            registry, artifacts_root=artifacts, bait_id="x", version="1.0.0",
            bait_dir=bait_dir, manifest=manifest)


def test_version_bump_freezes_new_copy(registry, tmp_path):
    artifacts = str(tmp_path / "artifacts")
    bait_dir, manifest = _bait(tmp_path, _LISTENER_A)
    h1 = listeners.freeze_and_check(
        registry, artifacts_root=artifacts, bait_id="x", version="1.0.0",
        bait_dir=bait_dir, manifest=manifest)
    registry.put_design(DesignRecord(
        bait_id="x", manifest={**manifest, "version": "1.0.0"},
        bait_dir=bait_dir, listener_hash=h1))

    # New version + changed listener → new frozen copy, new hash, no error.
    (tmp_path / "bait_a" / "listener.py").write_text(_LISTENER_B)
    manifest_v2 = {**manifest, "version": "2.0.0"}
    h2 = listeners.freeze_and_check(
        registry, artifacts_root=artifacts, bait_id="x", version="2.0.0",
        bait_dir=bait_dir, manifest=manifest_v2)
    assert h2 != h1
    assert os.path.isfile(os.path.join(
        listeners.frozen_listener_dir(artifacts, "x", "2.0.0"), "listener.py"))
    assert os.path.isfile(os.path.join(
        listeners.frozen_listener_dir(artifacts, "x", "1.0.0"), "listener.py"))  # v1 still there


def test_reregister_identical_listener_is_noop(registry, tmp_path):
    artifacts = str(tmp_path / "artifacts")
    bait_dir, manifest = _bait(tmp_path, _LISTENER_A)
    h1 = listeners.freeze_and_check(
        registry, artifacts_root=artifacts, bait_id="x", version="1.0.0",
        bait_dir=bait_dir, manifest=manifest)
    registry.put_design(DesignRecord(
        bait_id="x", manifest=manifest, bait_dir=bait_dir, listener_hash=h1))
    # Same version, unchanged listener → same hash, no error.
    h2 = listeners.freeze_and_check(
        registry, artifacts_root=artifacts, bait_id="x", version="1.0.0",
        bait_dir=bait_dir, manifest=manifest)
    assert h2 == h1


def test_load_frozen_listener_verifies_hash(tmp_path):
    artifacts = str(tmp_path / "artifacts")
    bait_dir, manifest = _bait(tmp_path, _LISTENER_A)
    h = listeners.freeze_listener(
        bait_dir, manifest, artifacts_root=artifacts, bait_id="x", version="1.0.0")

    # Correct hash → imports fine.
    inst = listeners.load_frozen_listener(artifacts, "x", "1.0.0", manifest, expected_hash=h)
    assert inst.__class__.__name__ == "MyListener"

    # Tamper the frozen bytes → refuse to import (O11 #3).
    frozen_file = os.path.join(listeners.frozen_listener_dir(artifacts, "x", "1.0.0"), "listener.py")
    with open(frozen_file, "a") as f:
        f.write("\n# tampered\n")
    with pytest.raises(listeners.ListenerError):
        listeners.load_frozen_listener(artifacts, "x", "1.0.0", manifest, expected_hash=h)


def test_load_frozen_listener_missing_material_errors(tmp_path):
    _, manifest = _bait(tmp_path, _LISTENER_A)
    with pytest.raises(listeners.ListenerError):
        listeners.load_frozen_listener(
            str(tmp_path / "artifacts"), "ghost", "1.0.0", manifest, expected_hash=None)
