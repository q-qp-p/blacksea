"""listeners.py — freeze the design's listener into the **material** store + hash it
(O10/O11).

The brain no longer scans git for listener source (O9); it imports the *frozen* listener
from ``<artifacts-root>/<bait_id>/<version>/listener/`` (the material half of the
catalog/material split, D7), verifying it against the catalog's ``listener_hash`` (O11)
before ``importlib``-ing it. This module owns:

* :func:`compute_listener_hash` — sha256 over the listener's dependency **closure**
  (source side; used for the version-immutability check at ``register``).
* :func:`freeze_listener` — materialise that closure into the per-``(bait_id, version)``
  ``listener/`` directory at ``register`` (freeze timing, O10) and return its hash.
* :func:`load_frozen_listener` — the brain-side loader: verify the frozen bytes hash to
  the pinned digest, then import the class (Phase 3).

**Closure scope.** Blacksea listeners import only the SDK (``blacksea.sdk.*``, present on
the brain host), the stdlib, and — for a listener that ships its own sibling data file
(e.g. a YAML knowledge base loaded via ``Path(__file__).parent / "..."``) — any filenames
the manifest lists under ``listener_data_files`` (paths relative to the listener module's
own directory). :func:`compute_listener_hash` hashes a ``{relpath: bytes}`` map, so both
the module and its declared data files are covered by the same version-immutability +
brain-side verification guards. A listener that never declares ``listener_data_files``
behaves exactly as the historical single-file case.

**Hash ≠ signature (O11 honest scope).** The stored hash catches *accidental* drift and
enforces version discipline; it is not a defense against an attacker who can write both
the material and the catalog row. A signed delivery channel to the brain host is O10's
still-open sub-item (Phase 5).
"""

from __future__ import annotations

import hashlib
import importlib.util
import os
import sys

LISTENER_SUBDIR = "listener"


class ListenerError(Exception):
    """A listener could not be resolved, frozen, or (brain-side) loaded/verified."""


class ListenerImmutabilityError(ListenerError):
    """A ``(bait_id, version)`` was re-registered with a differently-hashing listener
    (O11 #1). A version's listener is immutable — bump the version to change it."""


def resolve_listener_ref(manifest: dict) -> tuple[str, str]:
    """Split ``listener_class`` into ``(module_ref, class_name)``. ``module_ref`` may be
    a ``../``-relative path into the ``lure_material/`` catalog (manifest-only authoring
    model) — resolved against the bait dir by the caller. Raises ``ListenerError`` on a
    malformed ref."""
    ref = str(manifest.get("listener_class", ""))
    if "." not in ref:
        raise ListenerError(f"listener_class {ref!r} must be '<module>.<ClassName>'")
    module_ref, class_name = ref.rsplit(".", 1)
    return module_ref, class_name


def _collect_closure(bait_dir: str, manifest: dict) -> dict[str, bytes]:
    """Return the listener's dependency closure as ``{relpath: bytes}``: the
    ``<module_ref>.py`` file itself, keyed by its basename (so the frozen copy is
    importable as ``<basename>``), plus any sibling data files the manifest declares
    under ``listener_data_files`` (filenames resolved relative to the listener module's
    own directory, keyed by that same filename so ``Path(__file__).parent / "<name>"``
    resolves identically against the frozen copy)."""
    module_ref, _ = resolve_listener_ref(manifest)
    src = os.path.join(bait_dir, module_ref + ".py")
    if not os.path.isfile(src):
        raise ListenerError(f"listener file not found: {src!r}")
    with open(src, "rb") as f:
        data = f.read()
    basename = os.path.basename(module_ref) + ".py"
    files = {basename: data}

    module_dir = os.path.dirname(module_ref)
    for rel in manifest.get("listener_data_files") or []:
        data_src = os.path.join(bait_dir, module_dir, rel)
        if not os.path.isfile(data_src):
            raise ListenerError(f"listener data file not found: {data_src!r}")
        with open(data_src, "rb") as f:
            files[rel] = f.read()
    return files


def _hash_closure(files: dict[str, bytes]) -> str:
    """Deterministic sha256 over a ``{relpath: bytes}`` closure. Length-framed and
    sorted so the digest is stable regardless of dict order and unambiguous across
    file boundaries."""
    h = hashlib.sha256()
    for rel in sorted(files):
        blob = files[rel]
        h.update(f"{rel}\0{len(blob)}\0".encode())
        h.update(blob)
    return h.hexdigest()


def compute_listener_hash(bait_dir: str, manifest: dict) -> str:
    """Hash the *source* listener closure (pre-freeze). Used for the version-immutability
    check at ``register`` before anything is written."""
    return _hash_closure(_collect_closure(bait_dir, manifest))


def frozen_listener_dir(artifacts_root: str, bait_id: str, version: str) -> str:
    """Location of the frozen listener for a ``(bait_id, version)`` — derived from IDs,
    never a stored path (O9)."""
    return os.path.join(artifacts_root, bait_id, version, LISTENER_SUBDIR)


def freeze_listener(
    bait_dir: str,
    manifest: dict,
    *,
    artifacts_root: str,
    bait_id: str,
    version: str,
) -> str:
    """Materialise the listener closure into ``<artifacts-root>/<bait_id>/<version>/
    listener/`` (O10 freeze-at-register) and return its sha256. Idempotent: re-freezing
    the same source rewrites identical bytes. Returns the same value
    :func:`compute_listener_hash` did for the same source."""
    files = _collect_closure(bait_dir, manifest)
    dest_dir = frozen_listener_dir(artifacts_root, bait_id, version)
    os.makedirs(dest_dir, exist_ok=True)
    for rel, blob in files.items():
        dest = os.path.join(dest_dir, rel)
        os.makedirs(os.path.dirname(dest) or dest_dir, exist_ok=True)
        with open(dest, "wb") as f:
            f.write(blob)
    return _hash_closure(files)


def freeze_and_check(
    registry,
    *,
    artifacts_root: str,
    bait_id: str,
    version: str,
    bait_dir: str,
    manifest: dict,
) -> str:
    """Register-time guard + freeze (O10/O11 #1). If a design already exists for
    ``bait_id`` at the *same* ``version`` with a different ``listener_hash``, raise
    ``ListenerImmutabilityError`` (a version's listener is immutable). Otherwise freeze
    the closure and return its hash for the caller to record on the design row."""
    new_hash = compute_listener_hash(bait_dir, manifest)
    prior = registry.get_design(bait_id)
    if (prior is not None and prior.version == version
            and prior.listener_hash and prior.listener_hash != new_hash):
        raise ListenerImmutabilityError(
            f"listener for {bait_id!r} v{version} changed "
            f"(hash {prior.listener_hash[:12]}… → {new_hash[:12]}…) — bump the version")
    frozen_hash = freeze_listener(
        bait_dir, manifest, artifacts_root=artifacts_root, bait_id=bait_id, version=version)
    return frozen_hash


# ── brain-side load (Phase 3) ────────────────────────────────────────────────


def load_frozen_listener(
    artifacts_root: str,
    bait_id: str,
    version: str,
    manifest: dict,
    *,
    expected_hash: str | None,
):
    """Import the frozen listener class for ``(bait_id, version)`` from the material store,
    **verifying the bytes against ``expected_hash`` first** (O11 #3). A mismatch (drift or
    tampering) raises ``ListenerError`` so the brain can refuse to load it (dead-letter +
    alert) rather than ``importlib``-ing untrusted code. Returns an instantiated listener.
    """
    _, class_name = resolve_listener_ref(manifest)
    dest_dir = frozen_listener_dir(artifacts_root, bait_id, version)
    module_ref, _ = resolve_listener_ref(manifest)
    module_basename = os.path.basename(module_ref)
    listener_path = os.path.join(dest_dir, module_basename + ".py")
    if not os.path.isfile(listener_path):
        raise ListenerError(
            f"frozen listener for {bait_id!r} v{version} not found at {listener_path!r} "
            f"(register freezes it — is the material store present on this host? O10)")

    # Re-hash the frozen closure (module + any declared data files) and compare against
    # the catalog's pinned digest (O11).
    frozen_files: dict[str, bytes] = {}
    with open(listener_path, "rb") as f:
        frozen_files[module_basename + ".py"] = f.read()
    for rel in manifest.get("listener_data_files") or []:
        data_path = os.path.join(dest_dir, rel)
        if not os.path.isfile(data_path):
            raise ListenerError(
                f"frozen listener data file for {bait_id!r} v{version} not found at "
                f"{data_path!r} (register freezes it alongside the module — O10)")
        with open(data_path, "rb") as f:
            frozen_files[rel] = f.read()
    actual = _hash_closure(frozen_files)
    if expected_hash is not None and actual != expected_hash:
        raise ListenerError(
            f"frozen listener hash mismatch for {bait_id!r} v{version}: "
            f"expected {expected_hash[:12]}…, got {actual[:12]}… — refusing to import (O11)")

    synthetic = f"_frozen_bait_{bait_id}_{version}_{module_basename}".replace(".", "_").replace("-", "_")
    spec = importlib.util.spec_from_file_location(synthetic, listener_path)
    if spec is None or spec.loader is None:
        raise ListenerError(f"cannot create import spec for {listener_path!r}")
    mod = importlib.util.module_from_spec(spec)
    sys.modules[synthetic] = mod
    try:
        spec.loader.exec_module(mod)
    except BaseException:
        sys.modules.pop(synthetic, None)
        raise
    cls = getattr(mod, class_name, None)
    if cls is None:
        raise ListenerError(f"frozen listener module has no class {class_name!r}")
    return cls()
