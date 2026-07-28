"""ingestion.py — manifest parsing + the validation rules (see context.md's "Ingestion
validation rules" section for the full rule table).

The control plane is the only component that reads a bait without executing its
payload. Ingestion is the gate: parse ``manifest.yaml``, run every validation rule,
load the listener class, check it implements the ``Listener`` ABC, and run its
``golden_cases()`` offline. Any blocking failure returns a structured error —
**never a silent pass** (context.md invariant).

The result is a list of ``Issue`` records (each ``error`` or ``warn``). A clean
ingest = zero errors; warnings surface review-worthy facts (tier/channel mismatch,
interactive-service segmentation, high DNS burst) without blocking.
"""

from __future__ import annotations

import importlib.util
import os
import sys
from dataclasses import dataclass

import yaml

from blacksea.sdk.abc import Listener
from blacksea.sdk.testing import run_golden_cases

# Channels with a registered edge receiver today (DNS + HTTPS are frozen;
# tcp/icmp are additive future receivers). An unknown channel is a deliberate
# surface change, not a hot-wire, so ingestion blocks on it.
KNOWN_CHANNELS = frozenset({"dns", "https"})

# Channels that carry no signature and so pin a bait to tier 0.
TIER0_ONLY_CHANNELS = frozenset({"dns", "icmp"})

KNOWN_ENVELOPE_VERSIONS = frozenset({1})

DEPLOY_CLASSES = frozenset({"portable_artifact", "host_resident", "interactive_service"})
ISOLATION_CLASSES = frozenset({"in_process", "subprocess", "sandboxed"})

# Required top-level manifest fields plus the three-component authoring
# fields the factory needs (listener_class/payload_file/staging_vessel).
_REQUIRED_FIELDS = (
    "bait_id",
    "version",
    "description",
    "assurance_tier",
    "deploy_class",
    "channels",
    "envelope_version",
    "provenance",
    "build",
    "listener_class",
    "payload_file",
    "staging_vessel",
)


@dataclass
class Issue:
    severity: str   # "error" | "warn"
    rule: str
    message: str

    def __str__(self) -> str:
        mark = "✗" if self.severity == "error" else "⚠"
        return f"  {mark} [{self.rule}] {self.message}"


@dataclass
class IngestResult:
    bait_id: str
    manifest: dict
    issues: list[Issue]
    # True when ``deploy_class: interactive_service`` — staging needs an explicit
    # operator acknowledgement (inv 14).
    requires_ack: bool = False

    @property
    def errors(self) -> list[Issue]:
        return [i for i in self.issues if i.severity == "error"]

    @property
    def warnings(self) -> list[Issue]:
        return [i for i in self.issues if i.severity == "warn"]

    @property
    def ok(self) -> bool:
        return not self.errors


class IngestError(Exception):
    """Raised when a manifest cannot even be parsed (vs. a validation failure,
    which is reported as an ``Issue`` in the result)."""


def load_manifest(bait_dir: str) -> dict:
    """Parse ``<bait_dir>/manifest.yaml``. Raises ``IngestError`` if missing or
    not a YAML mapping."""
    path = os.path.join(bait_dir, "manifest.yaml")
    if not os.path.exists(path):
        raise IngestError(f"no manifest.yaml in {bait_dir!r}")
    with open(path) as f:
        manifest = yaml.safe_load(f)
    if not isinstance(manifest, dict):
        raise IngestError(f"manifest.yaml in {bait_dir!r} is not a mapping")
    return manifest


def ingest(
    bait_dir: str,
    existing_bait_ids: frozenset[str] | set[str],
    *,
    refresh_bait_id: str | None = None,
) -> IngestResult:
    """Run full validation on the bait at ``bait_dir``.

    ``existing_bait_ids`` is the set already in the registry (for the uniqueness
    rule). When ``refresh_bait_id`` is set, that id is exempt from the uniqueness
    check so ``register --refresh`` can reload an updated manifest from disk.
    Returns an ``IngestResult``; check ``.ok`` before reconciling.
    """
    manifest = load_manifest(bait_dir)
    bait_id = str(manifest.get("bait_id", "")) or "<missing>"
    issues: list[Issue] = []

    def err(rule: str, msg: str) -> None:
        issues.append(Issue("error", rule, msg))

    def warn(rule: str, msg: str) -> None:
        issues.append(Issue("warn", rule, msg))

    # ── required fields present ──────────────────────────────────────────────
    for field_name in _REQUIRED_FIELDS:
        if manifest.get(field_name) in (None, "", {}, []):
            err("required-field", f"manifest field {field_name!r} is missing or empty")

    # bait_id uniqueness — skipped for the id being refreshed from disk.
    if bait_id in existing_bait_ids and bait_id != refresh_bait_id:
        err("bait-id-unique",
            f"bait_id {bait_id!r} already registered; use a new id, bump version, "
            f"or `register --refresh` to reload the manifest from disk")

    # ── provenance gate ───────────────────────────────────────────────────────
    prov = manifest.get("provenance") or {}
    for sub in ("behavior", "source", "observed_date"):
        if not str(prov.get(sub, "")).strip():
            err("provenance",
                f"provenance.{sub} required — cite the attacker behavior (no generic bait)")

    # ── channels ──────────────────────────────────────────────────────────────
    channels = manifest.get("channels") or {}
    if not channels:
        err("channels", "at least one channel is required")
    unknown = sorted(set(channels) - KNOWN_CHANNELS)
    for ch in unknown:
        err("channel-receiver",
            f"channel {ch!r} has no edge receiver — deliberate surface change required")

    tier = manifest.get("assurance_tier")
    chan_names = set(channels)
    if tier == 0:
        if chan_names and not chan_names <= TIER0_ONLY_CHANNELS:
            warn("tier-channel",
                 "assurance_tier 0 with a fat channel — tier-0 is signal-only; "
                 "the fat channel will be treated as tier-0 by default")
    elif tier in (1, 2):
        if chan_names and chan_names <= TIER0_ONLY_CHANNELS:
            warn("tier-channel",
                 "tier ≥ 1 requires a fat channel for signature delivery; "
                 "DNS is tier-0 only by default")
    else:
        err("assurance-tier", f"assurance_tier must be 0, 1 or 2 (got {tier!r})")

    # dns.max_chunks ceiling
    dns_cfg = channels.get("dns") or {}
    max_chunks = dns_cfg.get("max_chunks")
    if isinstance(max_chunks, int) and max_chunks > 50:
        warn("dns-burst",
             f"dns.max_chunks={max_chunks} — high DNS burst: detection + canary-zone "
             "DoS risk; add an explicit justification comment")

    # ── deploy_class / isolation_class ───────────────────────────────────────
    deploy_class = manifest.get("deploy_class")
    if deploy_class not in DEPLOY_CLASSES:
        err("deploy-class",
            f"deploy_class must be one of {sorted(DEPLOY_CLASSES)} (got {deploy_class!r})")
    requires_ack = deploy_class == "interactive_service"
    if requires_ack:
        warn("interactive-service",
             "interactive service — segmentation required (inv 14); explicit operator "
             "acknowledgement needed before staging")

    isolation_class = manifest.get("isolation_class", "in_process")
    if isolation_class not in ISOLATION_CLASSES:
        err("isolation-class",
            f"isolation_class must be one of {sorted(ISOLATION_CLASSES)} (got {isolation_class!r})")
    has_isolation_block = bool(manifest.get("isolation"))
    if isolation_class == "sandboxed" and not has_isolation_block:
        err("isolation-block", "sandboxed isolation_class requires an `isolation` block")
    if isolation_class in ("in_process", "subprocess") and has_isolation_block:
        err("isolation-block", "isolation block only valid for sandboxed class")

    # ── envelope_version ──────────────────────────────────────────────────────
    ev = manifest.get("envelope_version")
    if ev not in KNOWN_ENVELOPE_VERSIONS:
        err("envelope-version",
            f"unknown envelope version {ev!r} (known: {sorted(KNOWN_ENVELOPE_VERSIONS)})")

    # ── test (optional, additive; default false) ─────────────────────────────
    if "test" in manifest and not isinstance(manifest["test"], bool):
        err("test-flag", f"manifest field 'test' must be a boolean (got {manifest['test']!r})")

    # ── ABC check + golden tests ─────────────────────────────────────────────
    # Only attempt if the basic structural fields are sound — loading a listener
    # for a manifest that is already broken adds noise, not signal.
    if not any(i.rule in ("required-field",) for i in issues):
        _check_listener(manifest, bait_dir, err)

    return IngestResult(
        bait_id=bait_id,
        manifest=manifest,
        issues=issues,
        requires_ack=requires_ack,
    )


def _check_listener(manifest: dict, bait_dir: str, err) -> None:
    """Load ``listener_class``, assert it implements ``Listener``, run its golden
    cases offline. Every failure mode is reported as an error Issue — this never
    raises (a broken bait must not crash ingestion)."""
    ref = str(manifest.get("listener_class", ""))
    if "." not in ref:
        err("listener-load",
            f"listener_class {ref!r} must be '<module>.<ClassName>'")
        return
    module_name, class_name = ref.rsplit(".", 1)
    listener_path = os.path.join(bait_dir, module_name + ".py")
    if not os.path.exists(listener_path):
        err("listener-load", f"listener file {listener_path!r} not found")
        return

    try:
        listener_cls = _import_class(bait_dir, module_name, class_name, manifest["bait_id"])
    except Exception as exc:  # import error, missing class, syntax error …
        err("listener-load", f"could not import {ref!r}: {type(exc).__name__}: {exc}")
        return

    # ABC check. issubclass is the structural gate; also confirm it is
    # instantiable (abstract methods all implemented).
    if not (isinstance(listener_cls, type) and issubclass(listener_cls, Listener)):
        err("abc-check", f"{class_name} does not implement the Listener interface")
        return
    try:
        listener = listener_cls()
    except TypeError as exc:
        err("abc-check",
            f"{class_name} cannot be instantiated (unimplemented abstract method?): {exc}")
        return

    # Golden tests. run_golden_cases also enforces the zero-body gate.
    try:
        results = run_golden_cases(listener)
    except Exception as exc:
        err("golden-test", f"golden_cases() raised {type(exc).__name__}: {exc}")
        return
    for r in results:
        if not r.passed:
            err("golden-test", f"golden test failure — {r.label}: {r.detail}")


def _import_class(bait_dir: str, module_name: str, class_name: str, bait_id: str):
    """Import ``<bait_dir>/<module_name>.py`` under a unique synthetic name and
    return its ``class_name`` attribute. Mirrors the brain pool's loader so a
    bait that ingests cleanly also loads cleanly in the pool."""
    listener_path = os.path.join(bait_dir, module_name + ".py")
    synthetic = f"_cp_bait_{bait_id}_{module_name}"
    spec = importlib.util.spec_from_file_location(synthetic, listener_path)
    if spec is None or spec.loader is None:
        raise ImportError(f"cannot create import spec for {listener_path!r}")
    mod = importlib.util.module_from_spec(spec)
    # Register before exec so dataclasses / relative lookups inside resolve.
    sys.modules[synthetic] = mod
    try:
        spec.loader.exec_module(mod)
    except BaseException:
        sys.modules.pop(synthetic, None)
        raise
    return getattr(mod, class_name)
