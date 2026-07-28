"""Frozen SDK types — the locked dataclasses a BoobyBait author imports.

Ground truth for the types specified in src/blacksea/sdk/context.md. All are
``frozen=True`` (immutable) unless noted; the two analyzer-output types
(`Signals`, `AnalyzerOutput`) are mutable because the author constructs and
populates them incrementally inside ``interpret()``.

Naming note: the design's core unit was renamed from "pair" to **BoobyBait**;
the routing key is ``bait_id`` and the iteration field is ``bait_version``.
In the three-component model, the listener is the unit; bait_id is
still the queue routing key.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass


# ── Observed source (edge-stamped, from envelope) ────────────────────────────
@dataclass(frozen=True)
class ObservedSource:
    """Edge-observed source facts (observed-tier, trusted — inv 17)."""

    ip: str
    ja3: str | None        # None for non-TLS channels (DNS)
    source_type: str       # "client" (HTTPS/TCP) | "resolver" (DNS)


# ── Envelope (brain-verified logical record; passed to interpret()) ─────────
@dataclass(frozen=True)
class Envelope:
    """The brain-verified logical envelope handed to ``interpret()``.

    All sensor-set fields here are already decrypted + authenticated by the brain's
    HMAC-SHA256 AEAD key directory lookup (``sig_valid`` — name retained from the prior
    Ed25519-signing design, see src/blacksea/brain/context.md); the edge-set fields
    (``edge_recv_time``, ``observed_source``, ``edge_id``) are observed-tier. ``body``
    is **not** a field — it is passed to ``interpret()`` separately as raw bytes.
    """

    ev: int                          # envelope version
    bait_id: str
    bait_version: str
    instance_token: bytes            # 8 B
    campaign_id: str
    assurance_tier: int              # 0 | 1 | 2
    session_id: bytes                # 8 B
    seq_no: int                      # uint16; 0 = single-shot tripwire
    sensor_time: int                 # ms — claimed-tier (inv 17)
    channel: str                     # "dns" | "https" | ...
    edge_recv_time: int              # ms — observed-tier, trusted (inv 17)
    observed_source: ObservedSource
    edge_id: str
    sig_valid: bool                  # brain's authoritative re-verify result (inv 13)


# ── Analyzer output (what interpret() returns; merged into Record) ───────────
@dataclass
class Signals:
    """Optional promoted fields the analyzer surfaces to Tier-2.

    Every field is optional; omit any signal that cannot be honestly computed
    (a faked ``caution_level`` poisons burn-detection). Tier-2 reads ``signals``
    but never ``details``.
    """

    fingerprint_hash: str | None = None
    caution_level: str | None = None      # "none" | "low" | "medium" | "high"
    explicit_session_end: bool | None = None


@dataclass
class AnalyzerOutput:
    """The pair-specific part of a Record returned by ``interpret()``.

    The framework assembles the full Record by merging the verified envelope
    fields with this object; the analyzer can never set framework fields
    (``sig_valid``, ``instance_token``, …).
    """

    event_type: str                  # must be non-empty
    signals: Signals | None = None
    details: dict | None = None       # opaque pair-specific intel; size-capped by framework


# ── Artifact (type-agnostic build output) ────────────────────────────────────
@dataclass(frozen=True)
class Artifact:
    """Type-agnostic descriptor of what a build step produced.

    ``artifact_type`` is one of: "file" | "image" | "token-registration" |
    "repo" | "mcp-package". ``descriptor`` carries the type-specific metadata.
    """

    artifact_type: str
    descriptor: dict


# ── Build subprocess result ───────────────────────────────────────────────────
@dataclass(frozen=True)
class RunResult:
    returncode: int
    stdout: bytes
    stderr: bytes


# ── Build context (factory handle) ───────────────────────────────────────────
class BuildContext(ABC):
    """The hermetic build sandbox handle used by the factory.

    In the three-component model the factory (not the bait listener) drives the
    build: it prepends injected constants to ``payload.py``, calls the bundler
    to produce a self-contained Python file, then hands that file to
    ``staging_vessel/setup.sh`` to create the final artifact. This class is the
    factory's API contract; bait listeners do not call it.

    Concrete implementation lives in ``control_plane/factory.py``.
    """

    # Instance attributes the factory sets before the build step.
    instance_token: bytes
    key: bytes                           # master key `_KEY`, 32 B (HMAC-SHA256 AEAD)
    campaign_id: str
    callback_addresses: dict[str, str]   # {"https": "https://…", "dns": "zone.example"}
    bait_id: str
    bait_version: str
    target_arch: list[str]               # from manifest.build.target_arch

    @abstractmethod
    def run(
        self,
        cmd: list[str],
        env: dict[str, str] | None = None,
        timeout: float = 300.0,
    ) -> RunResult:
        """Run ``cmd`` in the hermetic build sandbox. Raises ``BuildError`` on
        non-zero exit."""

    @abstractmethod
    def read_source(self, path: str) -> bytes:
        """Read a file relative to the bait's manifest directory (the directory
        containing its ``manifest.yaml`` — there is no fixed ``baits/`` root; see
        the manifest-only authoring model in docs/bait-authoring.md §2)."""

    @abstractmethod
    def write_output(self, path: str, data: bytes) -> None:
        """Write a file into the build output directory."""

    @abstractmethod
    def bundle_payload(self, payload_path: str, inject: dict[str, str]) -> bytes:
        """Prepend ``inject`` as module-level constants, run the bundler
        on ``payload_path``, and return the self-contained Python
        source as bytes.

        ``inject`` maps constant name → Python literal string, e.g.
        ``{"_ZONE": '"cb.example.com"', "_TOKEN": '"abc123"'}``.
        The factory prepends one ``<name> = <literal>\\n`` line per entry
        before calling the bundler so the payload can reference them as globals.
        """

    @abstractmethod
    def run_staging_vessel(self, vessel_dir: str, bundled: bytes) -> Artifact:
        """Write ``bundled`` to a temp file, invoke ``vessel_dir/setup.sh``
        with it, and return the resulting ``Artifact``.

        The staging vessel is responsible for wrapping the bundled payload into
        its final delivery form (shell script, notebook, fake binary, …). It
        receives the bundled payload path as its first argument and must write
        its output to the directory provided as its second argument.
        """


# ── Golden test fixture ───────────────────────────────────────────────────────
@dataclass
class GoldenCase:
    """One offline interpret() test fixture (run at registration + locally).

    ``expected`` may use the ``ANY`` sentinel (see ``testing.py``) for fields
    whose exact value should not be asserted, and may omit signals/details
    entirely to express "don't care".
    """

    label: str
    body: bytes                      # b"" for the signal-only / zero-body case
    envelope: Envelope               # build with the test_envelope() helper
    expected: AnalyzerOutput
