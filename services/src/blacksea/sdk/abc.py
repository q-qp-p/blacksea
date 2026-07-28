"""The ``Listener`` ABC and its ``Interpretable`` protocol view.

A bait is authored as three separate files:

1. ``payload.py`` — standalone Python script; imports comms primitives from
   ``blacksea.sdk.payload.*`` directly. Fed through the bundler at
   factory time, which inlines the comms source and prepends injected constants
   (instance token, callback address, …) to produce a self-contained artifact.

2. ``listener.py`` — a ``Listener`` subclass. Owns the server-side half: body
   encoding/decoding, telemetry interpretation, and golden-case fixtures. A
   single Listener class can be registered under multiple bait_ids when the
   same interpret logic applies to different staging vessels.

3. ``staging_vessel/setup.sh`` — takes the bundled payload file and produces
   the final bait artifact (a shell script, notebook embed, fake binary, …).

The framework hands the analyzer pool an ``Interpretable`` view so bait-side
code never sees framework internals (inv 11).

``BoobyBait`` is kept as a deprecated alias for code written against the old
single-class model. New authors subclass ``Listener`` directly.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from typing import Protocol, runtime_checkable

from .types import AnalyzerOutput, Envelope, GoldenCase


class Listener(ABC):
    """Server-side half of a bait: decode incoming telemetry and interpret it.

    One class implements the full interpret contract; the factory handles the
    build side (bundler + staging vessel) based on the manifest declaration.
    A single Listener class may be registered for multiple bait_ids (different
    staging vessels, same decode+interpret logic).

    Pure function contract: ``interpret()`` (and ``decode_body()``) must have
    no I/O, no eval, no external modules, bounded time + memory (inv 11).
    """

    # ════════════════════════════════════════════════════════════════════
    # BODY CODEC — kept on the Listener so encode/decode never drift apart.
    # encode_body is the reference serialiser; the payload's own code must
    # produce byte-for-byte equivalent output for the same logical data.
    # ════════════════════════════════════════════════════════════════════

    @abstractmethod
    def encode_body(self, data: dict) -> bytes:
        """Canonical serialisation of a body dict → bytes.

        Used for golden-case generation and round-trip testing. Must be
        deterministic. The deployed payload must produce equivalent bytes for
        the same logical payload — keeping them in sync is the author's
        responsibility (structural enforcement is impossible across two files).
        """

    @abstractmethod
    def decode_body(self, body: bytes) -> dict:
        """Deserialise body bytes → dict. Inverse of ``encode_body``.

        MUST NOT raise on truncated / partially-corrupt input — return a
        best-effort dict for partial data. Raise ``BodyDecodeError`` ONLY on
        completely unrecoverable input (wrong magic, incompatible version).
        Never raise any other exception type.
        """

    # ════════════════════════════════════════════════════════════════════
    # INTERPRET — pure function, called once per inbound hit.
    # ════════════════════════════════════════════════════════════════════

    @abstractmethod
    def interpret(self, envelope: Envelope, body: bytes) -> AnalyzerOutput:
        """Classify one hit into an ``AnalyzerOutput``. Pure function.

        MUST handle ``body == b""`` (signal-only / tier-0). MUST NOT raise —
        catch all exceptions and express them in ``details`` via ``_``-prefixed
        meta-keys. MUST complete within the framework's time + memory
        limits. Internally calls ``decode_body`` and catches ``BodyDecodeError``.
        """

    # ════════════════════════════════════════════════════════════════════
    # LIFECYCLE HOOKS — optional, default no-op.
    # Same ambient-authority restrictions as interpret().
    # ════════════════════════════════════════════════════════════════════

    def on_register(self) -> None:
        """Called once when the design is staged (pool module loaded)."""

    def on_deploy(self, instance_token: bytes) -> None:
        """Called when a new instance of this design goes active."""

    def on_burn(self, reason: str) -> None:
        """Called when this design or one of its instances is marked burned."""

    def on_retire(self) -> None:
        """Called when this design is retired. Last call before pool unloads."""

    # ════════════════════════════════════════════════════════════════════
    # GOLDEN TESTS — required; registration gate.
    # ════════════════════════════════════════════════════════════════════

    @abstractmethod
    def golden_cases(self) -> list[GoldenCase]:
        """Offline ``interpret()`` test fixtures. Must include at minimum:

        1. A normal hit with a representative body.
        2. A zero-body (signal-only, ``body=b""``) hit.

        Additional cases for malformed input / edge conditions are encouraged.
        The framework runs these at registration; any failure blocks staging.
        """


# Backward-compat alias — the old single-class authoring model.
# New bait authors subclass ``Listener`` directly.
BoobyBait = Listener


@runtime_checkable
class Interpretable(Protocol):
    """Interpret-side view handed to the analyzer pool. Documents the
    no-ambient-authority contract (inv 11); the pool sandbox enforces it at
    runtime, but the type boundary starts here."""

    def encode_body(self, data: dict) -> bytes: ...
    def decode_body(self, body: bytes) -> dict: ...
    def interpret(self, envelope: Envelope, body: bytes) -> AnalyzerOutput: ...
    def on_register(self) -> None: ...
    def on_deploy(self, instance_token: bytes) -> None: ...
    def on_burn(self, reason: str) -> None: ...
    def on_retire(self) -> None: ...
    def golden_cases(self) -> list[GoldenCase]: ...
