"""Dev/test helpers: the ``test_envelope()`` fixture builder and the golden-test
runner used both offline by BoobyBait authors and at registration by the
control plane (see control_plane/context.md's ingestion validation rules).

The runner deliberately supports *loose* matching so a golden ``expected`` can
assert only the fields that matter:

* Omit ``signals`` / ``details`` entirely → that part is not checked.
* Leave an individual ``Signals`` field ``None`` → that field is not checked.
* Use the ``ANY`` sentinel as a ``details`` value (or a ``Signals`` field) →
  the key must be present but its value is not asserted.

This matches the reference golden cases in docs/bait-authoring.md (e.g. a
``_decode_error`` whose exact message is not pinned, or a ``fingerprint_hash``
omitted from the fixture).
"""

from __future__ import annotations

from dataclasses import dataclass

from .abc import Listener
from .types import AnalyzerOutput, Envelope, GoldenCase, ObservedSource, Signals

# Stable, recognisable defaults for fixtures.
_DEFAULT_INSTANCE_TOKEN = bytes.fromhex("9f86d081884c7d65")
_DEFAULT_SESSION_ID = bytes.fromhex("a3f2b1c4e5d6f708")
_DEFAULT_SENSOR_TIME = 1_749_292_381_190
_DEFAULT_EDGE_RECV_TIME = 1_749_292_381_412


class _Any:
    """Sentinel meaning 'this key/field must be present, value not asserted'."""

    _instance: "_Any | None" = None

    def __new__(cls) -> "_Any":
        if cls._instance is None:
            cls._instance = super().__new__(cls)
        return cls._instance

    def __repr__(self) -> str:
        return "ANY"


#: Singleton don't-care marker for golden ``expected`` values.
ANY = _Any()


def test_envelope(
    *,
    tier: int = 2,
    bait_id: str = "test-bait",
    bait_version: str = "1.0.0",
    ev: int = 2,
    instance_token: bytes = _DEFAULT_INSTANCE_TOKEN,
    campaign_id: str = "C-TEST",
    session_id: bytes = _DEFAULT_SESSION_ID,
    seq_no: int = 0,
    sensor_time: int = _DEFAULT_SENSOR_TIME,
    channel: str | None = None,
    edge_recv_time: int = _DEFAULT_EDGE_RECV_TIME,
    observed_source: ObservedSource | None = None,
    edge_id: str = "edge-test",
    sig_valid: bool | None = None,
) -> Envelope:
    """Construct an ``Envelope`` for golden-case authoring and local testing.

    Defaults model a tier-2 HTTPS hit; pass ``tier=0`` for the signal-only case
    (channel defaults to ``dns`` and ``sig_valid`` to ``False`` for tier 0).
    Convenience only — not part of the production wire path.
    """
    if channel is None:
        channel = "https" if tier >= 1 else "dns"
    if observed_source is None:
        if channel == "dns":
            observed_source = ObservedSource(ip="198.51.100.2", ja3=None, source_type="resolver")
        else:
            observed_source = ObservedSource(
                ip="203.0.113.7", ja3="771,4865-4866-4867", source_type="client"
            )
    if sig_valid is None:
        sig_valid = tier >= 1  # tier-0 is unsigned by definition
    return Envelope(
        ev=ev,
        bait_id=bait_id,
        bait_version=bait_version,
        instance_token=instance_token,
        campaign_id=campaign_id,
        assurance_tier=tier,
        session_id=session_id,
        seq_no=seq_no,
        sensor_time=sensor_time,
        channel=channel,
        edge_recv_time=edge_recv_time,
        observed_source=observed_source,
        edge_id=edge_id,
        sig_valid=sig_valid,
    )


# ``test_envelope`` is a fixture *builder*, not a pytest test — its ``test_``
# prefix would otherwise be auto-collected wherever it is imported.
test_envelope.__test__ = False


@dataclass
class GoldenResult:
    """Outcome of running one ``GoldenCase`` through a bait's ``interpret()``."""

    label: str
    passed: bool
    detail: str = ""


def _match_value(expected: object, actual: object) -> bool:
    return expected is ANY or expected == actual


def _match_signals(expected: Signals | None, actual: Signals | None) -> str | None:
    """Return ``None`` if signals match, else a mismatch message."""
    if expected is None:
        return None  # "don't care" — signals not asserted
    if actual is None:
        return f"expected signals {expected!r} but analyzer returned signals=None"
    for fname in ("fingerprint_hash", "caution_level", "explicit_session_end"):
        ev = getattr(expected, fname)
        if ev is None:
            continue  # field-level don't-care
        av = getattr(actual, fname)
        if not _match_value(ev, av):
            return f"signals.{fname}: expected {ev!r}, got {av!r}"
    return None


def _match_details(expected: dict | None, actual: dict | None) -> str | None:
    """Subset match: every expected key must be present (value ANY = presence
    only). Extra keys in ``actual`` are allowed. Return ``None`` if ok."""
    if expected is None:
        return None  # "don't care" — details not asserted
    if actual is None:
        return f"expected details with keys {list(expected)} but analyzer returned details=None"
    for key, exp_val in expected.items():
        if key not in actual:
            return f"details missing expected key {key!r}"
        if not _match_value(exp_val, actual[key]):
            return f"details[{key!r}]: expected {exp_val!r}, got {actual[key]!r}"
    return None


def run_golden_case(bait: Listener, case: GoldenCase) -> GoldenResult:
    """Run a single golden case and return its result. Never raises."""
    try:
        out = bait.interpret(case.envelope, case.body)
    except Exception as exc:  # interpret() must be total
        return GoldenResult(
            case.label,
            False,
            f"interpret() raised {type(exc).__name__}: {exc} — interpret() must never raise",
        )
    if not isinstance(out, AnalyzerOutput):
        return GoldenResult(
            case.label,
            False,
            f"interpret() returned {type(out).__name__}, expected AnalyzerOutput",
        )
    if not isinstance(out.event_type, str) or not out.event_type:
        return GoldenResult(case.label, False, "event_type must be a non-empty string")
    if out.event_type != case.expected.event_type:
        return GoldenResult(
            case.label,
            False,
            f"event_type: expected {case.expected.event_type!r}, got {out.event_type!r}",
        )
    msg = _match_signals(case.expected.signals, out.signals)
    if msg:
        return GoldenResult(case.label, False, msg)
    msg = _match_details(case.expected.details, out.details)
    if msg:
        return GoldenResult(case.label, False, msg)
    return GoldenResult(case.label, True)


def run_golden_cases(bait: Listener) -> list[GoldenResult]:
    """Run every golden case a bait declares, plus the registration gates.

    Returns one ``GoldenResult`` per case. An extra ``<registration gate>``
    result enforces the zero-body requirement: ``golden_cases()``
    must include at least one ``body=b""`` case.
    """
    cases = bait.golden_cases()
    results = [run_golden_case(bait, c) for c in cases]
    if not cases:
        results.append(
            GoldenResult("<registration gate>", False, "golden_cases() returned no cases")
        )
    elif not any(c.body == b"" for c in cases):
        results.append(
            GoldenResult(
                "<registration gate>",
                False,
                "golden_cases() must include at least one zero-body (body=b'') case",
            )
        )
    return results


def assert_golden(bait: Listener) -> None:
    """Run all golden cases and raise ``AssertionError`` on any failure.

    Convenience for local/pytest use; the control plane uses
    ``run_golden_cases`` directly so it can report structured results.
    """
    failures = [r for r in run_golden_cases(bait) if not r.passed]
    if failures:
        lines = "\n".join(f"  ✗ {r.label}: {r.detail}" for r in failures)
        raise AssertionError(f"{len(failures)} golden case(s) failed:\n{lines}")
