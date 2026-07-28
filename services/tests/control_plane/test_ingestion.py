"""Ingestion validation rules (see context.md's "Ingestion validation rules" section)."""

from __future__ import annotations

from blacksea.control_plane.ingestion import ingest


def _rules(result) -> set[str]:
    return {i.rule for i in result.issues}


def _error_rules(result) -> set[str]:
    return {i.rule for i in result.errors}


def test_reference_bait_ingests_clean(bait_factory):
    result = ingest(bait_factory(), existing_bait_ids=set())
    assert result.ok, [str(i) for i in result.errors]
    assert result.bait_id == "hostname-probe"


def test_bait_id_uniqueness_blocks(bait_factory):
    result = ingest(bait_factory(), existing_bait_ids={"hostname-probe"})
    assert not result.ok
    assert "bait-id-unique" in _error_rules(result)


def test_provenance_gate_blocks_on_empty_subfield(bait_factory):
    bad = ingest(
        bait_factory(provenance={"behavior": "x", "source": "", "observed_date": "2026-01-01"}),
        existing_bait_ids=set(),
    )
    assert not bad.ok
    assert "provenance" in _error_rules(bad)


def test_unknown_channel_blocks(bait_factory):
    result = ingest(bait_factory(channels={"carrier_pigeon": {}}), existing_bait_ids=set())
    assert not result.ok
    assert "channel-receiver" in _error_rules(result)


def test_unknown_envelope_version_blocks(bait_factory):
    result = ingest(bait_factory(envelope_version=99), existing_bait_ids=set())
    assert not result.ok
    assert "envelope-version" in _error_rules(result)


def test_non_bool_test_flag_blocks(bait_factory):
    result = ingest(bait_factory(test="yes"), existing_bait_ids=set())
    assert not result.ok
    assert "test-flag" in _error_rules(result)


def test_test_flag_defaults_false_when_absent(bait_factory):
    result = ingest(bait_factory(test=None), existing_bait_ids=set())
    assert result.ok, [str(i) for i in result.errors]
    assert result.manifest.get("test", False) is False


def test_sandboxed_without_isolation_block_blocks(bait_factory):
    result = ingest(bait_factory(isolation_class="sandboxed"), existing_bait_ids=set())
    assert not result.ok
    assert "isolation-block" in _error_rules(result)


def test_isolation_block_on_in_process_blocks(bait_factory):
    result = ingest(
        bait_factory(isolation_class="in_process", isolation={"sandbox_type": "wasm"}),
        existing_bait_ids=set(),
    )
    assert not result.ok
    assert "isolation-block" in _error_rules(result)


def test_tier1_with_only_dns_warns_not_blocks(bait_factory):
    # tier ≥ 1 over a dns-only channel set: warn (signature needs a fat channel),
    # but it does not block staging.
    result = ingest(bait_factory(assurance_tier=1), existing_bait_ids=set())
    assert "tier-channel" in {w.rule for w in result.warnings}
    # No tier-channel *error*; the only blocker would be elsewhere.
    assert "tier-channel" not in _error_rules(result)


def test_interactive_service_requires_ack(bait_factory):
    result = ingest(bait_factory(deploy_class="interactive_service"), existing_bait_ids=set())
    assert result.requires_ack
    assert "interactive-service" in {w.rule for w in result.warnings}


def test_missing_required_field_blocks(bait_factory):
    result = ingest(bait_factory(description=None), existing_bait_ids=set())
    assert not result.ok
    assert "required-field" in _error_rules(result)


def test_golden_failure_blocks(bait_factory, tmp_path):
    # Point listener_class at a broken listener whose golden case fails.
    bait_dir = bait_factory()
    broken = (
        "from blacksea.sdk.listener import Listener, AnalyzerOutput, GoldenCase, "
        "Envelope, test_envelope\n"
        "class Broken(Listener):\n"
        "    def encode_body(self, data): return b''\n"
        "    def decode_body(self, body): return {}\n"
        "    def interpret(self, envelope, body):\n"
        "        return AnalyzerOutput(event_type='WRONG')\n"
        "    def golden_cases(self):\n"
        "        return [GoldenCase('zero', b'', test_envelope(tier=0),\n"
        "                           AnalyzerOutput(event_type='signal_only'))]\n"
    )
    (tmp_path_listener := __import__("pathlib").Path(bait_dir) / "broken.py").write_text(broken)
    result = ingest(_with_listener(bait_dir, "broken.Broken"), existing_bait_ids=set())
    assert not result.ok
    assert "golden-test" in _error_rules(result)


def test_missing_zero_body_golden_case_blocks(bait_factory, tmp_path):
    bait_dir = bait_factory()
    no_zero = (
        "from blacksea.sdk.listener import Listener, AnalyzerOutput, GoldenCase, test_envelope\n"
        "class NoZero(Listener):\n"
        "    def encode_body(self, data): return b'x'\n"
        "    def decode_body(self, body): return {}\n"
        "    def interpret(self, envelope, body):\n"
        "        return AnalyzerOutput(event_type='payload_exec_collect')\n"
        "    def golden_cases(self):\n"
        "        return [GoldenCase('nonzero', b'x', test_envelope(tier=2),\n"
        "                           AnalyzerOutput(event_type='payload_exec_collect'))]\n"
    )
    (__import__("pathlib").Path(bait_dir) / "nozero.py").write_text(no_zero)
    result = ingest(_with_listener(bait_dir, "nozero.NoZero"), existing_bait_ids=set())
    assert not result.ok
    assert "golden-test" in _error_rules(result)


def _with_listener(bait_dir: str, listener_class: str) -> str:
    import pathlib
    import yaml as _yaml
    p = pathlib.Path(bait_dir) / "manifest.yaml"
    m = _yaml.safe_load(p.read_text())
    m["listener_class"] = listener_class
    p.write_text(_yaml.safe_dump(m, sort_keys=False))
    return bait_dir
