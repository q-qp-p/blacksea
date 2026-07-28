"""assembly.py — §3.0 framework record assembly.

The central guarantee: framework-set fields come from the verified envelope and
the analyzer cannot override them. The AnalyzerOutput type structurally lacks
those fields, so this is enforced at the type level; these tests pin the
assembled shape, the §3.2 record_id, §3.4 signals filtering, and the §3.5
details size cap.
"""

from __future__ import annotations

from blacksea.brain.assembly import assemble
from blacksea.sdk.types import AnalyzerOutput, Signals
from blacksea.sdk.listener import test_envelope


def test_record_id_is_deterministic_compound_key():
    """§3.2: <itoken_hex>-<sid_hex>-<seq_hex(4)>."""
    env = test_envelope(
        instance_token=bytes.fromhex("1122334455667788"),
        session_id=bytes.fromhex("aabbccddeeff0011"),
        seq_no=7,
    )
    rec = assemble(env, AnalyzerOutput(event_type="x"),
                   deploy_class="portable_artifact", design_status="deployed",
                   instance_status="active", orphan=False, test=False)
    assert rec["record_id"] == "1122334455667788-aabbccddeeff0011-0007"


def test_framework_fields_come_from_envelope():
    """sig_valid, instance_token, campaign_id, tier, channel, edge_id, source
    are all taken from the verified envelope (§3.0)."""
    env = test_envelope(tier=2, bait_id="hostname-probe", campaign_id="C-TEST")
    rec = assemble(env, AnalyzerOutput(event_type="payload_exec_collect"),
                   deploy_class="host_resident", design_status="deployed",
                   instance_status="active", orphan=False, test=False)

    assert rec["sig_valid"] == env.sig_valid is True
    assert rec["instance_token"] == env.instance_token.hex()
    assert rec["campaign_id"] == "C-TEST"
    assert rec["assurance_tier"] == 2
    assert rec["channel"] == env.channel
    assert rec["edge_id"] == env.edge_id
    assert rec["bait_id"] == "hostname-probe"
    assert rec["deploy_class"] == "host_resident"
    assert rec["observed_source"] == {
        "ip": env.observed_source.ip,
        "ja3": env.observed_source.ja3,
        "source_type": env.observed_source.source_type,
    }


def test_analyzer_supplies_only_event_signals_details():
    env = test_envelope()
    rec = assemble(
        env,
        AnalyzerOutput(
            event_type="payload_exec_collect",
            details={"hostname": "victim-box"},
        ),
        deploy_class="portable_artifact", design_status="deployed",
        instance_status="active", orphan=False, test=False,
    )
    assert rec["event_type"] == "payload_exec_collect"
    assert rec["details"] == {"hostname": "victim-box"}


def test_signals_none_when_absent():
    rec = assemble(test_envelope(), AnalyzerOutput(event_type="signal_only"),
                   deploy_class="portable_artifact", design_status="deployed",
                   instance_status="active", orphan=False, test=False)
    assert rec["signals"] is None


def test_signals_drop_none_fields():
    """§3.4: only honestly-computed signals are promoted; None fields are dropped."""
    rec = assemble(
        test_envelope(),
        AnalyzerOutput(
            event_type="payload_exec_collect",
            signals=Signals(caution_level="high"),  # other two left None
        ),
        deploy_class="portable_artifact", design_status="deployed",
        instance_status="active", orphan=False, test=False,
    )
    assert rec["signals"] == {"caution_level": "high"}


def test_all_none_signals_collapse_to_none():
    rec = assemble(
        test_envelope(),
        AnalyzerOutput(event_type="x", signals=Signals()),
        deploy_class="portable_artifact", design_status="deployed",
        instance_status="active", orphan=False, test=False,
    )
    assert rec["signals"] is None


def test_details_size_cap_truncates_and_flags():
    """§3.5: oversized details are dropped (set null) and the truncated flag set."""
    big = {"blob": "x" * 1000}
    rec = assemble(
        test_envelope(),
        AnalyzerOutput(event_type="x", details=big),
        deploy_class="portable_artifact", design_status="deployed",
        instance_status="active", orphan=False, test=False,
        details_size_cap=100,
    )
    assert rec["details"] is None
    assert rec["details_truncated"] is True


def test_test_flag_comes_from_framework_not_analyzer():
    """The `test` flag is framework-set (from the bait's manifest, via the pool's
    per-bait registry) — an analyzer's AnalyzerOutput has no way to set it."""
    rec = assemble(test_envelope(), AnalyzerOutput(event_type="x"),
                   deploy_class="portable_artifact", design_status="deployed",
                   instance_status="active", orphan=False, test=True)
    assert rec["test"] is True


def test_unserializable_details_are_dropped_and_flagged():
    """§3.5: details that aren't JSON-serializable (an analyzer bug) must not silently pass
    through to storage — they're dropped + flagged the same as an oversized payload."""
    rec = assemble(
        test_envelope(),
        AnalyzerOutput(event_type="x", details={"blob": {1, 2, 3}}),
        deploy_class="portable_artifact", design_status="deployed",
        instance_status="active", orphan=False, test=False,
    )
    assert rec["details"] is None
    assert rec["details_truncated"] is True


def test_details_under_cap_preserved():
    rec = assemble(
        test_envelope(),
        AnalyzerOutput(event_type="x", details={"k": "v"}),
        deploy_class="portable_artifact", design_status="deployed",
        instance_status="active", orphan=False, test=False,
        details_size_cap=100,
    )
    assert rec["details"] == {"k": "v"}
    assert rec["details_truncated"] is False
