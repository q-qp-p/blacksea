"""Golden mapping tests — pure, no DB, no live exporter.

Locks the §5 field mapping, the §5 severity map, and the §6 details gate. These are
the module's contract with a SIEM: change an attribute name or a severity and one of
these fails.
"""

from __future__ import annotations

from blacksea.otel_export import map_record, severity_for
from blacksea.otel_export.mapping import (
    MS_TO_NS,
    SEV_ERROR,
    SEV_FATAL,
    SEV_INFO,
    SEV_WARN,
)


# ── severity map (§5) ─────────────────────────────────────────────────────────


def test_severity_map_by_caution():
    assert severity_for(None, True) == (SEV_INFO, "INFO")
    assert severity_for("none", True) == (SEV_INFO, "INFO")
    assert severity_for("low", True) == (SEV_WARN, "WARN")
    assert severity_for("medium", True) == (SEV_ERROR, "ERROR")
    assert severity_for("high", True) == (SEV_FATAL, "FATAL")


def test_severity_floored_at_warn_when_sig_invalid():
    # An unverifiable hit is never reported below WARN...
    assert severity_for(None, False) == (SEV_WARN, "WARN")
    assert severity_for("none", False) == (SEV_WARN, "WARN")
    # ...but a higher caution still wins over the WARN floor.
    assert severity_for("high", False) == (SEV_FATAL, "FATAL")


def test_unknown_caution_treated_as_none():
    assert severity_for("banana", True) == (SEV_INFO, "INFO")


# ── the illustrative hostname-beacon hit (§5) ─────────────────────────────────


def test_hostname_beacon_example(make_detail):
    d = make_detail(
        event_type="payload_exec_collect",
        bait_id="hostname-beacon",
        source_ip="203.0.113.77",
        sig_valid=True,
        signals={"caution_level": "low"},
        details={"hostname": "victim-box"},
        edge_recv_time=1_700_000_000_000,
    )
    m = map_record(d)

    assert m.severity_text == "WARN"
    assert m.body == "payload_exec_collect on hostname-beacon from 203.0.113.77"
    assert m.attributes["client.address"] == "203.0.113.77"
    assert m.attributes["blacksea.sig_valid"] is True
    assert m.attributes["blacksea.caution_level"] == "low"
    assert m.attributes["blacksea.details.hostname"] == "victim-box"
    assert m.attributes["blacksea.record_id"] == d.record_id  # dedup key present
    assert m.timestamp_ns == 1_700_000_000_000 * MS_TO_NS
    assert m.trace_id == 0 and m.span_id == 0  # reserved empty


# ── primary timestamp is edge_recv_time, sensor_time only secondary ───────────


def test_primary_timestamp_is_edge_recv_time_never_sensor(make_detail):
    d = make_detail(edge_recv_time=1_000, sensor_time=9_999)
    m = map_record(d)
    assert m.timestamp_ns == 1_000 * MS_TO_NS               # trusted clock
    assert m.attributes["blacksea.sensor_time"] == 9_999  # labelled secondary only


# ── full field coverage ───────────────────────────────────────────────────────


def test_all_framework_fields_present(make_detail):
    d = make_detail(
        bait_version="3",
        campaign_id="C-9",
        assurance_tier=2,
        deploy_class="interactive_service",
        seq_no=7,
        source_type="resolver",
        channel="dns",
        edge_id="edge-42",
        orphan=True,
        instance_status="revoked",
        design_status="retired",
        test=True,
    )
    a = map_record(d).attributes
    assert a["blacksea.bait_version"] == "3"
    assert a["blacksea.campaign_id"] == "C-9"
    assert a["blacksea.assurance_tier"] == 2
    assert a["blacksea.deploy_class"] == "interactive_service"
    assert a["blacksea.seq_no"] == 7
    assert a["blacksea.source.type"] == "resolver"
    assert a["blacksea.channel"] == "dns"
    assert a["blacksea.edge_id"] == "edge-42"
    assert a["blacksea.orphan"] is True
    assert a["blacksea.instance_status"] == "revoked"
    assert a["blacksea.design_status"] == "retired"
    assert a["blacksea.test"] is True


def test_ja3_omitted_when_null_present_when_set(make_detail):
    assert "blacksea.source.ja3" not in map_record(make_detail(source_ja3=None)).attributes
    m = map_record(make_detail(source_ja3="deadbeef"))
    assert m.attributes["blacksea.source.ja3"] == "deadbeef"


# ── signals flattening ────────────────────────────────────────────────────────


def test_signals_flatten_caution_promoted_rest_namespaced(make_detail):
    d = make_detail(signals={"caution_level": "medium", "fingerprint_hash": "abc", "burned": True})
    a = map_record(d).attributes
    assert a["blacksea.caution_level"] == "medium"          # promoted top-level
    assert a["blacksea.signals.fingerprint_hash"] == "abc"  # rest namespaced
    assert a["blacksea.signals.burned"] is True


def test_no_signals_means_no_caution_attr(make_detail):
    a = map_record(make_detail(signals=None)).attributes
    assert "blacksea.caution_level" not in a


# ── details gate (§6) ─────────────────────────────────────────────────────────


def test_details_emitted_by_default(make_detail):
    a = map_record(make_detail(details={"user": "root", "pid": 1234})).attributes
    assert a["blacksea.details.user"] == "root"
    assert a["blacksea.details.pid"] == 1234


def test_details_suppressed_when_gate_off(make_detail):
    a = map_record(make_detail(details={"user": "root"}), emit_details=False).attributes
    assert not any(k.startswith("blacksea.details.") for k in a)
    # sig_valid always paired regardless of the gate
    assert "blacksea.sig_valid" in a


def test_details_truncated_flag(make_detail):
    a = map_record(make_detail(details={"x": 1}, details_truncated=True)).attributes
    assert a["blacksea.details.truncated"] is True


def test_attacker_content_stays_inside_a_typed_field(make_detail):
    # A malicious newline in an attacker-controlled details value must stay INSIDE the
    # attribute value — it cannot forge a separate log line (that is the whole §6
    # safety argument for structured attributes over concatenated messages).
    nasty = "victim\nSEV=CRITICAL fake=line"
    d = make_detail(details={"hostname": nasty})
    m = map_record(d)
    assert m.attributes["blacksea.details.hostname"] == nasty  # verbatim, one field
    assert "\n" not in m.body                                    # body is unaffected


def test_nested_details_value_serialised_to_json_string(make_detail):
    # A dict/nested value isn't a valid OTLP attribute; it becomes one JSON string,
    # never dropped and never split into forgeable fields.
    d = make_detail(details={"env": {"USER": "root", "SHELL": "/bin/sh"}})
    v = map_record(d).attributes["blacksea.details.env"]
    assert isinstance(v, str)
    assert '"USER": "root"' in v


def test_homogeneous_primitive_list_kept_as_list(make_detail):
    d = make_detail(details={"ports": [22, 80, 443]})
    assert map_record(d).attributes["blacksea.details.ports"] == [22, 80, 443]
