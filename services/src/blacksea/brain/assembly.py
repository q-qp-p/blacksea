"""brain.assembly — §3.0 framework record assembly.

Full Record = framework_fields(verified_envelope) ∪ analyzer_output(event_type, signals?, details)

Framework-set fields always win (§3.0 assembly rule); the AnalyzerOutput return type
has no sig_valid / instance_token / campaign_id / etc. fields by design, making the
override impossible at the type level. The size cap on details is enforced here (§3.5).
"""

from __future__ import annotations

import json

from blacksea.config import settings
from blacksea.sdk.types import AnalyzerOutput, Envelope

_DETAILS_CAP_DEFAULT = settings.DETAILS_CAP  # §3.5 default (256 KiB), overridable via BS_DETAILS_CAP


def assemble(
    envelope: Envelope,
    analyzer_out: AnalyzerOutput,
    deploy_class: str,
    design_status: str,
    instance_status: str,
    orphan: bool,
    test: bool,
    details_size_cap: int = _DETAILS_CAP_DEFAULT,
) -> dict:
    """Return a full §3.1 Record dict. Framework fields are set from the verified
    envelope and cannot be overridden by the AnalyzerOutput (§3.0)."""

    # §3.2 deterministic compound key
    record_id = (
        f"{envelope.instance_token.hex()}"
        f"-{envelope.session_id.hex()}"
        f"-{envelope.seq_no:04x}"
    )

    # §3.4 signals — include only non-None fields
    signals: dict | None = None
    if analyzer_out.signals is not None:
        s = analyzer_out.signals
        signals = {
            k: v
            for k, v in {
                "fingerprint_hash": s.fingerprint_hash,
                "caution_level": s.caution_level,
                "explicit_session_end": s.explicit_session_end,
            }.items()
            if v is not None
        } or None

    # §3.5 details — enforce size cap; truncate to null + flag if exceeded. A non-JSON-serializable
    # details value (an analyzer bug — details must be a plain JSON object) is treated the same way
    # as oversize rather than silently passed through: passing it through would only defer the
    # failure to storage's Jsonb() encoding, dropping the whole record instead of just the details.
    details = analyzer_out.details
    details_truncated = False
    if details is not None:
        try:
            encoded = json.dumps(details, separators=(",", ":")).encode()
        except (TypeError, ValueError):
            details = None
            details_truncated = True
        else:
            if len(encoded) > details_size_cap:
                details = None
                details_truncated = True

    return {
        # identity / routing
        "record_id": record_id,
        "bait_id": envelope.bait_id,
        "bait_version": envelope.bait_version,
        "instance_token": envelope.instance_token.hex(),
        "campaign_id": envelope.campaign_id,
        "assurance_tier": envelope.assurance_tier,
        "deploy_class": deploy_class,
        # session correlation
        "session_id": envelope.session_id.hex(),
        "seq_no": envelope.seq_no,
        "event_type": analyzer_out.event_type,
        # timestamps
        "edge_recv_time": envelope.edge_recv_time,
        "sensor_time": envelope.sensor_time,
        # observed source (struct; storage.py flattens to columns)
        "observed_source": {
            "ip": envelope.observed_source.ip,
            "ja3": envelope.observed_source.ja3,
            "source_type": envelope.observed_source.source_type,
        },
        # integrity / provenance
        "sig_valid": envelope.sig_valid,
        "channel": envelope.channel,
        "edge_id": envelope.edge_id,
        # status flags
        "orphan": orphan,
        "instance_status": instance_status,
        "design_status": design_status,
        "test": test,
        # analyzer-provided (type-constrained: analyzer cannot set framework fields)
        "signals": signals,
        "details": details,
        "details_truncated": details_truncated,
    }
