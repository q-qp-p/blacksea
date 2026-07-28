"""mapping.py — the pure Record → OTLP LogRecord mapper.

This is the one file with the field contract (§5 of this module's ``context.md``).
It is **I/O-free and SDK-free**: it takes a
:class:`~blacksea.correlation.RecordDetail` — the exact display value object the
observer renders (observer parity) — and returns a :class:`MappedLog`, a plain
frozen description of one OTLP LogRecord. ``emitter.py`` turns a ``MappedLog`` into
an actual SDK emit call, filling ``observedTimeUnixNano`` with its own wall clock
(the only field this mapper cannot set without reading a clock).

Keeping this SDK-free is deliberate: the whole field mapping is golden-testable with
no OTel install, no DB, and no network — a change to an attribute name or the
severity map is caught by ``tests/otel_export/test_mapping.py`` alone.

Invariants enforced here:

- **Primary timestamp is ``edge_recv_time``** (trusted, observed-tier), never
  ``sensor_time``. The sensor-claimed clock rides only as the clearly-labelled
  secondary attribute ``blacksea.sensor_time``.
- **``sig_valid`` is always emitted**, paired with ``details`` — the operator can
  always tell trustworthy from forgeable content.
- **Attacker-influenced content stays inside typed attribute values.** ``details``
  and free-form ``signals`` are emitted as OTLP attributes (typed key/value), so a
  malicious newline/ANSI in an attacker string stays *inside* a field — it cannot
  forge a log line the way a concatenated syslog message could.
- **``traceId``/``spanId`` reserved empty** (0) for a future session→trace layer.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from typing import Any

from blacksea.correlation import RecordDetail

# OTel SeverityNumber values (https://opentelemetry.io/docs/specs/otel/logs/data-model/).
# Held as plain ints so this module never imports the SDK; emitter.py maps int →
# SeverityNumber at emit time.
SEV_INFO = 9
SEV_WARN = 13
SEV_ERROR = 17
SEV_FATAL = 21

_SEV_TEXT = {SEV_INFO: "INFO", SEV_WARN: "WARN", SEV_ERROR: "ERROR", SEV_FATAL: "FATAL"}

# caution_level → base severity (§5 severity map). None/"none"/"" → INFO.
_CAUTION_SEV = {
    None: SEV_INFO,
    "none": SEV_INFO,
    "": SEV_INFO,
    "low": SEV_WARN,
    "medium": SEV_ERROR,
    "high": SEV_FATAL,
}

MS_TO_NS = 1_000_000

_PRIMITIVE = (str, bool, int, float)


@dataclass(frozen=True)
class MappedLog:
    """SDK-free description of one OTLP LogRecord.

    ``observedTimeUnixNano`` is intentionally absent — the emitter stamps it with
    its own wall clock at emit time (that is the "when otel_export processed it"
    field, and the only one that requires reading a clock).
    """

    timestamp_ns: int
    severity_number: int
    severity_text: str
    body: str
    attributes: dict[str, Any]
    trace_id: int = 0     # reserved empty — future session→trace layer (additive)
    span_id: int = 0      # reserved empty


def severity_for(caution_level: str | None, sig_valid: bool) -> tuple[int, str]:
    """(caution_level, sig_valid) → (SeverityNumber int, text).

    Floored at WARN when ``sig_valid`` is false: an unverifiable hit is never
    reported below WARN, even a caution-``none`` one.
    """
    key = caution_level if caution_level in _CAUTION_SEV else "none"
    sev = _CAUTION_SEV[key]
    if not sig_valid:
        sev = max(sev, SEV_WARN)
    return sev, _SEV_TEXT[sev]


def resource_attributes(deployment_id: str) -> dict[str, Any]:
    """OTLP Resource attributes — the emitter identity, attached to every record."""
    return {
        "service.name": "blacksea-brain",
        "service.namespace": "blacksea",
        "blacksea.deployment_id": deployment_id,
    }


def _coerce(v: Any) -> Any:
    """Coerce an arbitrary jsonb value into an OTLP-safe attribute value.

    OTLP attribute values are a primitive (str/bool/int/float) or a *homogeneous*
    array of primitives. Anything else — a dict, a nested/heterogeneous list — is
    serialised to a compact JSON string so it lands as one typed field rather than
    being dropped or splitting into forged fields. ``None`` → ``None`` (caller
    omits the attribute).
    """
    if v is None:
        return None
    if isinstance(v, bool) or isinstance(v, _PRIMITIVE):
        return v
    if isinstance(v, (list, tuple)):
        items = list(v)
        if items and all(
            not isinstance(x, bool) and isinstance(x, _PRIMITIVE) and type(x) is type(items[0])
            for x in items
        ):
            return items
        return json.dumps(v, default=str, sort_keys=True)
    return json.dumps(v, default=str, sort_keys=True)


def map_record(detail: RecordDetail, *, emit_details: bool = True) -> MappedLog:
    """Map one assembled Record (as a display ``RecordDetail``) → one OTLP LogRecord.

    ``emit_details=False`` yields a metadata-only feed (no ``blacksea.details.*``).
    """
    signals = detail.signals or {}
    caution = signals.get("caution_level")
    sev, sev_text = severity_for(caution, detail.sig_valid)

    attrs: dict[str, Any] = {
        "blacksea.record_id": detail.record_id,        # dedup key (deterministic, replay-stable)
        "blacksea.bait_id": detail.bait_id,
        "blacksea.bait_version": detail.bait_version,
        "blacksea.instance_token": detail.instance_token,
        "blacksea.campaign_id": detail.campaign_id,
        "blacksea.assurance_tier": detail.assurance_tier,
        "blacksea.deploy_class": detail.deploy_class,
        "blacksea.session_id": detail.session_id,
        "blacksea.seq_no": detail.seq_no,
        "blacksea.event_type": detail.event_type,
        "client.address": detail.source_ip,              # OTel standard attribute name
        "blacksea.source.type": detail.source_type,    # client | resolver
        "blacksea.channel": detail.channel,
        "blacksea.edge_id": detail.edge_id,
        "blacksea.sig_valid": detail.sig_valid,        # prominent — trustworthy vs forgeable
        "blacksea.orphan": detail.orphan,              # late hit from a burned/retired instance
        "blacksea.instance_status": detail.instance_status,  # 'revoked' = someone wielding a burned sensor
        "blacksea.design_status": detail.design_status,
        "blacksea.test": detail.test,                  # flags hits from test/example baits
        # Sensor-claimed time — secondary only; the primary timeUnixNano is edge_recv_time.
        "blacksea.sensor_time": detail.sensor_time,
    }
    if detail.source_ja3 is not None:
        attrs["blacksea.source.ja3"] = detail.source_ja3

    # signals: caution_level promoted to a top-level attr; the rest namespaced under
    # blacksea.signals.* so they can never collide with a framework attribute name.
    if caution is not None:
        attrs["blacksea.caution_level"] = caution
    for k, v in signals.items():
        if k == "caution_level":
            continue
        cv = _coerce(v)
        if cv is not None:
            attrs[f"blacksea.signals.{k}"] = cv

    # details — gated (§6, default on). Attacker-influenced; kept inside typed fields.
    if emit_details and detail.details:
        if detail.details_truncated:
            attrs["blacksea.details.truncated"] = True
        for k, v in detail.details.items():
            cv = _coerce(v)
            if cv is not None:
                attrs[f"blacksea.details.{k}"] = cv

    body = f"{detail.event_type} on {detail.bait_id} from {detail.source_ip}"
    return MappedLog(
        timestamp_ns=int(detail.edge_recv_time) * MS_TO_NS,
        severity_number=sev,
        severity_text=sev_text,
        body=body,
        attributes=attrs,
    )
