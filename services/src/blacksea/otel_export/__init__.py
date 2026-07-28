"""blacksea.otel_export — push assembled Records out as an OTLP log stream.

The third consumer of assembled Records (alongside ``observer`` and ``console``): a
standalone, read-only process that tails the durable ``records`` table through the
shared ``correlation`` read layer, maps each ``RecordDetail`` to one OpenTelemetry
LogRecord, and pushes it over OTLP to an endpoint the operator controls (normally an
OpenTelemetry Collector fronting their SOC/SIEM or observability stack). It holds no
keys, writes nothing, and runs off the ingest hot path.

Public surface:

- ``map_record`` / ``MappedLog`` / ``severity_for`` / ``resource_attributes`` — the
  pure, SDK-free mapper (``mapping.py``). Importable and golden-testable without the
  OpenTelemetry SDK installed.
- ``OtelEmitter`` / ``OtelRunner`` — the SDK-backed emitter and the poll loop. These
  are imported lazily (they pull in the OpenTelemetry SDK) so the pure mapper stays
  usable on its own.
"""

from __future__ import annotations

from .mapping import MappedLog, map_record, resource_attributes, severity_for

__all__ = [
    "MappedLog",
    "map_record",
    "resource_attributes",
    "severity_for",
    "OtelEmitter",
    "OtelRunner",
]


def __getattr__(name: str):
    # Lazy: keep the OpenTelemetry SDK off the import path for pure-mapper consumers.
    if name == "OtelEmitter":
        from .emitter import OtelEmitter

        return OtelEmitter
    if name == "OtelRunner":
        from .runner import OtelRunner

        return OtelRunner
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")
