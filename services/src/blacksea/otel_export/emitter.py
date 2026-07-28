"""emitter.py — the OTLP provider/exporter setup + the emit call.

This is the only file that touches the OpenTelemetry SDK. It builds a
``LoggerProvider`` (carrying the Resource identity), wires a
``BatchLogRecordProcessor`` around an OTLP exporter (HTTP by default, gRPC
selectable), and turns a :class:`~blacksea.otel_export.mapping.MappedLog` into a
single ``logger.emit(...)`` call — stamping ``observedTimeUnixNano`` with its own
wall clock at that moment.

The batch processor gives us bounded-queue buffering + background export + retry for
free, so a transient SIEM blip is absorbed and a long outage degrades to best-effort
(the queue overflows and drops from the *push* — the events stay in Postgres). None
of that ever reaches back to the ingest hot path: this process only reads the durable
``records`` table.

Testability: the constructor accepts an injected ``processor`` (or ``exporter``), so a
test can wire a ``SimpleLogRecordProcessor`` around an in-memory sink and assert on
exactly what would go on the wire, with no live Collector.
"""

from __future__ import annotations

import time
from typing import Any

from opentelemetry._logs import SeverityNumber
from opentelemetry.sdk._logs import LoggerProvider, LogRecordProcessor
from opentelemetry.sdk._logs.export import BatchLogRecordProcessor
from opentelemetry.sdk.resources import Resource

from blacksea.config import settings

from . import mapping
from .mapping import MappedLog

_INSTRUMENTATION = "blacksea.otel_export"


def parse_headers(raw: str | None) -> dict[str, str]:
    """Parse ``BS_OTEL_HEADERS`` — comma-separated ``key=value`` pairs, e.g.
    ``Authorization=Bearer abc,X-Scope-OrgID=42``. Only the first ``=`` splits, so a
    value may itself contain ``=``. Malformed fragments (no ``=``) are skipped."""
    out: dict[str, str] = {}
    if not raw:
        return out
    for part in raw.split(","):
        part = part.strip()
        if "=" not in part:
            continue
        k, v = part.split("=", 1)
        k = k.strip()
        if k:
            out[k] = v.strip()
    return out


def _http_logs_endpoint(endpoint: str) -> str:
    """The HTTP exporter wants the signal-specific path. Accept either a base
    collector URL (``http://host:4318``) or a full logs URL and normalise to the
    ``/v1/logs`` path so operators can set either."""
    e = endpoint.rstrip("/")
    return e if e.endswith("/v1/logs") else e + "/v1/logs"


def build_exporter():
    """Build the OTLP log exporter from ``settings`` (§9). HTTP/protobuf by default;
    gRPC when ``BS_OTEL_PROTOCOL=grpc`` (imported lazily — the grpc exporter is an
    optional extra)."""
    protocol = (settings.BS_OTEL_PROTOCOL or "http/protobuf").strip().lower()
    endpoint = settings.BS_OTEL_ENDPOINT
    headers = parse_headers(settings.BS_OTEL_HEADERS) or None

    if protocol in ("grpc", "grpc/protobuf"):
        from opentelemetry.exporter.otlp.proto.grpc._log_exporter import OTLPLogExporter

        kwargs: dict[str, Any] = {"headers": headers}
        if endpoint:
            kwargs["endpoint"] = endpoint
        if settings.BS_OTEL_TLS_CA or settings.BS_OTEL_TLS_CERT or settings.BS_OTEL_TLS_KEY:
            import grpc

            kwargs["credentials"] = grpc.ssl_channel_credentials(
                root_certificates=_read(settings.BS_OTEL_TLS_CA),
                private_key=_read(settings.BS_OTEL_TLS_KEY),
                certificate_chain=_read(settings.BS_OTEL_TLS_CERT),
            )
        return OTLPLogExporter(**kwargs)

    # default: HTTP/protobuf
    from opentelemetry.exporter.otlp.proto.http._log_exporter import OTLPLogExporter

    kwargs = {"headers": headers}
    if endpoint:
        kwargs["endpoint"] = _http_logs_endpoint(endpoint)
    if settings.BS_OTEL_TLS_CA:
        kwargs["certificate_file"] = settings.BS_OTEL_TLS_CA
    if settings.BS_OTEL_TLS_CERT:
        kwargs["client_certificate_file"] = settings.BS_OTEL_TLS_CERT
    if settings.BS_OTEL_TLS_KEY:
        kwargs["client_key_file"] = settings.BS_OTEL_TLS_KEY
    return OTLPLogExporter(**kwargs)


def _read(path: str | None) -> bytes | None:
    if not path:
        return None
    with open(path, "rb") as fh:
        return fh.read()


class OtelEmitter:
    """Wraps a ``LoggerProvider`` + processor and emits ``MappedLog`` records.

    Provide exactly one of ``processor`` (used verbatim — the injection seam for
    tests / custom pipelines) or ``exporter`` (wrapped in a
    ``BatchLogRecordProcessor``).
    """

    def __init__(
        self,
        *,
        resource_attrs: dict[str, Any],
        processor: LogRecordProcessor | None = None,
        exporter: Any | None = None,
    ) -> None:
        if processor is None and exporter is None:
            raise ValueError("OtelEmitter needs a processor or an exporter")
        self._provider = LoggerProvider(resource=Resource.create(resource_attrs))
        self._provider.add_log_record_processor(
            processor if processor is not None else BatchLogRecordProcessor(exporter)
        )
        self._logger = self._provider.get_logger(_INSTRUMENTATION)

    def emit(self, m: MappedLog) -> None:
        """Emit one mapped record. ``observed_timestamp`` is this process's wall
        clock now (when otel_export handed it off); ``timestamp`` is the trusted
        ``edge_recv_time`` carried on the ``MappedLog``. trace/span ids are left
        empty (reserved)."""
        self._logger.emit(
            timestamp=m.timestamp_ns,
            observed_timestamp=time.time_ns(),
            severity_number=SeverityNumber(m.severity_number),
            severity_text=m.severity_text,
            body=m.body,
            attributes=m.attributes,
        )

    def force_flush(self, timeout_millis: int = 30_000) -> bool:
        return self._provider.force_flush(timeout_millis)

    def shutdown(self) -> None:
        self._provider.shutdown()

    @classmethod
    def from_settings(cls) -> "OtelEmitter":
        """Build the production emitter: OTLP exporter from ``settings`` (§9),
        Resource from ``BS_OTEL_DEPLOYMENT_ID``."""
        return cls(
            resource_attrs=mapping.resource_attributes(settings.BS_OTEL_DEPLOYMENT_ID),
            exporter=build_exporter(),
        )
