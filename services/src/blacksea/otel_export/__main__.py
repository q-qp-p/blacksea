"""Entry point: ``python -m blacksea.otel_export``.

The standalone OTLP emitter. Reads its whole configuration from
``blacksea.config.settings`` (the ``BS_OTEL_*`` block, §9) — the operator's entire
"subscription" is: stand up an OTLP endpoint (normally an OpenTelemetry Collector),
set ``BS_OTEL_ENDPOINT`` to it, and turn ``BS_OTEL_ENABLED`` on.

Env (see ``blacksea/config/settings.py`` for the full list + defaults):
  BS_OTEL_ENABLED      master on/off (must be on)
  BS_OTEL_ENDPOINT     OTLP endpoint URL (their Collector / a SIEM OTLP receiver)
  POSTGRES_DSN         the durable records table this tails (read-only)
"""

from __future__ import annotations

import logging

from blacksea.config import settings

from .emitter import OtelEmitter
from .runner import OtelRunner


def main() -> int:
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s %(levelname)s %(name)s: %(message)s",
    )
    log = logging.getLogger("blacksea.otel_export")

    if not settings.BS_OTEL_ENABLED:
        log.error("BS_OTEL_ENABLED is off — set BS_OTEL_ENABLED=1 to run the emitter.")
        return 2
    if not settings.BS_OTEL_ENDPOINT:
        log.error("BS_OTEL_ENDPOINT is not set — point it at your OTLP Collector / SIEM receiver.")
        return 2
    if not settings.POSTGRES_DSN:
        log.error("POSTGRES_DSN is not set — the emitter tails the durable records table.")
        return 2

    emitter = OtelEmitter.from_settings()
    runner = OtelRunner.from_settings(emitter)
    log.info(
        "otel_export → %s (protocol=%s, emit_details=%s); tailing records from cursor %s",
        settings.BS_OTEL_ENDPOINT,
        settings.BS_OTEL_PROTOCOL,
        settings.BS_OTEL_EMIT_DETAILS,
        runner.cursor.as_tuple(),
    )
    runner.run_forever()
    log.info("otel_export stopped.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
