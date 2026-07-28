"""runner.py — the poll → map → emit → advance loop.

The standalone process's control loop (§3). It holds an **in-memory**
``RecordCursor`` (seeded from "now", or ``BS_OTEL_START_TIME``), tails the durable
``records`` table through the shared ``correlation`` keyset reader, maps each
``RecordDetail`` to an OTLP LogRecord, emits it, and advances the cursor past the
last row it saw. It **persists nothing** — on restart it reseeds from "now" and new
events flow; a gap during downtime lives only in the *push* (Postgres + the observer
remain the durable backstop). A persistent checkpoint (true at-least-once catch-up)
is a purely additive upgrade, deliberately deferred.

It is off the ingest hot path by construction: it reads the durable table, not the
NATS stream, so a slow/dead SIEM can only make the emitter fall behind — it can never
back-pressure edge→brain→Postgres.
"""

from __future__ import annotations

import logging
import signal
import time

import psycopg

from blacksea.config import settings
from blacksea.correlation import RecordCursor, RecordFilter, records_after

from . import mapping
from .emitter import OtelEmitter

log = logging.getLogger("blacksea.otel_export")


def _now_ms() -> int:
    return int(time.time() * 1000)


class OtelRunner:
    """Owns the cursor and the poll loop. ``poll_once``/``drain`` are separated from
    ``run_forever`` so tests can drive one iteration against a real connection with no
    threads or signals."""

    def __init__(
        self,
        dsn: str,
        emitter: OtelEmitter,
        *,
        start_cursor: RecordCursor,
        emit_details: bool = True,
        poll_interval: float = 2.0,
        batch_limit: int = 500,
        filt: RecordFilter | None = None,
    ) -> None:
        self._dsn = dsn
        self._emitter = emitter
        self._cursor = start_cursor
        self._emit_details = emit_details
        self._poll_interval = poll_interval
        self._limit = max(1, int(batch_limit))
        # Optional coarse scope for the tail. Production leaves this None → tails the
        # whole records firehose (content/severity filtering is the Collector's job,
        # §7). A caller may scope to e.g. one bait/campaign — the shared reader
        # composes the keyset with where_clause (§4) — which is also what isolates
        # the runner tests on a shared dev DB.
        self._filt = filt
        self._stop = False

    @property
    def cursor(self) -> RecordCursor:
        return self._cursor

    def poll_once(self, conn: "psycopg.Connection") -> int:
        """Read one keyset page after the cursor, emit each record, advance the
        cursor to the last row. Returns how many records were emitted."""
        records = records_after(conn, self._cursor, self._filt, limit=self._limit)
        for detail in records:
            self._emitter.emit(mapping.map_record(detail, emit_details=self._emit_details))
        if records:
            last = records[-1]
            self._cursor = RecordCursor(last.edge_recv_time, last.record_id)
        return len(records)

    def drain(self, conn: "psycopg.Connection") -> int:
        """Poll repeatedly until a page comes back short — i.e. we have caught up to
        the tail — so a burst larger than one page is fully forwarded before we
        sleep. Returns the total emitted this drain."""
        total = 0
        while not self._stop:
            n = self.poll_once(conn)
            total += n
            if n < self._limit:
                break
        return total

    def stop(self) -> None:
        self._stop = True

    def run_forever(self) -> None:
        self._install_signal_handlers()
        conn: "psycopg.Connection | None" = None
        try:
            while not self._stop:
                try:
                    if conn is None or conn.closed:
                        conn = psycopg.connect(self._dsn, autocommit=True)
                    n = self.drain(conn)
                    if n:
                        log.info("emitted %d record(s); cursor now %s", n, self._cursor.as_tuple())
                except Exception as exc:  # keep tailing — records are durable, just fall behind
                    log.warning("poll error (will retry): %s", exc)
                    conn = _safe_close(conn)
                self._sleep(self._poll_interval)
        finally:
            self._shutdown(conn)

    # ── internals ──────────────────────────────────────────────────────────────

    def _sleep(self, seconds: float) -> None:
        """Interruptible sleep — wakes promptly on stop() so SIGTERM is responsive."""
        end = time.monotonic() + seconds
        while not self._stop:
            remaining = end - time.monotonic()
            if remaining <= 0:
                break
            time.sleep(min(0.2, remaining))

    def _install_signal_handlers(self) -> None:
        def handler(_signum, _frame):
            log.info("shutdown signal received; flushing and stopping")
            self.stop()

        for sig in (signal.SIGINT, signal.SIGTERM):
            try:
                signal.signal(sig, handler)
            except (ValueError, OSError):
                # not on the main thread (e.g. under a test harness) — caller drives stop()
                pass

    def _shutdown(self, conn: "psycopg.Connection | None") -> None:
        try:
            self._emitter.force_flush()
        except Exception as exc:
            log.warning("force_flush on shutdown failed: %s", exc)
        finally:
            try:
                self._emitter.shutdown()
            finally:
                _safe_close(conn)

    @classmethod
    def from_settings(cls, emitter: OtelEmitter) -> "OtelRunner":
        seed = settings.BS_OTEL_START_TIME
        start_ms = int(seed) if seed is not None else _now_ms()
        return cls(
            settings.POSTGRES_DSN,
            emitter,
            start_cursor=RecordCursor(start_ms, ""),
            emit_details=settings.BS_OTEL_EMIT_DETAILS,
            poll_interval=settings.BS_OTEL_POLL_INTERVAL,
            batch_limit=settings.BS_OTEL_BATCH_LIMIT,
        )


def _safe_close(conn: "psycopg.Connection | None") -> None:
    if conn is not None:
        try:
            conn.close()
        except Exception:
            pass
    return None
