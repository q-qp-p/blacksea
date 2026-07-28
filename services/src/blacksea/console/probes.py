"""probes.py — infra-status probes. **No click/rich** (facade purity).

`blacksea status` reports each component as `{status, source, detail}` where ``source`` is
``direct`` (authoritative), ``inferred`` (a liveness guess), or ``unit`` (an OS unit's own
report) — so an *inferred* green is never presented as proof (the false-green trap).

| Component | Signal | Source |
|---|---|---|
| Postgres | ``SELECT 1`` + catalog/event counts + last-event time | direct |
| NATS     | TCP-connect to the broker host:port (listening) | inferred (liveness only) |
| Brain    | the ``brain_health`` heartbeat row vs a staleness threshold | direct |
| Edge     | TCP-reachability of the DNS/HTTPS ports if co-located; unknown otherwise | inferred |
| Otel     | systemd unit status if a unit was installed, else "unmanaged/unknown" | unit / inferred |

Deferred: the JetStream consumer-lag check — it would pull a NATS *client*
dependency into the console; TCP reachability is the MVP. All probes are best-effort and never
raise — a probe failure becomes a ``down``/``unknown`` row, so one dead component never blanks
the whole view.
"""

from __future__ import annotations

import socket
import time
from urllib.parse import urlsplit

import psycopg

from blacksea.control_plane.schema import validate_schema

from .models import ComponentStatus


# ── individual probes ──────────────────────────────────────────────────────────


def probe_postgres(conn: "psycopg.Connection | None", exc: Exception | None) -> ComponentStatus:
    """Postgres liveness — authoritative. ``conn`` is the facade's already-opened read
    connection (or ``None`` with ``exc`` set if opening it failed)."""
    if conn is None:
        return ComponentStatus(
            "postgres", "down", "direct",
            f"cannot connect: {exc}" if exc else "no connection")
    try:
        with conn.cursor() as cur:
            cur.execute("SELECT 1")
            cur.fetchone()
        return ComponentStatus("postgres", "up", "direct", "SELECT 1 ok")
    except Exception as e:  # noqa: BLE001
        return ComponentStatus("postgres", "down", "direct", f"query failed: {e}")


def probe_brain(
    conn: "psycopg.Connection | None", stale_after_s: float
) -> ComponentStatus:
    """Brain liveness via the ``brain_health`` heartbeat — authoritative. A
    ``last_poll_at`` older than ``stale_after_s`` reads as ``stale`` (brain likely stopped
    consuming), never a false green. No row / no table → ``unknown`` (brain never started, or
    an older brain without the heartbeat)."""
    if conn is None:
        return ComponentStatus("brain", "unknown", "direct", "postgres unreachable")
    try:
        with conn.cursor() as cur:
            cur.execute(
                "SELECT EXTRACT(EPOCH FROM (now() - last_poll_at)), consumer_lag "
                "FROM brain_health WHERE id = 1")
            row = cur.fetchone()
    except psycopg.errors.UndefinedTable:
        return ComponentStatus(
            "brain", "unknown", "direct", "no brain_health table (brain not started / pre-heartbeat)")
    except Exception as e:  # noqa: BLE001
        return ComponentStatus("brain", "unknown", "direct", f"heartbeat read failed: {e}")
    if row is None:
        return ComponentStatus("brain", "unknown", "direct", "no heartbeat row yet")
    age_s = float(row[0])
    lag = row[1]
    lag_note = f", lag={lag}" if lag is not None else ""
    if age_s > stale_after_s:
        return ComponentStatus(
            "brain", "stale", "direct",
            f"last heartbeat {age_s:.0f}s ago (> {stale_after_s:.0f}s){lag_note}")
    return ComponentStatus(
        "brain", "up", "direct", f"heartbeat {age_s:.0f}s ago{lag_note}")


def probe_nats(nats_url: str, timeout: float = 1.5) -> ComponentStatus:
    """NATS liveness — inferred (a listening port is not proof the broker is healthy). TCP-connect
    to the host:port parsed from ``NATS_URL``."""
    host, port = _hostport(nats_url, default_port=4222)
    ok, detail = _tcp_probe(host, port, timeout)
    return ComponentStatus(
        "nats", "up" if ok else "down", "inferred", f"{host}:{port} — {detail}")


def probe_edge(
    dns_addr: str | None, https_addr: str | None, co_located: bool, timeout: float = 1.0
) -> ComponentStatus:
    """Edge reachability — inferred, and only meaningful when the edge is co-located with the
    control plane (dev). When it runs on a separate network (the deployed shape) the console
    cannot see it, so the honest answer is ``unknown (separate network)`` — never a false red."""
    if not co_located:
        return ComponentStatus(
            "edge", "unknown", "inferred",
            "not probed (edge runs on a separate network in a real deployment)")
    checks: list[str] = []
    any_up = False
    for label, addr, default in (("dns", dns_addr, 15353), ("https", https_addr, 8443)):
        if not addr:
            continue
        host, port = _hostport(addr, default_port=default, bare_is_hostport=True)
        ok, _ = _tcp_probe(host or "127.0.0.1", port, timeout)
        any_up = any_up or ok
        checks.append(f"{label} {host or '127.0.0.1'}:{port} {'up' if ok else 'down'}")
    if not checks:
        return ComponentStatus("edge", "unknown", "inferred", "no edge ports configured to probe")
    return ComponentStatus(
        "edge", "up" if any_up else "down", "inferred", "; ".join(checks))


# ── system counts (part of the Postgres direct probe) ──────────────────────────


def gather_counts(
    conn: "psycopg.Connection | None", schema: str
) -> tuple[int | None, int | None, int | None, int | None]:
    """Return ``(bait_count, instance_count, event_count, last_event_ms)`` — all ``None`` when
    Postgres is unreachable (so the view shows "couldn't ask", not a misleading zero). Each
    count is independent and best-effort: a missing table (catalog not bootstrapped, or no
    records yet) yields ``0``/``None`` for that count, not an exception."""
    if conn is None:
        return (None, None, None, None)
    try:
        safe_schema = validate_schema(schema)
    except ValueError:
        # An invalid --schema is a misconfiguration, not a Postgres outage — surface it the
        # same way as "couldn't ask" rather than interpolating an unvalidated identifier.
        baits = instances = None
    else:
        baits = _scalar(conn, f'SELECT count(*) FROM "{safe_schema}".design')
        instances = _scalar(conn, f'SELECT count(*) FROM "{safe_schema}".instance')
    events = _scalar(conn, "SELECT count(*) FROM records")
    last_ms = _scalar(conn, "SELECT max(edge_recv_time) FROM records")
    return (baits, instances, events, last_ms)


# ── helpers ────────────────────────────────────────────────────────────────────


def _scalar(conn: "psycopg.Connection", sql: str) -> int | None:
    """Run a scalar aggregate, returning ``None`` on any failure (missing table, etc.) — each
    count is optional and must not blank the others."""
    try:
        with conn.cursor() as cur:
            cur.execute(sql)
            row = cur.fetchone()
        return int(row[0]) if row and row[0] is not None else (0 if "count(" in sql else None)
    except Exception:  # noqa: BLE001 — best-effort; a missing table is not an error here
        return None


def _hostport(
    url: str, *, default_port: int, bare_is_hostport: bool = False
) -> tuple[str, int]:
    """Extract ``(host, port)`` from a ``scheme://host:port`` URL or (with
    ``bare_is_hostport``) a bare ``host:port`` / ``:port`` address like the edge's DNS_ADDR."""
    if "://" not in url and bare_is_hostport:
        host, _, port = url.rpartition(":")
        return host, int(port) if port.isdigit() else default_port
    parts = urlsplit(url if "://" in url else f"//{url}")
    return (parts.hostname or "127.0.0.1", parts.port or default_port)


def _tcp_probe(host: str, port: int, timeout: float) -> tuple[bool, str]:
    start = time.monotonic()
    try:
        with socket.create_connection((host, port), timeout=timeout):
            ms = (time.monotonic() - start) * 1000
            return True, f"listening ({ms:.0f}ms)"
    except OSError as e:
        return False, f"unreachable ({e.__class__.__name__})"
