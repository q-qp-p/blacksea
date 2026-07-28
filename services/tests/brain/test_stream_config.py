"""Locks the disk-cap fix on the brain side: the BAITS JetStream stream MUST be
provisioned with a size cap, an age cap, and discard=old. Without them a LimitsPolicy stream never
evicts acked messages, so it grows into an append-only log an unauthenticated party can drive to
disk exhaustion through the edge's beacon endpoints.

Kept in lockstep with the edge's baitsStreamConfig (edge/queue_stream_test.go) via the shared
NATS_MAX_BYTES / NATS_MAX_AGE_S defaults — the two provisioners must agree.
"""
import re
from pathlib import Path

import pytest
from nats.js.api import DiscardPolicy, RetentionPolicy, StorageType

from blacksea.brain.pool import _baits_stream_config
from blacksea.config import settings


def test_baits_stream_has_disk_limits():
    cfg = _baits_stream_config()

    assert cfg.max_bytes and cfg.max_bytes > 0, "max_bytes must be a positive disk cap"
    assert cfg.max_age and cfg.max_age > 0, "max_age must be a positive age cap"
    assert cfg.discard == DiscardPolicy.OLD, "discard must be OLD so the cap self-trims"
    assert cfg.retention == RetentionPolicy.LIMITS, "retention stays LIMITS (sole-consumer topology)"
    assert cfg.storage == StorageType.FILE
    assert cfg.subjects == ["bait.>"]


def _go_int_const(source: str, name: str) -> int:
    """Extract an integer Go const from config.go source. Matches the declaration line only
    (``^\\s*name [int64] = <expr>``), not the later usages, and evaluates the integer arithmetic
    (``1 << 30`` / ``7 * 24 * 3600`` are valid Python too) under a locked-down eval."""
    m = re.search(rf"^\s*{name}(?:\s+int64)?\s*=\s*([^/\n]+)", source, re.MULTILINE)
    assert m, f"could not find Go const {name} in config.go"
    expr = m.group(1).strip()
    assert re.fullmatch(r"[0-9\s<*+\-()]+", expr), f"unexpected Go const expr for {name}: {expr!r}"
    return int(eval(expr, {"__builtins__": {}}, {}))  # only integer arithmetic, no names/builtins


def test_defaults_match_edge_source():
    """Genuine cross-language lock (a same-language literal assertion gives false confidence — it
    passes even when only ONE side's default changes). Read the edge's Go defaults straight from
    edge/config.go and assert the Python settings equal them; if either side drifts, this fails."""
    if not settings.BS_PROJECT_ROOT:
        pytest.skip("no project anchor; cannot locate edge/config.go")
    config_go = Path(settings.BS_PROJECT_ROOT) / "edge" / "config.go"
    if not config_go.exists():
        pytest.skip(f"edge/config.go not found at {config_go}")
    src = config_go.read_text()
    assert settings.NATS_MAX_BYTES == _go_int_const(src, "defaultNATSMaxBytes"), \
        "NATS_MAX_BYTES default diverged from the edge's defaultNATSMaxBytes"
    assert settings.NATS_MAX_AGE_S == _go_int_const(src, "defaultNATSMaxAgeS"), \
        "NATS_MAX_AGE_S default diverged from the edge's defaultNATSMaxAgeS"


def test_zero_means_unbounded():
    # settings uses 0 as the "unbounded" sentinel; the builder must translate that to None (NATS's
    # own unbounded marker) rather than passing 0, which NATS would reject / treat as literal.
    import blacksea.brain.pool as pool

    orig_bytes, orig_age = pool.NATS_MAX_BYTES, pool.NATS_MAX_AGE_S
    pool.NATS_MAX_BYTES, pool.NATS_MAX_AGE_S = 0, 0.0
    try:
        cfg = _baits_stream_config()
        assert cfg.max_bytes is None
        assert cfg.max_age is None
    finally:
        pool.NATS_MAX_BYTES, pool.NATS_MAX_AGE_S = orig_bytes, orig_age
