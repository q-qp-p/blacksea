"""Postgres-backed catalog: round-trips, inv-16 (no key in the DB), and the O3 transaction
API (atomicity + writer serialization)."""

from __future__ import annotations

import threading

from psycopg import sql

from blacksea.control_plane import lifecycle
from blacksea.control_plane.registry import (
    DesignRecord,
    InstanceRecord,
    Registry,
    replace,
)


def _design(bait_id="hostname-probe", **manifest):
    base = {
        "version": "1.0.0",
        "assurance_tier": 0,
        "deploy_class": "portable_artifact",
        "channels": {"dns": {}},
    }
    base.update(manifest)
    return DesignRecord(bait_id=bait_id, manifest=base, bait_dir="/x", registered_at="t0")


def _instance(token="aabbccddeeff0011", bait_id="hostname-probe",
              callback_addresses=None, **kw):
    return InstanceRecord(
        instance_token=token, bait_id=bait_id, bait_version="1.0.0",
        key_ref="artifact-embedded", campaign_id="C-T",
        callback_addresses=callback_addresses if callback_addresses is not None else {"dns": "z"},
        **kw,
    )


# ── round-trips ────────────────────────────────────────────────────────────────


def test_design_round_trip(registry):
    registry.put_design(_design())
    got = registry.get_design("hostname-probe")
    assert got is not None
    assert got.bait_id == "hostname-probe"
    assert got.version == "1.0.0"
    assert got.default_channel == "dns"
    assert got.assurance_tier == 0
    assert got.test is False


def test_design_test_flag(registry):
    registry.put_design(_design(test=True))
    got = registry.get_design("hostname-probe")
    assert got is not None and got.test is True


def test_design_upsert_overwrites(registry):
    registry.put_design(_design())
    registry.put_design(replace(_design(), status="staged", listener_hash="deadbeef"))
    got = registry.get_design("hostname-probe")
    assert got.status == "staged"
    assert got.listener_hash == "deadbeef"
    assert len(registry.list_designs()) == 1  # upsert, not a second row


def test_instance_round_trip_and_filter(registry):
    registry.put_design(_design(bait_id="a"))
    registry.put_design(_design(bait_id="b"))
    registry.put_instance(_instance(token="1111111111111111", bait_id="a"))
    registry.put_instance(_instance(token="2222222222222222", bait_id="b"))
    assert len(registry.list_instances()) == 2
    only_a = registry.list_instances(bait_id="a")
    assert [i.instance_token for i in only_a] == ["1111111111111111"]


def test_instance_preserves_callbacks_and_artifact(registry):
    registry.put_design(_design())
    registry.put_instance(_instance(
        callback_addresses={"dns": "cb.zone"},
        artifact={"artifact_type": "file", "descriptor": {"filename": "bait.py"}},
        listener_hash="cafe",
    ))
    got = registry.get_instance("aabbccddeeff0011")
    assert got.callback_addresses == {"dns": "cb.zone"}
    assert got.artifact["descriptor"]["filename"] == "bait.py"
    assert got.listener_hash == "cafe"


def test_instance_comment_round_trip(registry):
    registry.put_design(_design())
    registry.put_instance(_instance(comment="built for field-2026q3, host bravo"))
    got = registry.get_instance("aabbccddeeff0011")
    assert got.comment == "built for field-2026q3, host bravo"


def test_instance_comment_defaults_to_none(registry):
    """An instance built without a note stores NULL, not an empty string."""
    registry.put_design(_design())
    registry.put_instance(_instance())
    got = registry.get_instance("aabbccddeeff0011")
    assert got.comment is None


def test_instance_artifact_dir_is_the_to_stage_directory():
    """`artifact_dir` is the vessel's whole `to_stage/` output directory (the descriptor's
    `output_dir`) — the full deployable an operator ships, which may hold more than the primary
    file — not a single file. None until the instance is built."""
    unbuilt = _instance()
    assert unbuilt.artifact_dir is None
    built = _instance(artifact={
        "artifact_type": "file",
        "descriptor": {"filename": "bait.py", "output_dir": "/reg/artifacts/hp/20260716/to_stage"},
    })
    assert built.artifact_dir == "/reg/artifacts/hp/20260716/to_stage"


def test_missing_records_return_none(registry):
    assert registry.get_design("nope") is None
    assert registry.get_instance("nope") is None
    assert registry.list_designs() == []


def test_key_never_stored_in_db(registry, pg_dsn, cp_schema):
    """inv 16: the instance table has no column that could hold key material — only key_ref."""
    registry.put_design(_design())
    registry.put_instance(_instance())
    got = registry.get_instance("aabbccddeeff0011")
    assert got.key_ref == "artifact-embedded"
    # And structurally: no 'key' column exists on the instance table.
    import psycopg
    with psycopg.connect(pg_dsn, autocommit=True) as conn:
        cols = {
            r[0] for r in conn.execute(
                "SELECT column_name FROM information_schema.columns "
                "WHERE table_schema = %s AND table_name = 'instance'", (cp_schema,)).fetchall()
        }
    assert "key_ref" in cols
    assert "key" not in cols and "pubkey" not in cols and "privkey" not in cols


# ── O3: transaction API ──────────────────────────────────────────────────────


def test_transaction_commits_both_writes(registry):
    registry.put_design(replace(_design(), status="staged"))
    registry.put_instance(_instance(status="pending"))
    with registry.transaction() as tx:
        inst = tx.get_instance("aabbccddeeff0011")
        tx.put_instance(replace(inst, status="active", approved_at="t1"))
        design = tx.get_design("hostname-probe")
        tx.put_design(replace(design, status="deployed"))
    assert registry.get_instance("aabbccddeeff0011").status == "active"
    assert registry.get_design("hostname-probe").status == "deployed"


def test_transaction_rolls_back_both_on_crash(registry):
    """A crash between the two writes leaves *neither* applied (Motivation #1)."""
    registry.put_design(replace(_design(), status="staged"))
    registry.put_instance(_instance(status="pending"))
    boom = RuntimeError("crash mid-transition")
    try:
        with registry.transaction() as tx:
            inst = tx.get_instance("aabbccddeeff0011")
            tx.put_instance(replace(inst, status="active"))
            raise boom  # before the design promote
    except RuntimeError as exc:
        assert exc is boom
    # Neither write survived.
    assert registry.get_instance("aabbccddeeff0011").status == "pending"
    assert registry.get_design("hostname-probe").status == "staged"


def test_concurrent_approve_serializes_no_lost_update(registry, pg_dsn, cp_schema, tmp_path):
    """Two racing approves on the same instance serialize via the FOR UPDATE row lock —
    exactly one wins (pending→active), the other sees 'active' and is rejected (Motivation #2)."""
    registry.put_design(replace(_design(), status="staged"))
    registry.put_instance(_instance(status="pending"))

    results: list[str] = []
    lock = threading.Lock()
    barrier = threading.Barrier(2)

    def worker():
        reg = Registry(pg_dsn, registry_root=str(tmp_path / "r"),
                       schema=cp_schema, auto_ensure=False)
        barrier.wait()  # maximise the race
        try:
            lifecycle.approve_instance(reg, "aabbccddeeff0011", now="t1")
            outcome = "approved"
        except lifecycle.TransitionError:
            outcome = "rejected"
        finally:
            reg.close()
        with lock:
            results.append(outcome)

    threads = [threading.Thread(target=worker) for _ in range(2)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert sorted(results) == ["approved", "rejected"]      # no lost update
    assert registry.get_instance("aabbccddeeff0011").status == "active"
    assert registry.get_design("hostname-probe").status == "deployed"
