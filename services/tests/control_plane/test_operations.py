"""operations end-to-end: register → build → approve, with the resulting
brain key directory consumable by its real reader (see context.md's "Brain key directory —
write side" section). Drives the CLI-agnostic
`operations.py` shared library directly (the same code the `blacksea` console calls) — there is
no argparse frontend anymore. The edge is a dumb dead-drop with no directory of its own, so there
is no edge routing snapshot to write. Over the Postgres catalog (D2)."""

from __future__ import annotations

import pytest

from blacksea.brain.verifier import KeyDirectory
from blacksea.control_plane import operations
from blacksea.control_plane.operations import OperationError
from blacksea.control_plane.registry import Registry

from conftest import HOSTNAME_PROBE, SDK_ROOT


def _ctx(tmp_path, pg_dsn, cp_schema) -> operations.Ctx:
    """Build the same `operations.Ctx` the console constructs from its flags — a registry over
    the test's Postgres catalog plus the brain-keydir / bundler / artifacts paths."""
    registry = Registry(pg_dsn, registry_root=str(tmp_path / "registry"), schema=cp_schema)
    return operations.Ctx(
        registry=registry,
        brain_keydir_path=str(tmp_path / "brain_keydir.json"),
        sdk_root=str(SDK_ROOT),
        artifacts_root=str(tmp_path / "artifacts"),
    )


def test_full_lifecycle_register_build_approve(tmp_path, pg_dsn, cp_schema):
    ctx = _ctx(tmp_path, pg_dsn, cp_schema)
    try:
        operations.register_bait(ctx, str(HOSTNAME_PROBE))

        # hostname-probe's payload (lure_material/payloads/hostname_grab_dns/) declares a
        # _DNS_SERVER build var for local/test raw-UDP delivery; not a standard auto-resolved
        # var, so it needs an explicit build_var (empty, as a real deployment would use).
        operations.build_instance_op(
            ctx, bait_id="hostname-probe", campaign="C-2026Q2-test",
            callbacks={"dns": "cb.example.com"}, build_vars={"_DNS_SERVER": ""})

        insts = ctx.registry.list_instances()
        assert len(insts) == 1
        token = insts[0].instance_token
        assert insts[0].listener_hash is not None            # O11: pinned at build

        # The brain key directory already has the entry after build() — before approval — with the
        # pending status (the factory writes _KEY at build so a pre-approval hit can be identified).
        kd_pending = KeyDirectory.from_file(str(tmp_path / "brain_keydir.json"))
        pending_entry = kd_pending.lookup(bytes.fromhex(token))
        assert pending_entry is not None and pending_entry.status == "pending"

        operations.approve_instance_op(ctx, token)

        # The exit criterion: approve refreshes the brain key directory's status to active.
        # There is no edge routing directory / signed snapshot anymore — the edge is a dead-drop.
        kd = KeyDirectory.from_file(str(tmp_path / "brain_keydir.json"))
        entry = kd.lookup(bytes.fromhex(token))
        assert entry is not None and entry.status == "active"

        # The frozen listener was materialised at register (O10).
        assert (tmp_path / "artifacts" / "hostname-probe" / "1.0.0" / "listener"
                / "listener.py").exists()
    finally:
        ctx.registry.close()


def test_cannot_build_unregistered(tmp_path, pg_dsn, cp_schema):
    ctx = _ctx(tmp_path, pg_dsn, cp_schema)
    try:
        with pytest.raises(OperationError, match="no such design"):
            operations.build_instance_op(
                ctx, bait_id="ghost", campaign="C", callbacks={"dns": "z"})
    finally:
        ctx.registry.close()


def test_register_blocks_bad_provenance(tmp_path, pg_dsn, cp_schema, bait_factory):
    bad = bait_factory(provenance={"behavior": "", "source": "s", "observed_date": "d"})
    ctx = _ctx(tmp_path, pg_dsn, cp_schema)
    try:
        with pytest.raises(OperationError) as exc:
            operations.register_bait(ctx, bad)
        # The blocking provenance error is surfaced in the exception's `issues` (echoed to stderr
        # by a frontend), not the summary message.
        assert any("provenance" in issue for issue in exc.value.issues)
    finally:
        ctx.registry.close()


def test_build_result_carries_factory_warnings(tmp_path, pg_dsn, cp_schema, bait_factory):
    """A vessel that doesn't produce how_to_stage.md surfaces that as a warning on
    BuildResult.warnings — the same field `instances build`'s console command already loops
    over and prints via render.note(), not a Python logging call the console never configures a
    handler for (see factory.py's LocalBuildContext.warnings)."""
    import os
    bait_dir = bait_factory(staging_vessel="staging_vessel")
    vessel_dir = f"{bait_dir}/staging_vessel"
    os.makedirs(vessel_dir, exist_ok=True)
    setup_sh = f"{vessel_dir}/setup.sh"
    with open(setup_sh, "w") as f:
        f.write("""#!/usr/bin/env bash
set -euo pipefail
CTX="${1:?usage: setup.sh <context.json>}"
BUNDLED=$(python3 -c "import json; c=json.load(open('$CTX')); print(c['bundled_payload_path'])")
OUTPUT=$(python3 -c "import json; c=json.load(open('$CTX')); print(c['output_dir'])")
OUTPUT_ROOT=$(python3 -c "import json; c=json.load(open('$CTX')); print(c['output_dir_root'])")
mkdir -p "$OUTPUT"
cp "$BUNDLED" "$OUTPUT/declared.py"
cat > "$OUTPUT_ROOT/artifact.json" <<'EOF'
{
  "primary": "declared.py",
  "files": {
    "declared.py": {"role": "script"}
  }
}
EOF
""")
    os.chmod(setup_sh, 0o755)

    ctx = _ctx(tmp_path, pg_dsn, cp_schema)
    try:
        operations.register_bait(ctx, bait_dir)
        import yaml
        bait_id = yaml.safe_load(open(bait_dir + "/manifest.yaml"))["bait_id"]
        result = operations.build_instance_op(
            ctx, bait_id=bait_id, campaign="C", callbacks={"dns": "z"},
            build_vars={"_DNS_SERVER": ""})
        assert any("how_to_stage.md" in w for w in result.warnings)
    finally:
        ctx.registry.close()


def test_pending_instance_is_pending_in_brain_keydir(tmp_path, pg_dsn, cp_schema):
    """A built-but-unapproved instance is in the brain key directory (the factory writes _KEY at
    build) with status pending — it only becomes active when approve refreshes it."""
    ctx = _ctx(tmp_path, pg_dsn, cp_schema)
    try:
        operations.register_bait(ctx, str(HOSTNAME_PROBE))
        operations.build_instance_op(
            ctx, bait_id="hostname-probe", campaign="C",
            callbacks={"dns": "z"}, build_vars={"_DNS_SERVER": ""})

        token = ctx.registry.list_instances()[0].instance_token
        kd = KeyDirectory.from_file(str(tmp_path / "brain_keydir.json"))
        entry = kd.lookup(bytes.fromhex(token))
        assert entry is not None and entry.status == "pending"
    finally:
        ctx.registry.close()
