"""forge end-to-end: the single-call `register → build → approve` path driven by a
self-sufficient manifest (`deploy:` block), with CLI overrides. Exercises the CLI-agnostic
`forge_bait()` library + `load_deploy_config()` directly — the exact code the `blacksea forge`
console command runs (there is no argparse forge script anymore). Over the Postgres catalog (D2)."""

from __future__ import annotations

import os

import pytest

from blacksea.brain.verifier import KeyDirectory
from blacksea.control_plane import operations
from blacksea.control_plane.forge import ForgeError, forge_bait, load_deploy_config
from blacksea.control_plane.ingestion import load_manifest
from blacksea.control_plane.registry import Registry

from conftest import SDK_ROOT

# hostname_probe is tier-0 DNS with a `_ZONE` build var → the callback channel is `dns`.
# Its payload (lure_material/payloads/hostname_grab_dns/) also declares `_DNS_SERVER` (local/
# test raw-UDP delivery override) — not a standard auto-resolved var, so it needs an explicit
# build_vars entry (empty, as a real deployment would use).
_DEPLOY = {
    "campaign": "C-forge", "callbacks": {"dns": "cb.forge.test"},
    "build_vars": {"_DNS_SERVER": ""},
}


def _ctx(tmp_path, pg_dsn, cp_schema) -> operations.Ctx:
    """The same `operations.Ctx` the console builds from its flags."""
    registry = Registry(pg_dsn, registry_root=str(tmp_path / "registry"), schema=cp_schema)
    return operations.Ctx(
        registry=registry,
        brain_keydir_path=str(tmp_path / "brain_keydir.json"),
        sdk_root=str(SDK_ROOT),
        artifacts_root=str(tmp_path / "artifacts"),
    )


def _forge(tmp_path, pg_dsn, cp_schema, bait_dir, **overrides):
    """Load the manifest's `deploy:` block (layering the CLI overrides on top) and drive
    `forge_bait` — the same two-step the console's `forge` command runs. Returns the ForgeResult."""
    ctx = _ctx(tmp_path, pg_dsn, cp_schema)
    try:
        cfg = load_deploy_config(load_manifest(bait_dir), **overrides)
        return forge_bait(ctx, bait_dir, cfg)
    finally:
        ctx.registry.close()


def _reg(tmp_path, pg_dsn, cp_schema) -> Registry:
    return Registry(pg_dsn, registry_root=str(tmp_path / "registry"),
                    schema=cp_schema, auto_ensure=False)


def _instances(tmp_path, pg_dsn, cp_schema):
    reg = _reg(tmp_path, pg_dsn, cp_schema)
    try:
        return reg.list_instances()
    finally:
        reg.close()


def test_forge_full_chain(tmp_path, pg_dsn, cp_schema, bait_factory):
    bait = bait_factory(deploy=_DEPLOY)
    res = _forge(tmp_path, pg_dsn, cp_schema, bait)
    assert res.status == "active"

    # One active instance in the catalog.
    insts = _instances(tmp_path, pg_dsn, cp_schema)
    assert len(insts) == 1
    inst = insts[0]
    assert inst.status == "active"
    assert inst.campaign_id == "C-forge"
    token = inst.instance_token

    # Brain key directory (the sole directory now) carries the key + active status.
    kd = KeyDirectory.from_file(str(tmp_path / "brain_keydir.json"))
    entry = kd.lookup(bytes.fromhex(token))
    assert entry is not None and entry.status == "active"

    # Artifact present on disk. There is no edge routing directory / signed snapshot anymore.
    desc = inst.artifact["descriptor"]
    assert os.path.isfile(desc["output_dir"] + "/" + desc["filename"])


def test_forge_no_approve_stops_at_pending(tmp_path, pg_dsn, cp_schema, bait_factory):
    bait = bait_factory(deploy=_DEPLOY)
    res = _forge(tmp_path, pg_dsn, cp_schema, bait, no_approve=True)
    assert res.status == "pending"

    inst = _instances(tmp_path, pg_dsn, cp_schema)[0]
    assert inst.status == "pending"
    # build still writes _KEY to the brain key directory (so a pre-approval hit can be
    # identified), but with pending status — approve is what refreshes it to active.
    kd = KeyDirectory.from_file(str(tmp_path / "brain_keydir.json"))
    entry = kd.lookup(bytes.fromhex(inst.instance_token))
    assert entry is not None and entry.status == "pending"


def test_forge_comment_from_cli_stored_on_instance(tmp_path, pg_dsn, cp_schema, bait_factory):
    bait = bait_factory(deploy=_DEPLOY)
    _forge(tmp_path, pg_dsn, cp_schema, bait, cli_comment="target: honeypot-7")
    inst = _instances(tmp_path, pg_dsn, cp_schema)[0]
    assert inst.comment == "target: honeypot-7"


def test_forge_comment_from_manifest_deploy_block(tmp_path, pg_dsn, cp_schema, bait_factory):
    bait = bait_factory(deploy={**_DEPLOY, "comment": "campaign default note"})
    _forge(tmp_path, pg_dsn, cp_schema, bait)
    inst = _instances(tmp_path, pg_dsn, cp_schema)[0]
    assert inst.comment == "campaign default note"


def test_forge_no_comment_leaves_none(tmp_path, pg_dsn, cp_schema, bait_factory):
    bait = bait_factory(deploy=_DEPLOY)
    _forge(tmp_path, pg_dsn, cp_schema, bait)
    inst = _instances(tmp_path, pg_dsn, cp_schema)[0]
    assert inst.comment is None


def test_forge_cli_overrides_beat_manifest(tmp_path, pg_dsn, cp_schema, bait_factory):
    bait = bait_factory(deploy=_DEPLOY)
    _forge(tmp_path, pg_dsn, cp_schema, bait,
           cli_campaign="C-override", cli_callbacks={"dns": "cb.override.test"})

    inst = _instances(tmp_path, pg_dsn, cp_schema)[0]
    assert inst.campaign_id == "C-override"
    assert inst.callback_addresses["dns"] == "cb.override.test"


def test_forge_missing_campaign_errors(bait_factory):
    # deploy block present but no campaign, and none on the CLI → load_deploy_config rejects it.
    bait = bait_factory(deploy={"callbacks": {"dns": "cb.forge.test"}})
    with pytest.raises(ForgeError, match="campaign"):
        load_deploy_config(load_manifest(bait))


def test_forge_missing_callback_errors(bait_factory):
    # campaign present but no callback for the declared `dns` channel.
    bait = bait_factory(deploy={"campaign": "C-forge"})
    with pytest.raises(ForgeError, match="callback"):
        load_deploy_config(load_manifest(bait))


def test_forge_idempotent_reforge_refreshes(tmp_path, pg_dsn, cp_schema, bait_factory):
    bait = bait_factory(deploy=_DEPLOY)
    # Two forges of the same bait_id: the second refreshes the design (no uniqueness error)
    # and builds a second, distinct instance.
    _forge(tmp_path, pg_dsn, cp_schema, bait)
    _forge(tmp_path, pg_dsn, cp_schema, bait)

    tokens = {i.instance_token for i in _instances(tmp_path, pg_dsn, cp_schema)}
    assert len(tokens) == 2
    reg = _reg(tmp_path, pg_dsn, cp_schema)
    assert len(reg.list_designs()) == 1  # still exactly one design
    reg.close()


def test_load_deploy_config_cli_precedence():
    manifest = {
        "channels": {"dns": {}},
        "deploy": {"campaign": "M", "callbacks": {"dns": "manifest.zone"},
                   "build_vars": {"_X": "m"}, "approve": True},
    }
    cfg = load_deploy_config(
        manifest,
        cli_campaign="CLI",
        cli_callbacks={"dns": "cli.zone"},
        cli_set={"_X": "c"},
        no_approve=True,
    )
    assert cfg.campaign == "CLI"
    assert cfg.callbacks["dns"] == "cli.zone"
    assert cfg.build_vars["_X"] == "c"
    assert cfg.approve is False  # --no-approve wins over deploy.approve


def test_load_deploy_config_comment_precedence():
    manifest = {
        "channels": {"dns": {}},
        "deploy": {"campaign": "M", "callbacks": {"dns": "z"}, "comment": "manifest note"},
    }
    # CLI comment overrides the manifest's deploy.comment.
    assert load_deploy_config(manifest, cli_comment="cli note").comment == "cli note"
    # No CLI comment → the manifest's deploy.comment is used.
    assert load_deploy_config(manifest).comment == "manifest note"
    # No comment anywhere → None (never an empty string).
    bare = {"channels": {"dns": {}}, "deploy": {"campaign": "M", "callbacks": {"dns": "z"}}}
    assert load_deploy_config(bare).comment is None
