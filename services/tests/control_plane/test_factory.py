"""Factory: keygen, build_var resolution, and the build pipeline."""

from __future__ import annotations

import pytest
import yaml

from blacksea.control_plane import factory
from blacksea.control_plane.registry import DesignRecord
from blacksea.sdk.exceptions import BuildError

from conftest import HOSTNAME_PROBE


def _design() -> DesignRecord:
    manifest = yaml.safe_load((HOSTNAME_PROBE / "manifest.yaml").read_text())
    return DesignRecord(
        bait_id=manifest["bait_id"], manifest=manifest,
        bait_dir=str(HOSTNAME_PROBE), status="staged",
    )


def test_key_shape():
    key = factory.generate_key()
    assert len(key) == 32
    assert factory.generate_key() != key                 # fresh each call
    assert len(factory.generate_instance_token()) == 8


def test_resolve_build_vars_standard_and_override():
    resolved = factory.resolve_build_vars(
        ["_ZONE", "_TOKEN", "_CUSTOM"],
        token_hex="aa" * 8, key_hex="bb" * 32,
        callbacks={"dns": "cb.zone"},
        overrides={"_CUSTOM": "hello"},
    )
    assert resolved == {"_ZONE": "cb.zone", "_TOKEN": "aa" * 8, "_CUSTOM": "hello"}


def test_campaign_id_is_not_an_injectable_build_var():
    """campaign_id is a backend-only routing fact — the payload never receives it.
    Declaring `_CAMPAIGN` fails the build like any other unresolved name."""
    assert "_CAMPAIGN" not in factory._STANDARD_VARS_DOC
    with pytest.raises(BuildError):
        factory.resolve_build_vars(
            ["_CAMPAIGN"],
            token_hex="aa" * 8, key_hex="bb" * 32,
            callbacks={"https": "cb"},
        )


def test_resolve_build_vars_unresolved_raises():
    with pytest.raises(BuildError):
        factory.resolve_build_vars(
            ["_MISSING"],
            token_hex="aa" * 8, key_hex="bb" * 32,
            callbacks={},
        )


def test_build_instance_produces_artifact_with_injected_constants(tmp_path, sdk_root):
    out = str(tmp_path / "art")
    outcome = factory.build_instance(
        _design(),
        campaign_id="C-T", callback_addresses={"dns": "cb.example.com"},
        sdk_root=sdk_root, output_dir_root=out, now_iso="2026-06-07T00:00:00+00:00",
        var_overrides={"_DNS_SERVER": ""},
    )
    inst = outcome.instance
    assert inst.status == "pending"
    assert len(inst.instance_token) == 16            # 8 B hex
    assert len(outcome.key_hex) == 64                 # 32 B hex, transient (never on inst)
    assert inst.key_ref == factory.KEY_REF_EMBEDDED

    # The bundled payload carries the injected constants (_ZONE/_TOKEN), proving
    # the bundler + build_var resolution ran end-to-end.
    import pathlib
    # The artifact lives in to_stage/ subdirectory
    produced = pathlib.Path(outcome.output_dir) / "to_stage" / inst.artifact["descriptor"]["filename"]
    text = produced.read_text()
    assert 'cb.example.com' in text
    assert inst.instance_token in text


def test_build_instance_does_not_persist_key(tmp_path, sdk_root):
    """inv 16: the instance record exposes no key material, only key_ref."""
    outcome = factory.build_instance(
        _design(), campaign_id="C", callback_addresses={"dns": "z"},
        sdk_root=sdk_root, output_dir_root=str(tmp_path / "a"), now_iso="t0",
        var_overrides={"_DNS_SERVER": ""},
    )
    import dataclasses
    fields = dataclasses.asdict(outcome.instance)
    assert "key" not in fields
    assert fields["key_ref"] == "artifact-embedded"


def test_artifact_primary_from_vessel_declaration_not_alphabetical(tmp_path, sdk_root, bait_factory):
    """Primary comes from artifact.json, not alphabetical sort (closes the
    alphabetical-sort bug where README.md could be picked as the primary)."""
    # Use bait_factory to create a vessel whose artifact.json declares
    # 'zzz_actual_primary.py' as primary even though 'aaa_readme.md' sorts first.
    # Override staging_vessel back to a local relative path (the default now points at the
    # real lure_material/staging_vessels/identity catalog entry) so the custom vessel written
    # below is the one the factory actually runs.
    bait_dir = bait_factory(staging_vessel="staging_vessel")
    vessel_dir = f"{bait_dir}/staging_vessel"
    import os
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
# Stage two files: aaa_readme.md (sorts first alphabetically) and zzz_actual_primary.py
cat > "$OUTPUT/aaa_readme.md" <<'EOF'
This is a readme that sorts first alphabetically.
EOF
cp "$BUNDLED" "$OUTPUT/zzz_actual_primary.py"
chmod +x "$OUTPUT/zzz_actual_primary.py"
# Declare zzz_actual_primary.py as the primary (not aaa_readme.md).
cat > "$OUTPUT_ROOT/artifact.json" <<'EOF'
{
  "primary": "zzz_actual_primary.py",
  "files": {
    "aaa_readme.md": {"role": "doc"},
    "zzz_actual_primary.py": {"role": "script"}
  }
}
EOF
""")
    os.chmod(setup_sh, 0o755)

    design = DesignRecord(
        bait_id="test-primary-order", manifest=yaml.safe_load(open(bait_dir + "/manifest.yaml")),
        bait_dir=bait_dir, status="staged",
    )
    outcome = factory.build_instance(
        design, campaign_id="C", callback_addresses={"dns": "z"},
        sdk_root=sdk_root, output_dir_root=str(tmp_path / "out"), now_iso="t0",
        var_overrides={"_DNS_SERVER": ""},
    )
    # The primary must be zzz_actual_primary.py, not aaa_readme.md (alphabetically first).
    assert outcome.artifact.descriptor["filename"] == "zzz_actual_primary.py"


def test_undeclared_leftover_file_raises_build_error(tmp_path, sdk_root, bait_factory):
    """Every file physically present in output_dir (except artifact.json) must be
    declared in artifact.json's files map. A vessel that leaves undeclared leftovers must
    fail the build."""
    # Override staging_vessel back to a local relative path (the default now points at the
    # real lure_material/staging_vessels/identity catalog entry) so the custom vessel written
    # below is the one the factory actually runs.
    bait_dir = bait_factory(staging_vessel="staging_vessel")
    vessel_dir = f"{bait_dir}/staging_vessel"
    import os
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
# Leave an undeclared leftover file.
echo "leftover build artifact" > "$OUTPUT/undeclared.o"
# Only declare declared.py in artifact.json (undeclared.o is missing).
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

    design = DesignRecord(
        bait_id="test-undeclared", manifest=yaml.safe_load(open(bait_dir + "/manifest.yaml")),
        bait_dir=bait_dir, status="staged",
    )
    with pytest.raises(BuildError, match="undeclared files in output_dir"):
        factory.build_instance(
            design, campaign_id="C", callback_addresses={"dns": "z"},
            sdk_root=sdk_root, output_dir_root=str(tmp_path / "out"), now_iso="t0",
            var_overrides={"_DNS_SERVER": ""},
        )


def _write_vessel(bait_dir: str, setup_body: str) -> None:
    """Shared helper for the how_to_stage.md tests below — writes a custom
    staging_vessel/setup.sh (mirrors the inline vessels in the tests above)."""
    import os
    vessel_dir = f"{bait_dir}/staging_vessel"
    os.makedirs(vessel_dir, exist_ok=True)
    setup_sh = f"{vessel_dir}/setup.sh"
    with open(setup_sh, "w") as f:
        f.write(setup_body)
    os.chmod(setup_sh, 0o755)


def test_how_to_stage_declared_in_to_stage_raises_build_error(tmp_path, sdk_root, bait_factory):
    """how_to_stage.md is operator-only (docs/bait-authoring.md §5) — a vessel that declares it
    in artifact.json (i.e. stages it into to_stage/, which ships to the honeypot) must fail the
    build, not just warn. This is the one hard-enforced part of the contract."""
    bait_dir = bait_factory(staging_vessel="staging_vessel")
    _write_vessel(bait_dir, """#!/usr/bin/env bash
set -euo pipefail
CTX="${1:?usage: setup.sh <context.json>}"
BUNDLED=$(python3 -c "import json; c=json.load(open('$CTX')); print(c['bundled_payload_path'])")
OUTPUT=$(python3 -c "import json; c=json.load(open('$CTX')); print(c['output_dir'])")
OUTPUT_ROOT=$(python3 -c "import json; c=json.load(open('$CTX')); print(c['output_dir_root'])")
mkdir -p "$OUTPUT"
cp "$BUNDLED" "$OUTPUT/declared.py"
echo "leaked staging instructions" > "$OUTPUT/how_to_stage.md"
cat > "$OUTPUT_ROOT/artifact.json" <<'EOF'
{
  "primary": "declared.py",
  "files": {
    "declared.py": {"role": "script"},
    "how_to_stage.md": {"role": "doc"}
  }
}
EOF
""")

    design = DesignRecord(
        bait_id="test-how-to-stage-leak", manifest=yaml.safe_load(open(bait_dir + "/manifest.yaml")),
        bait_dir=bait_dir, status="staged",
    )
    with pytest.raises(BuildError, match="operator-only"):
        factory.build_instance(
            design, campaign_id="C", callback_addresses={"dns": "z"},
            sdk_root=sdk_root, output_dir_root=str(tmp_path / "out"), now_iso="t0",
            var_overrides={"_DNS_SERVER": ""},
        )


def test_how_to_stage_missing_warns_via_outcome_but_build_succeeds(tmp_path, sdk_root, bait_factory):
    """Absence of how_to_stage.md is advisory only (recommended, not required for exit 0) —
    lets existing vessels adopt it gradually instead of needing an immediate retrofit. Surfaced
    on BuildOutcome.warnings (-> render.note() downstream), not via Python logging — the console
    never configures a handler, so a bare log.warning() would be effectively invisible."""
    bait_dir = bait_factory(staging_vessel="staging_vessel")
    _write_vessel(bait_dir, """#!/usr/bin/env bash
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

    design = DesignRecord(
        bait_id="test-how-to-stage-missing", manifest=yaml.safe_load(open(bait_dir + "/manifest.yaml")),
        bait_dir=bait_dir, status="staged",
    )
    outcome = factory.build_instance(
        design, campaign_id="C", callback_addresses={"dns": "z"},
        sdk_root=sdk_root, output_dir_root=str(tmp_path / "out"), now_iso="t0",
        var_overrides={"_DNS_SERVER": ""},
    )
    assert outcome.instance.status == "pending"      # build still succeeded
    assert any("how_to_stage.md" in w for w in outcome.warnings)


def test_how_to_stage_present_in_output_root_no_warning(tmp_path, sdk_root, bait_factory):
    """A vessel that correctly writes how_to_stage.md to output_dir_root (not to_stage/) builds
    cleanly with no warning."""
    bait_dir = bait_factory(staging_vessel="staging_vessel")
    _write_vessel(bait_dir, """#!/usr/bin/env bash
set -euo pipefail
CTX="${1:?usage: setup.sh <context.json>}"
BUNDLED=$(python3 -c "import json; c=json.load(open('$CTX')); print(c['bundled_payload_path'])")
OUTPUT=$(python3 -c "import json; c=json.load(open('$CTX')); print(c['output_dir'])")
OUTPUT_ROOT=$(python3 -c "import json; c=json.load(open('$CTX')); print(c['output_dir_root'])")
mkdir -p "$OUTPUT"
cp "$BUNDLED" "$OUTPUT/declared.py"
echo "# how to stage" > "$OUTPUT_ROOT/how_to_stage.md"
cat > "$OUTPUT_ROOT/artifact.json" <<'EOF'
{
  "primary": "declared.py",
  "files": {
    "declared.py": {"role": "script"}
  }
}
EOF
""")

    design = DesignRecord(
        bait_id="test-how-to-stage-present", manifest=yaml.safe_load(open(bait_dir + "/manifest.yaml")),
        bait_dir=bait_dir, status="staged",
    )
    outcome = factory.build_instance(
        design, campaign_id="C", callback_addresses={"dns": "z"},
        sdk_root=sdk_root, output_dir_root=str(tmp_path / "out"), now_iso="t0",
        var_overrides={"_DNS_SERVER": ""},
    )
    assert outcome.instance.status == "pending"
    assert outcome.warnings == []
