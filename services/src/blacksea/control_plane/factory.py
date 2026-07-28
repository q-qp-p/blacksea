"""factory.py — per-instance keygen + the hermetic build pipeline.

When the operator runs ``build`` for a design, the factory:

1. Generates a fresh per-instance HMAC-SHA256 master key ``_KEY`` (inv 9, revised — was an
   Ed25519 keypair, then AES-256-GCM) and a random 8-byte ``instance_token``.
2. Builds the artifact via the three-component pipeline: resolve the
   manifest's ``build_vars`` from the instance config, bundle ``payload_file``
   (via the bundler, with the constants injected as module globals), then hand the
   bundled payload to ``staging_vessel/setup.sh`` to produce the final artifact.
3. Records the artifact descriptor in a new ``InstanceRecord`` (status ``pending`` —
   it is not in either directory until approved; see context.md's "Lifecycle state
   machines" section). ``_KEY`` itself never enters
   the registry — the caller (``operations.build_instance_op`` / ``forge.forge_bait``)
   writes it straight to the brain's key directory (see context.md's "Brain key
   directory — write side" section) using the transient
   ``key_hex`` on ``BuildOutcome``.

**inv 16:** ``_KEY`` is injected into the artifact and then discarded server-side except
for the brain's key directory. The registry stores only ``key_ref`` — never the key
bytes. Today the "hermetic build sandbox" is a controlled subprocess
(``LocalBuildContext.run``); true sandbox isolation (Nix/Docker/gVisor) is deferred.
"""

from __future__ import annotations

import hashlib
import os
import secrets
import subprocess
import tempfile
from dataclasses import dataclass, field

from blacksea.bundler.builder import BuildOptions, build as bundler_build
from blacksea.bundler.vessel_wrappers import WrapperArtifacts, WRAPPERS
from blacksea.config import settings
from blacksea.sdk.exceptions import BuildError
from blacksea.sdk.types import Artifact, BuildContext, RunResult

from blacksea.control_plane.registry import DesignRecord, InstanceRecord

# key_ref is a *description* of where the key lives, not the key (inv 16).
# The key is embedded in the built artifact and discarded server-side
# (except for the brain's key directory).
KEY_REF_EMBEDDED = "artifact-embedded"

# Operator-facing staging/trigger instructions a vessel may write to output_dir_root
# (docs/bait-authoring.md §5's "Output: how_to_stage.md" subsection). Recommended, not
# required — see the advisory-vs-hard-enforced split in run_staging_vessel() below.
HOW_TO_STAGE_FILENAME = "how_to_stage.md"

# Artifact output subdirectories — bundler intermediates vs deployment-ready outputs
BUNDLING_OUTPUTS_SUBDIR = "bundling_outputs"
TO_STAGE_SUBDIR = "to_stage"


def generate_key() -> bytes:
    """Return a fresh per-instance HMAC-SHA256 master key ``_KEY`` — 32 B random."""
    return secrets.token_bytes(32)


def generate_instance_token() -> bytes:
    """Random 8-byte instance_token (64 bits is sufficient for a
    deployment-scoped, exposed-by-design token)."""
    return secrets.token_bytes(8)


# ── build context ────────────────────────────────────────────────────────────


class LocalBuildContext(BuildContext):
    """Concrete ``BuildContext``: bundles in-process and runs the staging
    vessel as a controlled subprocess.

    Not a security sandbox — it is the build *driver*. Hermetic toolchain
    isolation (network only to pinned mirrors, no host access) is deferred hardening.
    The contract surface (the ABC) is stable so swapping the
    driver for a real sandbox later changes nothing upstream.

    Directory structure:
        <output_dir_root>/
            bundling_outputs/   # bundler intermediates (bundled.py, .gz, .b64, etc.)
            to_stage/           # vessel outputs ready for deployment
    """

    def __init__(
        self,
        *,
        bait_dir: str,
        output_dir_root: str,
        sdk_root: str,
        instance_token: bytes,
        key: bytes,
        campaign_id: str,
        callback_addresses: dict[str, str],
        bait_id: str,
        bait_version: str,
        target_arch: list[str],
        toolchain: str,
    ) -> None:
        self._bait_dir = os.path.abspath(bait_dir)
        self._output_dir_root = os.path.abspath(output_dir_root)
        self._bundling_dir = os.path.join(self._output_dir_root, BUNDLING_OUTPUTS_SUBDIR)
        self._output_dir = os.path.join(self._output_dir_root, TO_STAGE_SUBDIR)
        self._sdk_root = os.path.abspath(sdk_root)
        os.makedirs(self._bundling_dir, exist_ok=True)
        os.makedirs(self._output_dir, exist_ok=True)
        self.instance_token = instance_token
        self.key = key
        self.campaign_id = campaign_id
        self.callback_addresses = callback_addresses
        self.bait_id = bait_id
        self.bait_version = bait_version
        self.target_arch = target_arch
        self.toolchain = toolchain
        # Non-fatal, operator-facing notices collected during the build (e.g. a vessel not
        # producing how_to_stage.md) — surfaced via BuildOutcome.warnings, the same
        # warnings -> render.note() pipeline RegisterResult already uses, rather than a
        # logging call the console never configures a handler for.
        self.warnings: list[str] = []

    def run(
        self,
        cmd: list[str],
        env: dict[str, str] | None = None,
        timeout: float = settings.FACTORY_SUBPROCESS_TIMEOUT,
    ) -> RunResult:
        proc = subprocess.run(
            cmd,
            cwd=self._bait_dir,
            env={**os.environ, **(env or {})},
            capture_output=True,
            timeout=timeout,
        )
        if proc.returncode != 0:
            raise BuildError(
                f"command {cmd!r} exited {proc.returncode}\n"
                f"stderr:\n{proc.stderr.decode(errors='replace')}"
            )
        return RunResult(returncode=proc.returncode, stdout=proc.stdout, stderr=proc.stderr)

    def read_source(self, path: str) -> bytes:
        with open(os.path.join(self._bait_dir, path), "rb") as f:
            return f.read()

    def write_output(self, path: str, data: bytes) -> None:
        dest = os.path.join(self._output_dir, path)
        os.makedirs(os.path.dirname(dest) or self._output_dir, exist_ok=True)
        with open(dest, "wb") as f:
            f.write(data)

    def _write_bundling_artifacts(self, artifacts: WrapperArtifacts) -> None:
        """Write bundler intermediate files to bundling_outputs/ subdirectory.

        Writes all transformation artifacts to bundling_outputs/ so vessels can choose
        which format to consume:
            - bundled.py (flattened source)
            - bundled.gz (gzip compressed)
            - bundled.b64 (base64 encoded)
            - ready_for_vessel.txt (one-liner command string)
            - bundle_manifest.json (transformation metadata)

        Vessels SHOULD prefer reading ready_for_vessel.txt over re-implementing
        payload transformation (eliminates manual gzip+base64 encoding).
        """
        import json

        # Write all intermediate files to bundling_outputs/
        for filename, content in artifacts.intermediate_files.items():
            dest = os.path.join(self._bundling_dir, filename)
            with open(dest, "wb") as f:
                f.write(content)

        # Write the ready-for-vessel one-liner command string
        dest = os.path.join(self._bundling_dir, "ready_for_vessel.txt")
        with open(dest, "wb") as f:
            f.write(artifacts.ready_string.encode("utf-8"))

        # Write metadata manifest documenting the transformation
        manifest = {
            "format": artifacts.metadata["format"],
            "sizes": {
                "source_bytes": artifacts.metadata["source_size"],
                "compressed_bytes": artifacts.metadata["compressed_size"],
                "base64_bytes": artifacts.metadata["b64_size"],
            },
            "compression_ratio": artifacts.metadata["compression_ratio"],
            "ready_file": "ready_for_vessel.txt",
            "files": list(artifacts.intermediate_files.keys()) + ["ready_for_vessel.txt"],
        }
        dest = os.path.join(self._bundling_dir, "bundle_manifest.json")
        with open(dest, "w") as f:
            json.dump(manifest, f, indent=2)

    def bundle_payload(self, payload_path: str, inject: dict[str, str]) -> tuple[bytes, WrapperArtifacts]:
        """Run bundler and generate vessel-ready artifacts.

        Bundles ``<bait_dir>/payload_path`` with ``inject`` prepended as module-level
        constants (``inject`` maps name → Python literal string, e.g.
        ``{"_ZONE": '"cb.example.com"'}``).

        Generates vessel wrapper artifacts (bundled.py, bundled.gz, bundled.b64,
        ready_for_vessel.txt, bundle_manifest.json) and writes them immediately to
        bundling_outputs/ so vessels can consume them.

        Returns:
            Tuple of (bundled_bytes, wrapper_artifacts). The bundled_bytes are for
            backward compatibility with vessels that read bundled_payload_path from
            context.json (the temp file path).
        """
        full = os.path.join(self._bait_dir, payload_path)
        if not os.path.isfile(full):
            raise BuildError(f"payload file not found: {full!r}")
        options = BuildOptions(roots=[self._sdk_root], global_vars=dict(inject), minify=True)
        try:
            result = bundler_build(full, options)
        except Exception as exc:  # BundlerError and friends
            raise BuildError(f"bundling {payload_path!r} failed: {exc}") from exc

        bundled_bytes = result.text.encode("utf-8")

        # Generate vessel wrapper artifacts (gzip+base64 one-liner + intermediates)
        # and write them immediately to bundling_outputs/
        wrapper = WRAPPERS["python"]()
        artifacts = wrapper.wrap(bundled_bytes)
        self._write_bundling_artifacts(artifacts)

        # Write pre-minified source if minification was applied
        if result.pre_minified_text is not None:
            dest = os.path.join(self._bundling_dir, "bundled_pre_minify.py")
            with open(dest, "w", encoding="utf-8") as f:
                f.write(result.pre_minified_text)

        return bundled_bytes, artifacts

    def run_staging_vessel(self, vessel_dir: str, bundled: bytes, wrapper_artifacts: WrapperArtifacts | None = None) -> Artifact:
        """Write ``bundled`` + build context to temp files, invoke
        ``<vessel_dir>/setup.sh <context.json>``, validate ``artifact.json``,
        and describe the resulting artifact.

        The to_stage/ output dir is emptied first so every file present afterwards is part
        of *this* build's artifact. The descriptor records each produced file's
        sha256; ``filename`` is the primary file declared by the vessel.

        Bundler artifacts are already written to bundling_outputs/ by bundle_payload().
        Vessel outputs go to to_stage/ (self._output_dir).

        Also enforces the how_to_stage.md placement rule (docs/bait-authoring.md §5): the vessel
        may write an operator-facing ``<output_dir_root>/how_to_stage.md`` (absence only appends
        to ``self.warnings``), but declaring it in artifact.json — i.e. staging it into
        to_stage/ — is a BuildError, since to_stage/ ships to the honeypot."""
        setup = os.path.join(self._bait_dir, vessel_dir, "setup.sh")
        if not os.path.isfile(setup):
            raise BuildError(f"staging vessel setup.sh not found: {setup!r}")

        # Empty only to_stage/ — bundling_outputs/ is already populated
        _empty_dir(self._output_dir)

        fd_bundled, tmp_bundled = tempfile.mkstemp(suffix="_bundled.py")
        fd_context, tmp_context = tempfile.mkstemp(suffix="_context.json")
        try:
            with os.fdopen(fd_bundled, "wb") as f:
                f.write(bundled)

            context = {
                "bundled_payload_path": tmp_bundled,
                "bundling_outputs_dir": self._bundling_dir,
                "output_dir": self._output_dir,
                "output_dir_root": self._output_dir_root,
                "bait_id": self.bait_id,
                "bait_version": self.bait_version,
                "campaign_id": self.campaign_id,
                "target_arch": self.target_arch,
                "toolchain": self.toolchain,
                "callback_addresses": self.callback_addresses,
                "seed": secrets.token_hex(16),
            }
            with os.fdopen(fd_context, "w") as f:
                import json
                json.dump(context, f)

            self.run(["bash", setup, tmp_context])
        finally:
            for tmp in (tmp_bundled, tmp_context):
                try:
                    os.unlink(tmp)
                except FileNotFoundError:
                    pass

        # Read and validate artifact.json.
        # artifact.json lives in the root (alongside bundling_outputs/ and to_stage/), not inside to_stage/
        artifact_json_path = os.path.join(self._output_dir_root, "artifact.json")
        if not os.path.isfile(artifact_json_path):
            raise BuildError(
                f"staging vessel did not produce artifact.json in {self._output_dir_root!r}"
            )
        import json
        try:
            with open(artifact_json_path) as f:
                artifact_manifest = json.load(f)
        except Exception as exc:
            raise BuildError(f"artifact.json parse failed: {exc}") from exc

        if "primary" not in artifact_manifest:
            raise BuildError("artifact.json missing required field 'primary'")
        if "files" not in artifact_manifest or not isinstance(artifact_manifest["files"], dict):
            raise BuildError("artifact.json missing or invalid 'files' map")

        primary = artifact_manifest["primary"]
        declared_files = set(artifact_manifest["files"].keys())

        # how_to_stage.md is operator-only (docs/bait-authoring.md §5) — to_stage/ is what ships
        # to the honeypot, so declaring it here (i.e. staging it into to_stage/) would leak
        # deployment/trigger intel to the attacker. Hard-enforced, unlike the file's own presence
        # (see the advisory check near the end of this method).
        if HOW_TO_STAGE_FILENAME in declared_files:
            raise BuildError(
                f"artifact.json declares '{HOW_TO_STAGE_FILENAME}' — it is operator-only and must "
                f"be written to output_dir_root, never staged into to_stage/ (output_dir)"
            )

        if primary not in declared_files:
            raise BuildError(
                f"artifact.json primary='{primary}' not in files map: {declared_files}"
            )
        primary_path = os.path.join(self._output_dir, primary)
        if not os.path.isfile(primary_path):
            raise BuildError(f"artifact.json primary='{primary}' does not exist on disk")

        # Every file physically present in to_stage/ must be declared.
        # artifact.json is in the root directory (not in to_stage/), so it won't appear here.
        # Bundler artifacts are in bundling_outputs/, not to_stage/, so they're not checked here.
        def walk_output_dir(root):
            for dirpath, _, filenames in os.walk(root):
                for filename in filenames:
                    full = os.path.join(dirpath, filename)
                    rel = os.path.relpath(full, root)
                    yield rel

        produced = set(walk_output_dir(self._output_dir))
        undeclared = produced - declared_files
        if undeclared:
            raise BuildError(
                f"staging vessel left undeclared files in output_dir: {sorted(undeclared)}"
            )
        missing = declared_files - produced
        if missing:
            raise BuildError(
                f"artifact.json declares files not found on disk: {sorted(missing)}"
            )

        # Advisory only (docs/bait-authoring.md §5): recommended but not required for exit 0,
        # so existing vessels can adopt it gradually instead of needing an immediate retrofit.
        # Collected on self.warnings (-> BuildOutcome.warnings) rather than logged, so it
        # reaches the operator through the same render.note() pipeline every other build/forge
        # warning already uses instead of Python logging, which the console never configures a
        # handler for.
        how_to_stage_path = os.path.join(self._output_dir_root, HOW_TO_STAGE_FILENAME)
        if not os.path.isfile(how_to_stage_path):
            self.warnings.append(
                f"staging vessel {vessel_dir!r} did not produce {HOW_TO_STAGE_FILENAME} in "
                f"{self._output_dir_root!r} — operators will have no per-build staging/trigger "
                f"instructions for this artifact (see docs/bait-authoring.md §5)")

        # Hash every declared file (never trust the vessel's hashes, always read from disk).
        files = {}
        for name in declared_files:
            with open(os.path.join(self._output_dir, name), "rb") as f:
                files[name] = hashlib.sha256(f.read()).hexdigest()

        return Artifact(
            artifact_type="file",
            descriptor={
                "filename": primary,
                "sha256": files[primary],
                "files": files,
                "output_dir": self._output_dir,
                "output_dir_root": self._output_dir_root,
            },
        )


# ── factory entry point ──────────────────────────────────────────────────────


@dataclass
class BuildOutcome:
    instance: InstanceRecord
    artifact: Artifact
    output_dir: str
    # The raw `_KEY` (64-char hex), returned ONLY so the caller can write it to the brain's
    # key directory (see context.md's "Brain key directory — write side" section) in the same
    # build step. Never persist this anywhere else — the
    # registry (`instance`) deliberately carries `key_ref`, not the key.
    key_hex: str
    # Non-fatal, operator-facing notices collected during the build (e.g. a vessel not
    # producing how_to_stage.md) — the same shape as RegisterResult.warnings, rendered via
    # render.note() by the caller.
    warnings: list[str] = field(default_factory=list)


# Standard build-var names the factory can resolve from instance config without
# operator input. Bait-author-chosen names outside this set must be supplied via
# ``--set NAME=VALUE`` at build time, else the build fails (never a silent pass).
#
# ``campaign_id`` is deliberately NOT injectable: the payload never needs it and it
# is never on the wire (minimal envelope). The brain derives campaign_id from
# the key directory keyed by ``instance_token`` (verifier.py) and records it there —
# so it stays entirely backend-side and is never shared with the delivered payload.
_STANDARD_VARS_DOC = {
    "_TOKEN": "instance_token (hex)",
    "_KEY": "HMAC-SHA256 master key (hex)",
    "_ZONE": "callback_addresses['dns']",
    "_SERVER_URL": "callback_addresses['https']",
}


def _standard_build_vars(
    *, token_hex: str, key_hex: str,
    callbacks: dict[str, str],
) -> dict[str, str]:
    std = {
        "_TOKEN": token_hex,
        "_KEY": key_hex,
    }
    if "dns" in callbacks:
        std["_ZONE"] = callbacks["dns"]
    if "https" in callbacks:
        std["_SERVER_URL"] = callbacks["https"]
    return std


def resolve_build_vars(
    declared: list[str],
    *, token_hex: str, key_hex: str,
    callbacks: dict[str, str],
    overrides: dict[str, str] | None = None,
) -> dict[str, str]:
    """Resolve every name in the manifest's ``build_vars`` to a concrete value.

    Resolution order: operator ``overrides`` first, then the standard vars
    derived from instance config. Any declared name left unresolved raises
    ``BuildError`` — the factory never bundles a payload with a dangling
    ``_FOO`` constant.

    Note: ``campaign_id`` is intentionally not resolvable here — it is a
    backend-only routing fact (see ``_STANDARD_VARS_DOC``)."""
    overrides = overrides or {}
    std = _standard_build_vars(
        token_hex=token_hex, key_hex=key_hex,
        callbacks=callbacks,
    )
    resolved: dict[str, str] = {}
    unresolved: list[str] = []
    for name in declared:
        if name in overrides:
            resolved[name] = overrides[name]
        elif name in std:
            resolved[name] = std[name]
        else:
            unresolved.append(name)
    if unresolved:
        raise BuildError(
            f"unresolved build_vars {unresolved!r}: not standard "
            f"({sorted(_STANDARD_VARS_DOC)}) and no --set override provided"
        )
    return resolved


def build_instance(
    design: DesignRecord,
    *,
    campaign_id: str,
    callback_addresses: dict[str, str],
    sdk_root: str,
    output_dir_root: str,
    now_iso: str,
    var_overrides: dict[str, str] | None = None,
    comment: str | None = None,
) -> BuildOutcome:
    """Run the full per-instance build and return the new (pending) instance
    record + its artifact. ``comment`` is an optional free-text operator note stored
    verbatim on the instance record (descriptive metadata only — it never affects the
    build, routing, or attribution). Does not write to the registry — the caller persists
    the returned record (so build + persistence stay one auditable step). The
    returned ``key_hex`` must be written to the brain's key directory (see context.md's
    "Brain key directory — write side" section) by
    the caller — this function does not do so itself (it has no I/O dependency
    on the brain's storage).

    output_dir_root is the base directory containing bundling_outputs/ and to_stage/."""
    manifest = design.manifest
    token = generate_instance_token()
    key = generate_key()
    token_hex, key_hex = token.hex(), key.hex()

    declared_vars = list(manifest.get("build_vars") or [])
    resolved = resolve_build_vars(
        declared_vars,
        token_hex=token_hex, key_hex=key_hex,
        callbacks=callback_addresses,
        overrides=var_overrides,
    )
    # Bundler global_vars are raw RHS expressions; pass each value as a repr'd
    # Python string literal so the payload sees `_ZONE = "cb.example.com"`.
    inject = {name: repr(value) for name, value in resolved.items()}

    build_cfg = manifest.get("build") or {}
    # An omitted/empty target_arch passes through as [], not a hardcoded default -- staging
    # vessels that compile native binaries (pwcrypt) already treat an empty target_arch as
    # "figure out what to build yourself" (it builds the full portable release matrix), so
    # silently substituting ["x86_64-linux"] here pre-empted that path before it could ever run.
    target_arch = list(build_cfg.get("target_arch") or [])
    toolchain = str(build_cfg.get("toolchain", "unspecified"))

    ctx = LocalBuildContext(
        bait_dir=design.bait_dir,
        output_dir_root=output_dir_root,
        sdk_root=sdk_root,
        instance_token=token,
        key=key,
        campaign_id=campaign_id,
        callback_addresses=callback_addresses,
        bait_id=design.bait_id,
        bait_version=design.version,
        target_arch=target_arch,
        toolchain=toolchain,
    )

    bundled, wrapper_artifacts = ctx.bundle_payload(str(manifest["payload_file"]), inject)
    # wrapper_artifacts are already written to bundling_outputs/ by bundle_payload()
    artifact = ctx.run_staging_vessel(str(manifest["staging_vessel"]), bundled, wrapper_artifacts)

    instance = InstanceRecord(
        instance_token=token_hex,
        bait_id=design.bait_id,
        bait_version=design.version,
        key_ref=KEY_REF_EMBEDDED,   # inv 16: never the key itself
        campaign_id=campaign_id,
        callback_addresses=dict(callback_addresses),
        status="pending",
        artifact={"artifact_type": artifact.artifact_type, "descriptor": artifact.descriptor},
        built_at=now_iso,
        # O11 #2: pin the design's frozen-listener digest onto the instance, so the
        # instance carries the exact listener it expects even if the design row is later edited.
        listener_hash=design.listener_hash,
        comment=comment or None,   # normalise empty → NULL (descriptive metadata only)
    )
    # `key`/`key_hex` go out of scope after the caller writes key_hex to the brain's key
    # directory; nothing else persists them (inv 16).
    return BuildOutcome(
        instance=instance, artifact=artifact, output_dir=output_dir_root, key_hex=key_hex,
        warnings=ctx.warnings)


def _empty_dir(path: str) -> None:
    os.makedirs(path, exist_ok=True)
    for name in os.listdir(path):
        full = os.path.join(path, name)
        if os.path.isfile(full) or os.path.islink(full):
            os.unlink(full)
