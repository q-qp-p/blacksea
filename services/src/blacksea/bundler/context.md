# bundler/ — blacksea.bundler payload bundler

**Status:** implemented. Built alongside the staging-vessel contract and
`control_plane/factory.py`'s build pipeline, well after `sdk/`. It is a sibling package of
`sdk/` at `src/blacksea/bundler/`, not nested under it.
**Language:** Python 3.11+
**Contracts:** this file is self-sufficient — the flattening/discovery contract, the CLI surface,
and the vessel-wrapper contract are locked below. No external design doc is required.

## Scope

`bundler` turns one entry-point Python script (`payload.py`) plus the pure-Python modules it
imports from a set of `--root` directories into a **single, self-contained, flattened `.py`
file**: every vendored module's real source is inlined as plain top-level code sharing one
namespace — no runtime loader, no embedded strings, no `exec` of packed data, and (proven by
`tests/sdk/bundler/test_bundle.py::test_independent_audit_records_zero_writes`) zero disk writes
when the bundle runs. This is what lets a bait's `payload.py` — which imports comms primitives
from `blacksea.sdk.payload.*` (see `src/blacksea/sdk/context.md`) — become the artifact dropped on
an attacker's machine: stock Python 3, no `blacksea` install, no network fetch of dependencies.

`bundler` is a **generic** static-import-graph flattener, not SDK-specific: it has no import
dependency on `blacksea.sdk` (or any other `blacksea.*` module — verified by
`tests/sdk/test_payload_import_is_minimal.py` treating it as an external consumer, and by
`tests/sdk/bundler/fixtures/sdk/` being a synthetic fixture package unrelated to the real
`blacksea.sdk`). It vendors whatever lives under the `--root` directories it is given; when
`control_plane/factory.py` calls it, one of those roots happens to be the real SDK.

It contains:

- **Discovery** (`discovery.py`) — a static AST walk of the import graph starting from the
  payload, resolving absolute imports, package `__init__` re-exports, relative imports
  (`from . import y` / `from ..errors import X`), and implicit parent packages. Only modules
  found under a `--root` are vendored; stdlib/third-party imports are left as external
  (hoisted, not inlined) and reported in `DiscoveryResult.warnings`/`.external`. Walks **all**
  AST nodes (`ast.walk`), including imports nested inside functions or `if TYPE_CHECKING:`
  blocks — there is no way to hide an import from discovery by nesting it (this is what makes
  the SDK's *Bundler minimality* invariant, `src/blacksea/sdk/context.md`, checkable at all).
- **Flattening** (`flatten.py`) — rewrites every vendored module's AST into the shared
  namespace: intra-bundle imports are stripped, `alias.symbol` references are de-qualified to
  `symbol`, external/stdlib imports are hoisted (deduped, `__future__` first) to the file top,
  and module bodies are emitted in dependency-first order (`discovery.exec_order()`) followed
  by the payload. This is heuristic and **fails loudly** (raises `FlattenError`) rather than
  silently producing unsound output, on: a top-level name collision between two vendored
  modules (or a vendored module and the payload); `from x import *` of a vendored module; a
  vendored module referenced as a bare value instead of `module.attr`; a mixed `import a, b`
  where `a` is vendored and `b` is not; a dotted `import a.b` with no `as` alias; or a static
  `importlib.import_module(...)`/`__import__(...)` call naming a vendored module (there is no
  module object left to resolve it against once flattened).
- **Compression pipeline** (`transform.py`) — staged, independently toggleable size-reduction
  passes, applied in this order by `builder.build()`:
  1. `strip_comments()` — AST round-trip that drops `#` comments and docstrings (default on).
  2. `treeshake()` — **experimental**, opt-in-by-default (`--experimental-treeshake`, default
     `True`): drops top-level `def`/`class` statements that are provably unreferenced
     bundle-wide (not referenced by name, not accessed as an attribute, not
     imported/re-exported anywhere, not listed in any module's `__all__`, and not decorated). A
     module using `getattr`/`globals`/`vars`/`eval`/`exec`/`locals`/`__getattr__` is left
     completely untouched (conservative bail-out). Unsafe in the presence of patterns invisible
     to this analysis (e.g. dynamic string dispatch) — validate against the project's test suite
     after enabling.
  3. `minify()` — runs `python-minifier` (optional dependency, the `minify` extra in
     `pyproject.toml`) over the final single module; raises `BundlerError` with an install
     hint if `--minify` is requested but the package isn't installed.
- **Assembly** (`emit.py`) — produces the final text: a `# DO NOT EDIT` header carrying a
  deterministic sha256 content fingerprint (no timestamps, so output is byte-for-byte
  reproducible for identical input — `tests/sdk/bundler/test_features.py::
  test_output_is_byte_for_byte_reproducible`), then hoisted imports, then module bodies in
  dependency order, then the payload. `--var NAME=VALUE` (`global_vars` in `BuildOptions`)
  injects `NAME = VALUE` assignments before all other code, but after any leading
  `from __future__ import …` lines (PEP 236 requires those to stay first) — used by
  `control_plane/factory.py` to inject the per-instance token/key/callback-address constants a
  payload references as globals.
- **Orchestration** (`builder.py`) — `build(payload, options) -> BuildResult` runs discovery →
  tree-shake → compression → flatten/emit → minify in that fixed order and returns the bundled
  text plus warnings, the removed-symbol list, and (module names, pre-minified text for
  debugging).
- **CLI** (`cli.py`, `__main__.py`) — the `bundle`-style argparse frontend, exposed as the
  `bs-bundle` console-script (`pyproject.toml`'s `[project.scripts]`) and as
  `python -m blacksea.bundler`. Flags: `payload` (positional), `--root` (repeatable, required),
  `-o/--output`, `--strip-comments`/`--no-strip-comments` (default on),
  `--minify`, `--include-module` (repeatable), `--experimental-treeshake`/
  `--no-experimental-treeshake` (default on), `--var NAME=VALUE` (repeatable). Exits 1 on a
  `BundlerError` (prints `bundle: error: …` to stderr), 2 on a CLI usage error (missing
  payload file, malformed `--var`).
- **Vessel wrappers** (`vessel_wrappers.py`) — a second, independent contract: turns the
  bundled bytes into a one-liner *command string* ready to embed in a delivery mechanism
  (shell heredoc, notebook cell, fake binary). `VesselWrapper` is the pluggable ABC;
  `PythonGzipB64Wrapper` (registered as `WRAPPERS["python"]`) is the only implementation —
  `gzip.compress` → `base64.b64encode` → `python3 -c "import gzip,base64;exec(...)"`. Returns
  `WrapperArtifacts` (the ready string, every intermediate file for debugging —
  `bundled.py`/`bundled.gz`/`bundled.b64` —, and transformation metadata including
  `compression_ratio`, guarded against divide-by-zero on empty input). `WRAPPERS` is a
  registry keyed by language name; only `"python"` exists today (see "Open items" below).
- **Errors** (`errors.py`) — `BundlerError` (base), `CExtError` (a required dependency
  resolved to a compiled `.so`/`.pyd`; bundler only vendors pure-Python source and refuses to
  silently drop a compiled extension), `ResolveError` (an explicit `--include-module` target
  wasn't found under any `--root`).

### `--include-module`

Force-vendors a module invisible to static analysis (e.g. reached only via a dynamic
`importlib.import_module()` call whose target isn't a string literal). The module's real source
is inlined, but flattening cannot rewire a *dynamic* call site to resolve against it (there is no
module object post-flatten) — the build still succeeds but emits a warning rather than silently
producing a bundle whose dynamic import will fail at runtime. A dynamic import whose target
resolves to an already-vendored module (found via static discovery) is a hard `FlattenError`,
not a warning — that case is fixable (reference it statically) instead of merely explainable.

## Scope boundary (what this module is NOT)

- Not the SDK (`src/blacksea/sdk/`) — bundler has no import dependency on it; it treats
  `blacksea.sdk.payload.*` as ordinary vendorable source under whatever `--root` names the SDK
  checkout.
- Not the build orchestrator — `control_plane/factory.py`'s `LocalBuildContext.bundle_payload()`
  calls `bundler.builder.build()` directly (roots=`[sdk_root]`, `global_vars=inject`,
  `minify=True`) and is the only production caller; bundler itself does not know about
  `manifest.yaml`, instance tokens, or the registry.
- Not the staging vessel — `vessel_wrappers.py` produces a *command string* a vessel can choose
  to embed; it does not invoke `staging_vessel/setup.sh` or write the final deployable artifact
  (that's `control_plane/factory.py`'s `run_staging_vessel()`).
- Not a package manager — third-party/stdlib imports are left as-is (hoisted, not vendored) and
  assumed present on the target; bundler never fetches or pins dependencies.

## Plan

Built incrementally after the staging-vessel work landed (`9a3c1ba feat(bundler): add
vessel-ready string generation for bundled payloads`, `6db3eae feat(bundler): enable global name
renaming and save pre-minified source`): discovery + flattening + the CLI first, then the
gzip+base64 vessel wrapper, then `--var` global-variable injection for the factory's per-instance
constants. No further phasing planned.

## Dependencies

- No dependency on `blacksea.sdk` or any other `blacksea.*` module (see *Scope* above) — the
  only coupling to the SDK is data-level: `control_plane/factory.py` happens to point `--root`
  at it, and `tests/sdk/test_payload_import_is_minimal.py` uses `bundler.discovery.Discovery`
  to assert the SDK's package root stays import-free.
- `python-minifier` — optional (`pyproject.toml`'s `minify` extra), needed only for `--minify`;
  every other pass is pure stdlib (`ast`, `gzip`, `base64`, `hashlib`).
- Consumed by `control_plane/factory.py` (`bundle_payload()`/`WRAPPERS`) and exposed directly to
  operators/bait authors as the `bs-bundle` console-script.

## Invariants enforced here

- **Fails loudly, never silently unsound.** Every construct flattening cannot soundly rewrite
  (name collisions, star-imports of a vendored module, bare-alias use, mixed vendored/external
  `import` statements, dynamic import of a vendored module) raises `FlattenError`/`ResolveError`
  rather than emitting a bundle that looks fine and breaks at runtime. Locked by the
  `FlattenError` cases in `tests/sdk/bundler/test_features.py`.
- **Zero runtime machinery, zero disk writes.** The output is real inlined source, not strings
  behind a loader (`test_bundle.py::test_bundle_has_no_runtime_machinery` greps for absent
  loader/audit-hook tokens) and an import-only bundle performs zero write-mode file operations
  under an audit hook (`test_bundle.py::test_independent_audit_records_zero_writes`).
- **Deterministic, reproducible output.** No timestamps in the header; module order is sorted;
  hoisted imports are deduped and sorted. Same input → byte-identical output
  (`test_features.py::test_output_is_byte_for_byte_reproducible`).
- **Case-exact module resolution.** `discovery._case_exact()` checks the real directory entry
  before resolving a dotted name to a file, so a case-insensitive filesystem (macOS/Windows)
  can't silently vendor `sdk.Client` as `client.py` and produce a bundle that differs from what
  a case-sensitive (Linux CI/build) host would produce.
- **Compiled extensions are refused, not dropped.** `CExtError` — bundler only inlines
  pure-Python source; a `.so`/`.pyd` dependency fails the build with a clear message instead of
  silently producing a bundle missing the extension.
- The SDK's own *Bundler minimality* invariant (`src/blacksea/sdk/__init__.py` must not import
  its submodules) is owned by `src/blacksea/sdk/context.md`, not here — bundler is the
  mechanism that makes it checkable (full-AST-walk discovery, no way to hide an import from
  it), but the invariant and its test (`tests/sdk/test_payload_import_is_minimal.py`) live with
  the SDK.

## Known limitations

- **`WRAPPERS` has one entry.** `vessel_wrappers.py`'s module docstring and the registry comment
  both flag `python` as the only implementation, with Ruby/Bash/PowerShell named as future
  possibilities — honest about scope, not a stub masquerading as done. No other language is
  referenced anywhere else in the codebase, so there's nothing pending here.

## File list

The package lives at `src/blacksea/bundler/`, part of the single `blacksea` distribution (root
`services/pyproject.toml`, `pip install -e .` via `make install`). Imports as `blacksea.bundler`;
runs as `bs-bundle` (and `python -m blacksea.bundler`).

| File | Description |
|---|---|
| `__init__.py` | Package root: re-exports `BundlerError`/`CExtError`/`ResolveError` and `VesselWrapper`/`WrapperArtifacts`/`WRAPPERS`; `__version__` |
| `__main__.py` | `python -m blacksea.bundler` entry point — delegates to `cli.main()` |
| `cli.py` | `bundle`/`bs-bundle` argparse CLI: parses flags, calls `builder.build()`, writes the output file, prints warnings + tree-shake/size summary to stderr |
| `builder.py` | `BuildOptions`/`BuildResult` dataclasses; `build()` — orchestrates discovery → tree-shake → compression → flatten/emit → minify |
| `discovery.py` | Static import-graph walk: `Module`/`DiscoveryResult` dataclasses, `Discovery` class, `resolve_relative_import()` (shared relative-import arithmetic — also used by `flatten.py` so the two can't drift), `dynamic_import_target()`, `exec_order()` (dependency-first topological sort, deterministic cycle-breaking) |
| `flatten.py` | Source-level flattening/rewriting into one shared namespace; `flatten()`, `_Rewriter` (the `ast.NodeTransformer`), `FlattenError` |
| `transform.py` | Compression pipeline: `CompressionOptions`, `strip_comments()`, `run_compression_pipeline()`, `minify()`, `treeshake()` (experimental dead-code elimination) |
| `emit.py` | `assemble()` — final single-file text: header + fingerprint, hoisted imports, dependency-ordered module bodies, payload, `--var` global-variable injection (`_prepend_globals()`, PEP-236-safe) |
| `errors.py` | `BundlerError`, `CExtError`, `ResolveError` |
| `vessel_wrappers.py` | `VesselWrapper` ABC, `WrapperArtifacts`, `PythonGzipB64Wrapper` (gzip+base64 one-liner), `WRAPPERS` registry |
| `tests/sdk/bundler/conftest.py` | Shared fixtures: `fixtures` (path to `tests/sdk/bundler/fixtures/`), `make_bundle` (builds in-process, writes to `tmp_path`), `run_clean_room()` (copies the bundle to an isolated dir with no SDK on disk, runs it under `python -I`) |
| `tests/sdk/bundler/test_bundle.py` | End-to-end guarantees on the flattened output: clean-room execution (plain/minify/treeshake modes), no runtime machinery, zero file writes (audit-hook check), relative-import/re-export resolution, case-insensitive-FS correctness, the C-extension error path (direct call + CLI exit code) |
| `tests/sdk/bundler/test_features.py` | Discovery edge cases, determinism/reproducibility, flattening (dequalification, name collisions, star-import rejection), size passes (strip-comments, minify, treeshake on/off), dynamic imports / `--include-module`, external/stdlib hoisting, `--var` + `__future__` ordering |
| `tests/sdk/bundler/test_vessel_wrappers.py` | Unit tests for `PythonGzipB64Wrapper`: artifact shape, the ready string is executable and valid Python, compression ratio, intermediate files, empty-source edge case, registry contents |
| `tests/sdk/bundler/fixtures/` | A synthetic `sdk`-shaped fixture package (`_util.py`, `client.py`, `config.py`, `errors.py`, `sub/codec.py`, `sub/transport.py`, `plugins/extra.py`, `unused_module.py`) plus `payload.py`, `dynamic_payload.py`, and `cext/` (a fake compiled-extension dependency) — deliberately unrelated to the real `blacksea.sdk`, proving bundler is generic |
