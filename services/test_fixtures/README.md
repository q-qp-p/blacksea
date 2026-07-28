# test_fixtures/

Shared fixtures for the Python unit-test suites. Nothing here is production/runtime state —
it exists only so `sdk`, `control_plane`, and `brain` tests have a stable, committed input.

## `baits/hostname_probe/`

The reference/test bait (`test: true`) used as the happy-path fixture by:

- `tests/control_plane/` — `conftest.HOSTNAME_PROBE` + `bait_factory` (ingestion,
  registry, factory, forge), and
- `tests/brain/test_e2e.py` — the full verify → interpret → store slice.

It is a **manifest-only** bait (see `docs/bait-authoring.md`): `manifest.yaml` is the only file; it
references its payload/listener/staging-vessel in the repo-root `lure_material/` catalog
(`payloads/hostname_grab_dns/` + `staging_vessels/identity/`) by a `../`-relative path. The
directory is kept **four levels below the repo root** (`hostname_probe` → `baits` → `test_fixtures`
→ `services` → root), which is what makes the manifest's `../../../../lure_material/...` paths
resolve. Adjust the `../` count if you ever move it to a different depth.

The brain no longer scans a git baits directory (it reads designs from the control-plane Postgres
catalog and imports the frozen listener from `registry/artifacts/`), so this bait's only consumers
are the tests above — hence it lives here rather than under a runtime path.
