"""End-to-end proofs for the required guarantees (flattened output)."""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path

import pytest

from conftest import FIXTURES, run_clean_room

from blacksea.bundler.builder import BuildOptions, build
from blacksea.bundler.discovery import Discovery
from blacksea.bundler.errors import CExtError

PAYLOAD = FIXTURES / "payload.py"
EXPECTED = "HELLO WORLD #T"


# --- clean-room execution (no sdk/ on disk) --------------------------------

def test_clean_room_run_no_sdk_on_disk(make_bundle):
    bundle = make_bundle(PAYLOAD)
    proc = run_clean_room(bundle)
    assert proc.returncode == 0, proc.stderr
    assert proc.stdout.strip() == EXPECTED
    # The isolated run dir must contain ONLY the bundle -- nothing else got there.
    assert sorted(p.name for p in bundle.parent.joinpath("cleanroom").iterdir()) == ["run.py"]


@pytest.mark.parametrize(
    "opts",
    [{}, {"minify": True}, {"experimental_treeshake": True}],
    ids=["plain", "minify", "treeshake"],
)
def test_all_modes_run_clean(make_bundle, opts):
    if opts.get("minify"):
        pytest.importorskip("python_minifier")
    bundle = make_bundle(PAYLOAD, **opts)
    proc = run_clean_room(bundle)
    assert proc.returncode == 0, proc.stderr
    assert proc.stdout.strip() == EXPECTED


# --- the flattened bundle is plain code: no loader, no embedded sources -----

def test_bundle_has_no_runtime_machinery(make_bundle):
    """The output is inlined real code -- not strings behind a loader."""
    text = make_bundle(PAYLOAD).read_text()
    for token in ("_BLUNDER_MODULES", "meta_path", "exec(", "addaudithook"):
        assert token not in text, token
    # The actual SDK source is present verbatim (readable), not in a string.
    assert "def normalize(value):" in text
    assert "class Client:" in text


# --- zero file writes -------------------------------------------------------

def test_independent_audit_records_zero_writes(make_bundle, tmp_path):
    """An audit hook records every write-mode open / fs-mutation while the bundle
    imports & runs; an import-only payload must produce 0."""
    bundle = make_bundle(PAYLOAD)
    wrapper = tmp_path / "auditor.py"
    wrapper.write_text(
        "import sys, os\n"
        "src = open(sys.argv[1]).read()\n"          # read BEFORE the hook (read is allowed)
        "writes = []\n"
        "WF = os.O_WRONLY | os.O_RDWR | os.O_CREAT | os.O_APPEND | os.O_TRUNC\n"
        "def hook(event, args):\n"
        "    if event == 'open':\n"
        "        mode = args[1] if len(args) > 1 else None\n"
        "        flags = args[2] if len(args) > 2 else None\n"
        "        if (isinstance(mode, str) and any(c in mode for c in 'wax+')) or \\\n"
        "           (isinstance(flags, int) and flags >= 0 and (flags & WF)):\n"
        "            writes.append((args[0], mode, flags))\n"
        "    elif event in ('os.rename','os.remove','os.unlink','os.mkdir','os.makedirs','os.rmdir'):\n"
        "        writes.append((event,))\n"
        "sys.addaudithook(hook)\n"
        "exec(compile(src, sys.argv[1], 'exec'), {'__name__': '__main__'})\n"
        "sys.stderr.write('WRITES=%d\\n' % len(writes))\n"
        "sys.exit(len(writes))\n",
        encoding="utf-8",
    )
    proc = subprocess.run(
        [sys.executable, "-I", str(wrapper), str(bundle)],
        capture_output=True, text=True,
    )
    assert "WRITES=0" in proc.stderr, proc.stderr
    assert proc.returncode == 0, proc.stderr
    assert EXPECTED in proc.stdout


# --- relative imports + re-exports resolve ---------------------------------

def test_relative_imports_and_reexports_resolved():
    result = Discovery([str(FIXTURES)]).discover(PAYLOAD)
    names = set(result.modules)
    # __init__ re-exports + cross-subpackage relative imports all pulled in:
    assert names == {
        "sdk", "sdk._util", "sdk.client", "sdk.config", "sdk.errors",
        "sdk.sub", "sdk.sub.codec", "sdk.sub.transport",
    }
    # module-level pruning: the never-imported module stays out.
    assert "sdk.unused_module" not in names
    # case-insensitive FS must not vendor `sdk.Client`/`sdk.Config` as modules.
    assert "sdk.Client" not in names and "sdk.Config" not in names


def test_packages_marked_correctly():
    result = Discovery([str(FIXTURES)]).discover(PAYLOAD)
    pkgs = {m.name for m in result.modules.values() if m.is_pkg}
    assert pkgs == {"sdk", "sdk.sub"}


# --- clear error on a C-extension dependency -------------------------------

def test_cext_dependency_errors_clearly():
    cext_payload = FIXTURES / "cext" / "payload_cext.py"
    with pytest.raises(CExtError) as exc:
        build(cext_payload, BuildOptions(roots=[str(FIXTURES / "cext")]))
    msg = str(exc.value)
    assert "compiled extension" in msg
    assert "badsdk.speedup" in msg
    assert ".so" in msg


def test_cext_cli_exit_code():
    import os
    cext_payload = FIXTURES / "cext" / "payload_cext.py"
    sdk_root = str(Path(__file__).resolve().parents[3] / "src")
    env = {**os.environ, "PYTHONPATH": sdk_root}
    proc = subprocess.run(
        [sys.executable, "-m", "blacksea.bundler", str(cext_payload),
         "--root", str(FIXTURES / "cext"), "-o", "/dev/null"],
        cwd=Path(__file__).resolve().parent.parent,
        env=env,
        capture_output=True, text=True,
    )
    assert proc.returncode == 1
    assert "compiled extension" in proc.stderr
