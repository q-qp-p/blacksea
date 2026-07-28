"""Shared fixtures: build bundles in-process, run them in a clean room."""

from __future__ import annotations

import os
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

FIXTURES = Path(__file__).resolve().parent / "fixtures"

from blacksea.bundler.builder import BuildOptions, build  # noqa: E402


@pytest.fixture
def fixtures() -> Path:
    return FIXTURES


@pytest.fixture
def make_bundle(tmp_path):
    """Build a bundle and return its on-disk path (inside tmp_path)."""

    def _make(payload: str | Path, *, root=FIXTURES, name="bundle.py", **opts) -> Path:
        roots = [str(root)] if isinstance(root, (str, Path)) else [str(r) for r in root]
        result = build(Path(payload), BuildOptions(roots=roots, **opts))
        out = tmp_path / name
        out.write_text(result.text, encoding="utf-8")
        return out

    return _make


def run_clean_room(bundle: Path, *, env=None, extra_args=()) -> subprocess.CompletedProcess:
    """Copy the bundle to an isolated dir with NO sdk/ on disk and run it.

    Uses ``-I`` (isolated mode: ignore PYTHON* env, user site, cwd) so the only
    way the import can succeed is the self-contained bundle itself.
    """
    room = bundle.parent / "cleanroom"
    room.mkdir(exist_ok=True)
    target = room / "run.py"
    shutil.copyfile(bundle, target)
    run_env = {"PATH": os.environ.get("PATH", "")}
    if env:
        run_env.update(env)
    return subprocess.run(
        [sys.executable, "-I", str(target), *extra_args],
        cwd=room,
        env=run_env,
        capture_output=True,
        text=True,
    )
