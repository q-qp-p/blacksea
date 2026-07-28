"""Regression guard: a payload-comms import must not drag in the server surface.

A payload imports only ``blacksea.sdk.payload.*``. The bundler vendors that
module's whole parent-package chain, so ``blacksea/sdk/__init__.py`` is always
vendored and scanned. If that ``__init__`` ever re-exports submodules again (the
old ``from .abc import Listener`` block), the Listener ABC, the golden-test
runner, and the SDK types would leak into every payload bundle.

This test locks the invariant documented in ``blacksea/sdk/__init__.py``:
discovering from a payload that imports ``blacksea.sdk.payload.http`` must
NOT pull in ``abc``/``testing``/``types``/``listener``.
"""

from __future__ import annotations

import ast
from pathlib import Path

from blacksea.bundler.discovery import Discovery

# Root that holds the real ``blacksea/`` namespace package (the src/ tree).
SDK_ROOT = Path(__file__).resolve().parents[2] / "src"
SDK_INIT = SDK_ROOT / "blacksea" / "sdk" / "__init__.py"

# Modules that define the server-side authoring surface — none of these may be
# reachable from a payload that only imports comms.
SERVER_SIDE = {
    "blacksea.sdk.abc",
    "blacksea.sdk.testing",
    "blacksea.sdk.types",
    "blacksea.sdk.listener",
    "blacksea.sdk.inject",
}


def test_payload_comms_import_does_not_pull_server_surface(tmp_path):
    payload = tmp_path / "payload.py"
    payload.write_text(
        "from blacksea.sdk.payload.http import send_https_encrypted\n",
        encoding="utf-8",
    )
    names = set(Discovery([str(SDK_ROOT)]).discover(payload).modules)
    # The parent package __init__ is vendored (it is on the chain)…
    assert "blacksea.sdk" in names
    # …but it must carry nothing server-side with it.
    leaked = names & SERVER_SIDE
    assert not leaked, f"payload bundle leaked server-side modules: {sorted(leaked)}"


def test_payload_comms_import_pulls_no_third_party_module(tmp_path):
    """Post-HMAC-migration invariant: the entire tier≥1 payload path is pure stdlib now
    (no more deferred cbor2/cryptography imports — see src/blacksea/sdk/context.md). A payload
    that imports the encrypted-envelope sender must not require anything beyond stdlib —
    ``Discovery.external`` (imports found outside the vendored roots, minus stdlib) must be
    empty, aside from the ``blacksea`` PEP-420 namespace root itself (it has no
    ``__init__.py`` by design — see the Bundler-minimality invariant above — so Discovery can
    never resolve it as a file and always classifies it as "external"; that is not a real
    third-party dependency)."""
    payload = tmp_path / "payload.py"
    payload.write_text(
        "from blacksea.sdk.payload.http import send_https_encrypted\n"
        "from blacksea.sdk.payload.envelope import build_encrypted_envelope\n",
        encoding="utf-8",
    )
    result = Discovery([str(SDK_ROOT)]).discover(payload)
    third_party = result.external - {"blacksea"}
    assert third_party == set(), (
        f"payload comms import pulled in third-party module(s): {sorted(third_party)}"
    )


def test_sdk_init_imports_no_blacksea_submodule():
    """The package root stays import-free of its own submodules (the invariant)."""
    tree = ast.parse(SDK_INIT.read_text(encoding="utf-8"), filename=str(SDK_INIT))
    offenders: list[str] = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            offenders += [a.name for a in node.names if a.name.startswith("blacksea")]
        elif isinstance(node, ast.ImportFrom):
            # level > 0 is a relative import (a submodule); module may also be absolute.
            if node.level > 0 or (node.module or "").startswith("blacksea"):
                offenders.append(node.module or f"(relative level {node.level})")
    assert not offenders, (
        f"src/blacksea/sdk/__init__.py must not import submodules, found: {offenders}"
    )
