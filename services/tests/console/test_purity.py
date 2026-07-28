"""Facade-purity invariant: importing the facade must NOT
drag in click/rich, so the future HTTP skin / web UI can import it clean. Run in a subprocess so
the assertion is about a *fresh* interpreter — a sibling test that imported click/rich first can't
mask a real leak."""

from __future__ import annotations

import subprocess
import sys


def test_service_imports_without_click_or_rich() -> None:
    code = (
        "import sys;"
        "import blacksea.console.service;"
        "import blacksea.console.models;"
        "import blacksea.console.probes;"
        "import blacksea.console.otel_ctl;"
        "import blacksea.console.envfile;"
        "leaked=[m for m in ('click','rich') if m in sys.modules];"
        "assert not leaked, f'facade pulled in {leaked}';"
        "print('PURE')"
    )
    proc = subprocess.run([sys.executable, "-c", code], capture_output=True, text=True)
    assert proc.returncode == 0, proc.stderr
    assert "PURE" in proc.stdout
