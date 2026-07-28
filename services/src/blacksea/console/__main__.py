"""``python -m blacksea.console`` → the `blacksea` CLI.

The installed console-script (`pyproject.toml` → `[project.scripts] blacksea`) is the primary
entry point; this module is the always-available fallback so the console also runs via
`python -m blacksea.console` wherever the `blacksea` package is importable (e.g. the editable
`pip install -e .`).
"""

from __future__ import annotations

from blacksea.console.cli import main

if __name__ == "__main__":
    raise SystemExit(main())
