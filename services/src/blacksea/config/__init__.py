"""blacksea.config — operational configuration for the Blacksea backend.

A leaf package (pure standard library, no third-party dependencies). Its public
module :mod:`blacksea.config.settings` is the one place every runtime value that
used to be a scattered ``os.environ.get(...)`` default now lives; the sibling
:mod:`blacksea.config.envload` loads the unified ``config/blacksea.env`` file into
``os.environ`` at settings-import time so every consumer reads one file. It is
imported by the brain, control plane,
observer, correlation, otel, and console packages; it is NOT imported by the deployed
payload (which must stay stdlib-only and minimal) nor by the Go edge (which mirrors
the shared values in ``edge/config.go``).
"""

from __future__ import annotations

from . import settings

__all__ = ["settings"]
