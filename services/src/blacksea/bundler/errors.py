"""Exception types raised by the build step."""

from __future__ import annotations


class BundlerError(Exception):
    """Base class for all build-time errors."""


class CExtError(BundlerError):
    """A required dependency resolved to a compiled C extension (not pure Python).

    bundler only vendors pure-Python sources; ``.so``/``.pyd`` extensions cannot be
    inlined into a text ``.py`` file, so we fail loudly rather than silently drop them.
    """

    def __init__(self, module: str, path) -> None:
        self.module = module
        self.path = path
        super().__init__(
            f"cannot vendor compiled extension {module!r} "
            f"(found {path}); bundler only bundles pure-Python modules. "
            f"Install this dependency on the target host, or exclude it."
        )


class ResolveError(BundlerError):
    """A module that was explicitly requested could not be found under any --root."""
