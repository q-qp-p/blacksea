"""bundler: bundle a Python script and its SDK into one self-contained .py file.

The output is a single, readable ``.py`` with every vendored module **flattened** in
as plain top-level source — one shared namespace, no runtime loader, no embedded
strings, no ``exec``. The only thing that can touch disk at run time is the payload.
"""

from .errors import BundlerError, CExtError, ResolveError
from .vessel_wrappers import VesselWrapper, WrapperArtifacts, WRAPPERS

__all__ = [
    "BundlerError",
    "CExtError",
    "ResolveError",
    "VesselWrapper",
    "WrapperArtifacts",
    "WRAPPERS",
    "__version__",
]

__version__ = "0.1.0"
