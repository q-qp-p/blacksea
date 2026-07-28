"""Unit tests for vessel wrapper transformations.

Verifies that the PythonGzipB64Wrapper produces correct gzip+base64 one-liner
strings and preserves all intermediate transformation artifacts.
"""

import base64
import gzip
import subprocess

import pytest

from blacksea.bundler.vessel_wrappers import (
    PythonGzipB64Wrapper,
    WrapperArtifacts,
    WRAPPERS,
)


def test_python_gzip_b64_wrapper_produces_valid_artifacts():
    """Wrapper generates all intermediate files and ready string."""
    wrapper = PythonGzipB64Wrapper()
    source = b'print("hello from payload")'

    artifacts = wrapper.wrap(source)

    assert isinstance(artifacts, WrapperArtifacts)
    assert "bundled.py" in artifacts.intermediate_files
    assert "bundled.gz" in artifacts.intermediate_files
    assert "bundled.b64" in artifacts.intermediate_files
    assert artifacts.ready_string.startswith("python3 -c")
    assert "gzip" in artifacts.ready_string
    assert "base64" in artifacts.ready_string


def test_ready_string_is_executable():
    """The generated ready string can be executed as a shell command."""
    wrapper = PythonGzipB64Wrapper()
    source = b"import sys; sys.exit(42)"

    artifacts = wrapper.wrap(source)

    # Extract the Python code from the one-liner (between the " quotes)
    # Format: python3 -c "import gzip,base64;exec(...)"
    # We want just the part between the quotes
    parts = artifacts.ready_string.split('"')
    if len(parts) >= 3:
        python_code = parts[1]
    else:
        pytest.fail(f"Unexpected ready_string format: {artifacts.ready_string}")

    result = subprocess.run(
        ["python3", "-c", python_code], capture_output=True, timeout=5
    )
    assert result.returncode == 42  # Payload executed correctly


def test_compression_ratio_is_positive():
    """Gzip compression reduces size for typical SDK payloads."""
    wrapper = PythonGzipB64Wrapper()
    # Simulate a realistic bundled SDK payload (repetitive imports, etc.)
    source = b"from blacksea.sdk import Listener\n" * 100

    artifacts = wrapper.wrap(source)

    assert artifacts.metadata["compression_ratio"] < 1.0
    assert artifacts.metadata["source_size"] > artifacts.metadata["compressed_size"]


def test_intermediate_files_are_correct():
    """Each intermediate file contains expected content."""
    wrapper = PythonGzipB64Wrapper()
    source = b'print("test")'

    artifacts = wrapper.wrap(source)

    # bundled.py should be source bytes
    assert artifacts.intermediate_files["bundled.py"] == source

    # bundled.gz should be gzip-compressed source
    assert gzip.decompress(artifacts.intermediate_files["bundled.gz"]) == source

    # bundled.b64 should be base64-encoded compressed
    assert base64.b64decode(artifacts.intermediate_files["bundled.b64"]) == artifacts.intermediate_files["bundled.gz"]


def test_metadata_contains_expected_fields():
    """Metadata includes all expected fields with correct types."""
    wrapper = PythonGzipB64Wrapper()
    source = b"test payload"

    artifacts = wrapper.wrap(source)

    assert artifacts.metadata["format"] == "python_gzip_b64"
    assert artifacts.metadata["source_size"] == len(source)
    assert isinstance(artifacts.metadata["compressed_size"], int)
    assert isinstance(artifacts.metadata["b64_size"], int)
    assert isinstance(artifacts.metadata["compression_ratio"], float)


def test_wrappers_registry_contains_python():
    """The WRAPPERS registry includes the Python wrapper."""
    assert "python" in WRAPPERS
    assert WRAPPERS["python"] is PythonGzipB64Wrapper


def test_wrapper_handles_empty_source():
    """Wrapper gracefully handles empty source bytes."""
    wrapper = PythonGzipB64Wrapper()
    source = b""

    artifacts = wrapper.wrap(source)

    assert artifacts.ready_string.startswith("python3 -c")
    assert artifacts.metadata["source_size"] == 0
    assert artifacts.metadata["compression_ratio"] == 0.0  # Avoid divide-by-zero


def test_wrapper_produces_valid_python_syntax():
    """The ready string is syntactically valid Python when extracted."""
    wrapper = PythonGzipB64Wrapper()
    source = b"x = 1 + 1"

    artifacts = wrapper.wrap(source)

    # Extract Python code
    parts = artifacts.ready_string.split('"')
    if len(parts) >= 3:
        python_code = parts[1]
    else:
        pytest.fail(f"Unexpected ready_string format: {artifacts.ready_string}")

    # Verify it compiles
    compile(python_code, "<ready_string>", "exec")


def test_compression_improves_for_repetitive_content():
    """Compression ratio improves significantly for repetitive SDK content."""
    wrapper = PythonGzipB64Wrapper()
    # Highly repetitive content (like inlined SDK modules with repeated imports)
    source = (
        b"from blacksea.sdk.payload.dns import send_dns\n"
        b"from blacksea.sdk.payload.http import send_https_encrypted\n"
        b"from blacksea.sdk.types import Envelope\n"
    ) * 50

    artifacts = wrapper.wrap(source)

    # For highly repetitive content, gzip should achieve significant compression
    # (typically 10:1 or better for repeated import statements)
    assert artifacts.metadata["compression_ratio"] < 0.2


def test_ready_string_preserves_payload_behavior():
    """The ready string correctly executes payload logic."""
    wrapper = PythonGzipB64Wrapper()
    source = b"print('SUCCESS')"

    artifacts = wrapper.wrap(source)

    # Extract Python code
    parts = artifacts.ready_string.split('"')
    python_code = parts[1] if len(parts) >= 3 else artifacts.ready_string

    result = subprocess.run(
        ["python3", "-c", python_code],
        capture_output=True,
        text=True,
        timeout=5
    )

    assert result.returncode == 0
    assert "SUCCESS" in result.stdout
