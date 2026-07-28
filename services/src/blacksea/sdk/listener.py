"""blacksea.sdk.listener — server-side bait-authoring surface.

Single import for everything a bait author needs when writing listener.py:
the Listener ABC, all SDK types, exceptions, the comms-source injection
helper, and the golden-test harness.

    from blacksea.sdk.listener import Listener, AnalyzerOutput, Envelope
"""

from .abc import BoobyBait, Interpretable, Listener
from .exceptions import BodyDecodeError, BuildError
from .inject import get_comms_source
from .testing import ANY, GoldenResult, assert_golden, run_golden_case, run_golden_cases, test_envelope
from .types import (
    AnalyzerOutput,
    Artifact,
    BuildContext,
    Envelope,
    GoldenCase,
    ObservedSource,
    RunResult,
    Signals,
)

__all__ = [
    "ANY",
    "AnalyzerOutput",
    "Artifact",
    "BoobyBait",
    "BodyDecodeError",
    "BuildContext",
    "BuildError",
    "Envelope",
    "GoldenCase",
    "GoldenResult",
    "Interpretable",
    "Listener",
    "ObservedSource",
    "RunResult",
    "Signals",
    "assert_golden",
    "get_comms_source",
    "run_golden_case",
    "run_golden_cases",
    "test_envelope",
]
