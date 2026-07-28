"""Toy SDK used to exercise the bundler (re-exports + relative imports)."""

from .client import Client
from .config import Config

__all__ = ["Client", "Config", "VERSION"]

VERSION = "1.0"
