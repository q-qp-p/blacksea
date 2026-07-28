"""Blacksea SDK package root.

INVARIANT — this ``__init__`` MUST NOT import its submodules (no
``from .abc import Listener``, no re-exports, not even under ``if
TYPE_CHECKING:``). The bundler vendors a payload's entire parent-package chain,
so any import here is dragged into every payload bundle: a payload that only
does ``from blacksea.sdk.payload.http import send_https_encrypted`` would
otherwise ship the Listener ABC, the golden-test runner, and the SDK types it
never uses. Discovery walks *all* AST nodes (including guarded/nested imports),
so there is no exception. See ``src/blacksea/sdk/context.md`` and
the regression test ``tests/sdk/test_payload_import_is_minimal.py``.

Bait authors import the server-side surface from ``blacksea.sdk.listener``
(the documented single entry point); payloads import comms from
``blacksea.sdk.payload.*``. Keep this file import-free.
"""

__version__ = "0.1.0"
