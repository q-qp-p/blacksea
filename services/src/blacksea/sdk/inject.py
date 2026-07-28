"""get_comms_source — returns inlineable primitive source for payload templates.

For a payload built by formatting a template string (rather than a real Listener-adjacent
payload.py that imports blacksea.sdk.payload.* directly, which the bundler inlines by static
discovery instead — see src/blacksea/sdk/context.md), call this and embed the result in the
payload template. The inlined code runs self-contained on the attacker's machine: stdlib only,
no blacksea imports required.

    comms = get_comms_source(["dns"])
    script = TEMPLATE.format(comms=comms, zone=callback_addresses["dns"])
"""

from __future__ import annotations

from pathlib import Path

_COMMS_DIR = Path(__file__).parent / "payload"

_VALID: dict[str, str] = {
    "dns": "dns.py",
    "http": "http.py",
    "dns_multiturn": "dns_multiturn.py",
}


def get_comms_source(channels: list[str]) -> str:
    """Return the combined source of the requested communication primitives.

    Each channel name must be one of: "dns", "http", "dns_multiturn".
    The returned string is a self-contained Python block: inline it verbatim
    into a payload template so the payload needs no external imports.

    Raises ValueError for unknown channel names.
    """
    unknown = [c for c in channels if c not in _VALID]
    if unknown:
        raise ValueError(f"Unknown channel(s): {unknown!r}. Valid: {sorted(_VALID)}")

    parts = [(_COMMS_DIR / _VALID[c]).read_text().strip() for c in channels]
    return "\n\n".join(parts)
