"""Framework-internal types — NOT part of the public BoobyBait authoring API.

A BoobyBait author must never import from ``blacksea.sdk.framework``. The
single type here (``TypedEvent``) is consumed by the Tier-2 correlation engine
and assembled by the brain framework; it is kept out of ``blacksea.sdk``'s
public ``__init__`` re-exports on purpose so authors cannot accidentally couple
to it.
"""
