"""blacksea.control_plane — the internal management layer (inv 10).

Ingests bait manifests, owns the registry (design + instance records), runs the
factory (per-instance keygen + hermetic build), drives the lifecycle state
machines, and writes the brain's key directory — the sole key directory now that
the edge is a dumb dead-drop holding none. See context.md for scope and the
locked contracts it implements.

This package never consumes telemetry (that is the brain) and never manages
sessions (that is the correlation engine). The registry is the source of truth; the key directory
is a read-only projection of it (inv 18).
"""

__version__ = "0.1.0"
