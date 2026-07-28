"""The ``TypedEvent`` projection — the Tier-1 → Tier-2 contract.

This is the only type the Tier-2 correlation/attribution engine imports from
the framework (see src/blacksea/correlation/context.md for the full engine spec).
The framework constructs a ``TypedEvent`` from every verified Record (see
src/blacksea/brain/context.md) and hands it to Tier-2; Tier-2 never touches the
full Record.

Two fields are **structurally excluded** — they are absent from the type, not
merely discouraged:

* ``details``      — attacker-influenced content. Reading it would make the
                     actor graph prompt-injectable (inv 12). Anything needed for
                     attribution must first be promoted to ``signals`` by the
                     analyzer.
* ``sensor_time``  — claimed-tier. Tier-2 builds every timeline on
                     ``edge_recv_time`` only (inv 17).
"""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class TypedEvent:
    # Identity
    record_id: str               # dedup key — <itoken_hex>-<sid_hex>-<seq_hex>
    bait_id: str
    instance_token: bytes        # 8 B
    campaign_id: str
    deploy_class: str            # "portable_artifact" | "host_resident" | "interactive_service"
    assurance_tier: int          # 0 | 1 | 2

    # Session
    session_id: bytes            # 8 B
    seq_no: int                  # uint16; 0 = single-shot
    event_type: str

    # Timestamps — edge-observed only; sensor_time deliberately absent
    edge_recv_time: int          # ms, observed-tier (inv 17)

    # Observed source (edge-stamped)
    source_ip: str
    source_ja3: str | None       # None for non-TLS channels (DNS)
    source_type: str             # "client" (HTTPS/TCP) | "resolver" (DNS)

    # Promoted signals (analyzer-extracted)
    fingerprint_hash: str | None
    caution_level: str | None    # "none" | "low" | "medium" | "high"
    explicit_session_end: bool   # defaults False when signals absent

    # Status
    sig_valid: bool
    orphan: bool
    instance_status: str         # "active" | "burned" | "retired" | "revoked"
