"""Shared test helpers for the brain suite.

Builds the two shapes the brain consumes off NATS — a tier-0 DNS QueuedEnvelope
and an encrypted tier≥1 HTTPS QueuedEnvelope — exactly as the edge (queue.go /
receiver_*.go) marshals them, so the tests exercise the real wire contract.
"""

from __future__ import annotations

import base64
import json
import os
from unittest import mock

from blacksea.brain.verifier import DirEntry
from blacksea.sdk.payload.envelope import build_encrypted_envelope


def gen_key() -> bytes:
    return os.urandom(32)


def dir_entry(
    *,
    bait_id: str = "hostname-probe",
    campaign_id: str = "camp-1",
    key: bytes = b"\x00" * 32,
    assurance_tier: int = 2,
    status: str = "active",
) -> DirEntry:
    return DirEntry(
        key_bytes=key,
        status=status,
        bait_id=bait_id,
        campaign_id=campaign_id,
        assurance_tier=assurance_tier,
        default_channel="https",
        valid_from=0,
        valid_until=None,
    )


def tier0_dns_envelope(
    *,
    instance_token: str = "1122334455667788",
    session_id: str = "aabbccddeeff0011",
    seq_no: int = 0,
    body: bytes | None = None,
) -> dict:
    """A tier-0 DNS QueuedEnvelope as the dead-drop edge (receiver_dns.go) produces it: only the
    parsed thin-form fields + the edge stamp. No bait_id/campaign_id/assurance_tier/status — the
    edge holds no directory; the brain resolves all routing from `tok`."""
    env = {
        "ev": 1,
        "channel": "dns",
        "instance_token": instance_token,
        "session_id": session_id,
        "seq_no": seq_no,
        "flags": 1,
        "edge": {
            "recv_time": 1_700_000_000_000,
            "source": {"ip": "203.0.113.9", "source_type": "resolver"},
            "edge_id": "edge-1",
        },
    }
    if body is not None:
        env["obs_body"] = base64.b64encode(body).decode()
    return env


def encrypted_https_envelope(
    key: bytes,
    *,
    instance_token: str = "1122334455667788",
    session_id: str = "aabbccddeeff0011",
    seq_no: int = 7,
    body: bytes = b'{"hostname":"victim-box"}',
    sensor_time: int = 1_700_000_000_123,
    corrupt_ct: bool = False,
) -> dict:
    """An encrypted HTTPS QueuedEnvelope as the dead-drop edge produces it: {ev, channel, tok, enc,
    edge}. Built via the production SDK seal (``build_encrypted_envelope``) so the test path
    exercises the real HMAC-SHA256 AEAD wire format (§1.4 Appendix). No bait_id/tier/status — the
    brain resolves those from `tok`. ``time.time`` is patched so ``sensor_time`` is deterministic."""
    with mock.patch("time.time", return_value=sensor_time / 1000):
        wire = build_encrypted_envelope(
            body, key.hex(), instance_token,
            session_id=bytes.fromhex(session_id), seq_no=seq_no,
        )
    enc_b64 = json.loads(wire)["enc"]

    if corrupt_ct:
        blob = bytearray(base64.urlsafe_b64decode(enc_b64 + "=" * (-len(enc_b64) % 4)))
        blob[12] ^= 0xFF  # first byte past the 12 B nonce — inside the ciphertext, not the tag
        enc_b64 = base64.urlsafe_b64encode(bytes(blob)).rstrip(b"=").decode()

    return {
        "ev": 2,
        "channel": "https",
        "instance_token": instance_token,
        "enc": enc_b64,
        "edge": {
            "recv_time": 1_700_000_000_999,
            "source": {
                "ip": "198.51.100.5",
                "ja3": "771,4865-4866",
                "source_type": "client",
            },
            "edge_id": "edge-1",
        },
    }


class FakeMsg:
    """Minimal NATS msg stand-in: carries .data and records .ack() calls."""

    def __init__(self, payload: dict | bytes) -> None:
        self.data = payload if isinstance(payload, bytes) else json.dumps(payload).encode()
        self.acked = False

    async def ack(self) -> None:
        self.acked = True
