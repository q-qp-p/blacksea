"""brain.verifier — HMAC-SHA256 AEAD decryption (inv 13) and envelope reconstruction.

The brain is the **sole** cryptographic authority (revises the prior edge+brain dual-verify
model — see edge/context.md): the edge never decrypts, so every tier≥1 hit is
decrypted here, against the brain's own key directory (see src/blacksea/brain/context.md), for
the first and only time. For tier 0 (unencrypted DNS) sig_valid is always False, which is
correct by design.

Wire format: {ev, tok, enc?}
  - tok: 16-char hex instance_token; key directory lookup key, also bound into the AEAD tag
  - enc: base64url(nonce(12B) ‖ ct ‖ tag(16B)); absent for tier-0

The AEAD is a pure-stdlib HMAC-SHA256 construction (PRF-as-CTR-stream-cipher + encrypt-then-MAC,
domain-separated enc/mac subkeys) over a fixed binary core (no CBOR) — see this module's
context.md for the full security rationale (nonce reuse, why HMAC over AES-GCM/Poly1305 here).
`hmac.compare_digest` verifies the tag before any keystream XOR is applied (verify-before-decrypt).

bait_id, campaign_id, assurance_tier are never transmitted — derived from the directory
entry for tok. channel comes from the edge-stamped QueuedEnvelope.Channel.

The brain's key directory is the sole key directory in the system now that the edge is a dumb
dead-drop with none of its own (see src/blacksea/brain/context.md): it carries `key` (the
per-instance master key, reused verbatim as the HMAC-SHA256 AEAD's master key) and never crosses
the edge-facing diode. The brain hot-reloads it via a plain stat/read/parse/swap poll
(keydir_poller.py) — no signing/anti-rollback, since it never leaves brain-controlled infra.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import logging
import os
from dataclasses import dataclass
from typing import Any

from blacksea.sdk.types import Envelope, ObservedSource

log = logging.getLogger(__name__)

# Fixed binary core layout (§1.4 Appendix): ev(1) ‖ session_id(8) ‖ seq_no(4) ‖ sensor_time(8) ‖ body
_CORE_HEADER_LEN = 21
_EV = 2


@dataclass(frozen=True)
class DirEntry:
    key_bytes: bytes
    status: str
    bait_id: str
    campaign_id: str
    assurance_tier: int
    default_channel: str
    valid_from: int
    valid_until: int | None


class KeyDirectory:
    """In-memory brain key directory (§5.11). Loaded from the brain-only JSON keydir format."""

    def __init__(self, entries: dict[bytes, DirEntry]) -> None:
        self._entries = entries

    @classmethod
    def from_file(cls, path: str) -> "KeyDirectory":
        """Load from a JSON keydir file. If the file doesn't exist, returns an empty
        directory with a warning — sufficient for tier-0 baits (no decryption required).
        Tier≥1 hits against an empty directory are dead-lettered (VerificationError)."""
        if not os.path.exists(path):
            log.warning(
                "keydir file %r not found — starting with empty directory "
                "(tier-0 hits work; tier≥1 hits will be dead-lettered). "
                "Provide a brain_keydir.json first.", path
            )
            return cls({})
        with open(path) as f:
            raw = json.load(f)
        entries: dict[bytes, DirEntry] = {}
        for e in raw:
            tok = bytes.fromhex(e["instance_token"])
            if len(tok) != 8:
                raise ValueError(f"instance_token must be 8 B, got {len(tok)}")
            key = bytes.fromhex(e["key"])
            if len(key) != 32:
                raise ValueError(f"key must be 32 B, got {len(key)}")
            entries[tok] = DirEntry(
                key_bytes=key,
                status=e["status"],
                bait_id=e["bait_id"],
                campaign_id=e["campaign_id"],
                assurance_tier=int(e["assurance_tier"]),
                default_channel=e["default_channel"],
                valid_from=int(e["valid_from"]),
                valid_until=e.get("valid_until"),
            )
        return cls(entries)

    def lookup(self, token: bytes) -> DirEntry | None:
        return self._entries.get(token)

    def __len__(self) -> int:
        return len(self._entries)

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, KeyDirectory):
            return NotImplemented
        return self._entries == other._entries


class VerificationError(Exception):
    """Structural problem with the queued envelope (not a decryption failure)."""


def resolve_entry(keydir: KeyDirectory, queued: dict[str, Any]) -> DirEntry | None:
    """The single key-directory lookup for a queued hit — the sole routing resolution now that the
    edge is a dumb dead-drop forwarding only ``tok`` (never ``bait_id``/status/tier).

    Every derived fact (bait_id, campaign_id, assurance_tier, status) comes from this one entry, so
    the pool resolves it once and threads it through decryption + the status stamp. The brain keydir
    is a superset of the edge's old routing view (it carries every built instance, incl. pending),
    so any token the edge would have routed resolves here too. Returns ``None`` when the token is
    absent or malformed; the pool treats that as an unroutable hit → dead-letter.
    """
    try:
        tok_bytes = bytes.fromhex(queued.get("instance_token", ""))
    except ValueError:
        return None
    return keydir.lookup(tok_bytes)


def instance_status_for(keydir: KeyDirectory, queued: dict[str, Any]) -> str:
    """Brain-authoritative instance lifecycle status for a queued hit (§5.7).

    Derived from the brain's OWN key directory — the sole authority now that the edge is a dumb
    dead-drop — not any edge-stamped value, so a revoked/burned/retired instance's hits are
    correctly flagged for the downstream heavy-sample/alert policy even if a directory has drifted.
    Returns ``"unknown"`` when the token is absent from (or malformed for) the directory.
    """
    entry = resolve_entry(keydir, queued)
    return entry.status if entry is not None else "unknown"


def verify(
    queued: dict[str, Any], keydir: KeyDirectory
) -> tuple[Envelope, bytes, bool]:
    """Resolve the hit's directory entry, then decrypt it — see :func:`verify_with_entry`.

    The single-keydir entry point for callers that have not already resolved the entry (tests,
    standalone use). The pool resolves the entry once via :func:`resolve_entry` and calls
    :func:`verify_with_entry` directly, so a hit is looked up exactly once.
    """
    return verify_with_entry(queued, resolve_entry(keydir, queued))


def verify_with_entry(
    queued: dict[str, Any], entry: DirEntry | None
) -> tuple[Envelope, bytes, bool]:
    """Decrypt a QueuedEnvelope dict against a pre-resolved directory ``entry``; return
    (envelope, body, sig_valid).

    body:      for tier≥1, decoded from the decrypted fixed binary core (§1.4); for tier 0,
               always b"" — the pool extracts obs_body separately.
    sig_valid: False for tier 0 (unencrypted by design) or when decryption/authentication fails.
               Name retained from the prior Ed25519-signing design.
    Raises VerificationError on parse/structural problems (caller dead-letters).
    """
    tok_hex = queued.get("instance_token", "")
    try:
        tok_bytes = bytes.fromhex(tok_hex)
    except ValueError as exc:
        raise VerificationError(f"invalid instance_token hex: {exc}") from exc

    # Tier-0 vs tier≥1 is derived from the CHANNEL, not an edge-supplied assurance_tier: DNS is the
    # sole tier-0 channel (locked invariant), and every HTTPS hit is tier≥1 carrying `enc` (the edge
    # drops an empty-enc POST). The dumb dead-drop edge no longer derives or sends a tier — the
    # record's authoritative assurance_tier comes from the brain key-directory entry (`_env_from_core`).
    if queued.get("channel") == "dns":
        return _env_tier0(queued, entry, tok_bytes), b"", False

    # Tier ≥ 1 (encrypted channel) — require a directory entry to decrypt against.
    if entry is None:
        raise VerificationError(
            f"instance_token {tok_hex!r} not in key directory (encrypted hit)"
        )

    # §5.3 validity window — defense in depth. The edge already drops out-of-window hits against
    # its own clock (§5.9-e); if one still reaches the brain, the directories have drifted or a
    # clock is off, so surface it rather than dropping (a brain-side drop would lose legitimate
    # hits on clock skew). The hit is still decrypted + stored; instance_status carries the signal.
    recv_time = int(queued.get("edge", {}).get("recv_time", 0))
    if recv_time and (
        recv_time < entry.valid_from
        or (entry.valid_until is not None and recv_time > entry.valid_until)
    ):
        log.warning(
            "tier≥1 hit for %s outside validity window [%s,%s] at %s (edge should have dropped it)",
            tok_hex, entry.valid_from, entry.valid_until, recv_time,
        )

    enc_b64 = queued.get("enc", "")
    if not enc_b64:
        raise VerificationError("encrypted hit missing 'enc' field")

    try:
        blob = base64.urlsafe_b64decode(enc_b64 + "=" * (-len(enc_b64) % 4))
    except Exception as exc:
        raise VerificationError(f"base64 decode of enc failed: {exc}") from exc

    if len(blob) < 12 + 16:
        raise VerificationError("enc too short to contain a 12 B nonce + 16 B tag")
    nonce, ct, tag = blob[:12], blob[12:-16], blob[-16:]

    core_bytes, sig_valid = _hmac_open(entry.key_bytes, nonce, tok_bytes, ct, tag)

    if sig_valid:
        if len(core_bytes) < _CORE_HEADER_LEN:
            raise VerificationError("decrypted core shorter than the fixed 21 B header")
        core = _parse_core(core_bytes)
        env = _env_from_core(queued, core, entry, sig_valid=True)
        body = core["body"]
    else:
        body = b""
        env = _env_from_hints(queued, entry, tok_bytes, blob)

    return env, body, sig_valid


# ── HMAC-SHA256 AEAD (§1.4 Appendix) ────────────────────────────────────────────

def _prf(k: bytes, d: bytes) -> bytes:
    return hmac.new(k, d, hashlib.sha256).digest()


def _keystream(ke: bytes, nonce: bytes, n: int) -> bytes:
    ks = b""
    while len(ks) < n:
        ks += _prf(ke, nonce + len(ks).to_bytes(4, "big"))
    return ks[:n]


def _hmac_open(
    master: bytes, nonce: bytes, tok_bytes: bytes, ct: bytes, tag: bytes
) -> tuple[bytes, bool]:
    """Verify-then-decrypt: tag mismatch returns (b"", False) without touching the keystream."""
    ke, ka = _prf(master, b"bs-env-v2-enc"), _prf(master, b"bs-env-v2-mac")
    expected_tag = _prf(ka, nonce + tok_bytes + bytes([_EV]) + ct)[:16]
    if not hmac.compare_digest(expected_tag, tag):
        return b"", False
    core = bytes(a ^ b for a, b in zip(ct, _keystream(ke, nonce, len(ct))))
    return core, True


def _parse_core(core_bytes: bytes) -> dict:
    return {
        "ev": core_bytes[0],
        "session_id": core_bytes[1:9],
        "seq_no": int.from_bytes(core_bytes[9:13], "big"),
        "sensor_time": int.from_bytes(core_bytes[13:21], "big"),
        "body": core_bytes[21:],
    }


# ── helpers ───────────────────────────────────────────────────────────────────

def _edge_stamp(queued: dict) -> tuple[int, ObservedSource, str]:
    edge = queued["edge"]
    src = edge["source"]
    return (
        int(edge["recv_time"]),
        ObservedSource(
            ip=src["ip"],
            ja3=src.get("ja3") or None,
            source_type=src["source_type"],
        ),
        edge["edge_id"],
    )


def _env_tier0(queued: dict, entry: DirEntry | None, tok_bytes: bytes) -> Envelope:
    sid_hex = queued.get("session_id", "")
    try:
        sid = bytes.fromhex(sid_hex) if sid_hex else b"\x00" * 8
    except ValueError:
        sid = b"\x00" * 8

    recv_time, obs, edge_id = _edge_stamp(queued)
    return Envelope(
        ev=int(queued.get("ev", 1)),
        bait_id=entry.bait_id if entry is not None else "",
        bait_version="",
        instance_token=tok_bytes if len(tok_bytes) == 8 else b"\x00" * 8,
        campaign_id=entry.campaign_id if entry else "",
        assurance_tier=0,
        session_id=sid,
        seq_no=int(queued["seq_no"]) if queued.get("seq_no") is not None else 0,
        sensor_time=0,
        channel=queued.get("channel", "dns"),
        edge_recv_time=recv_time,
        observed_source=obs,
        edge_id=edge_id,
        sig_valid=False,
    )


def _env_from_core(
    queued: dict, core: dict, entry: DirEntry, *, sig_valid: bool
) -> Envelope:
    """Build Envelope from the decrypted fixed binary core + directory facts (§1.2).

    Per-hit fields (ev, session_id, seq_no, sensor_time, body) come from the decrypted core.
    Routing facts (bait_id, campaign_id, assurance_tier) come exclusively from the directory.
    Channel comes from the edge-stamped QueuedEnvelope.channel (authoritative, §Q2 decision).
    """
    recv_time, obs, edge_id = _edge_stamp(queued)
    return Envelope(
        ev=core["ev"],
        bait_id=entry.bait_id,
        bait_version="",
        instance_token=_as_bytes(queued.get("instance_token", ""), 8),
        campaign_id=entry.campaign_id,
        assurance_tier=entry.assurance_tier,
        session_id=core["session_id"],
        seq_no=core["seq_no"],
        sensor_time=core["sensor_time"],
        channel=queued.get("channel", entry.default_channel),
        edge_recv_time=recv_time,
        observed_source=obs,
        edge_id=edge_id,
        sig_valid=sig_valid,
    )


def _env_from_hints(
    queued: dict, entry: DirEntry, tok_bytes: bytes, enc_raw: bytes
) -> Envelope:
    """Build from directory facts when decryption doesn't authenticate (sig_valid=False).

    session_id is derived from the raw (nonce || ct || tag) rather than a fixed all-zero
    value: assembly.py's record_id is `<itoken>-<sid>-<seq>` (§3.2), so an all-zero session_id
    collapses every failed decryption against one instance_token into the same record_id —
    storage's `ON CONFLICT (record_id) DO NOTHING` then silently drops every forgery/tamper
    attempt after the first one, undercutting §1.8's replay-is-intel rationale. Hashing the wire
    bytes keeps that dedup behavior for genuine retransmission of the exact same failed blob
    while giving each distinct tamper/forgery attempt its own record.
    """
    recv_time, obs, edge_id = _edge_stamp(queued)
    fallback_session_id = hashlib.sha256(enc_raw).digest()[:8]
    return Envelope(
        ev=int(queued.get("ev", 1)),
        bait_id=entry.bait_id,
        bait_version="",
        instance_token=tok_bytes if len(tok_bytes) == 8 else b"\x00" * 8,
        campaign_id=entry.campaign_id,
        assurance_tier=entry.assurance_tier,
        session_id=fallback_session_id,
        seq_no=0,
        sensor_time=0,
        channel=queued.get("channel", entry.default_channel),
        edge_recv_time=recv_time,
        observed_source=obs,
        edge_id=edge_id,
        sig_valid=False,
    )


def _as_bytes(val: Any, n: int) -> bytes:
    if isinstance(val, bytes):
        b = val
    elif isinstance(val, str):
        try:
            b = bytes.fromhex(val)
        except ValueError:
            b = val.encode()
    else:
        return b"\x00" * n
    return (b + b"\x00" * n)[:n]
