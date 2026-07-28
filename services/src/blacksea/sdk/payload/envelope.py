"""payload.envelope — channel-agnostic tier-2 encrypted envelope builder.

Assembles the fixed binary encrypted-core, seals it with a pure-stdlib HMAC-SHA256 AEAD keyed
by the per-instance master key, and returns the serialised JSON envelope bytes ready to POST
over HTTPS.

Wire format: {ev, tok, enc}
  - ev:  uint8 schema version (2) — outer fast-parse hint; also the first byte of the core
  - tok: 16-char hex instance_token (the only cleartext routing hint; also bound into the tag)
  - enc: base64url(nonce(12B) ‖ ct ‖ tag(16B)) — HMAC-SHA256-CTR keystream XOR of the fixed
         binary encrypted-core {ev(1B), session_id(8B), seq_no(4B), sensor_time(8B), body},
         authenticated encrypt-then-MAC with a domain-separated HMAC-SHA256 subkey

bait_id, campaign_id, channel, assurance_tier are never transmitted — the brain derives
them from tok via its key directory.

Pure standard library (base64, hmac, hashlib, json, os, time) — no third-party imports on the
envelope path. See src/blacksea/brain/context.md's security rationale note for the authoritative
spec of this construction (HMAC-SHA256 as a PRF, used as a CTR-mode stream cipher for
confidentiality and as the MAC for integrity, composed encrypt-then-MAC with distinct enc/mac
subkeys).
"""

import base64
import hashlib
import hmac
import json
import os
import time


def _prf(k: bytes, d: bytes) -> bytes:
    return hmac.new(k, d, hashlib.sha256).digest()


def _keystream(ke: bytes, nonce: bytes, n: int) -> bytes:
    ks = b""
    while len(ks) < n:
        ks += _prf(ke, nonce + len(ks).to_bytes(4, "big"))
    return ks[:n]


def build_encrypted_envelope(
    body: bytes,
    key_hex: str,
    instance_token_hex: str,
    *,
    session_id: bytes | None = None,
    seq_no: int = 0,
) -> bytes:
    """Encrypt + encode the payload; return the JSON envelope bytes.

    Builds the fixed binary encrypted-core, seals it with the per-instance HMAC-SHA256
    AEAD (encrypt-then-MAC, keyed off the master key with domain-separated subkeys, `tok` bound
    into the tag), and serialises the minimal {ev, tok, enc} envelope. The returned bytes are
    ready to POST over HTTPS.

    Args:
        body:                raw application payload bytes (included in the encrypted core)
        key_hex:             per-instance master key, 64-char hex (32 B raw)
        instance_token_hex:  instance_token, 16-char hex (8 B)
        session_id:          8-byte session id; random if omitted
        seq_no:              monotonic sequence number within the session
    """
    master = bytes.fromhex(key_hex)
    ke, ka = _prf(master, b"bs-env-v2-enc"), _prf(master, b"bs-env-v2-mac")
    nonce = os.urandom(12)
    ev = 2
    core = (
        bytes([ev])
        + (session_id or os.urandom(8))
        + seq_no.to_bytes(4, "big")
        + int(time.time() * 1000).to_bytes(8, "big")
        + body
    )
    ct = bytes(a ^ b for a, b in zip(core, _keystream(ke, nonce, len(core))))
    tok = bytes.fromhex(instance_token_hex)
    tag = _prf(ka, nonce + tok + bytes([ev]) + ct)[:16]

    def _b64url(b: bytes) -> str:
        return base64.urlsafe_b64encode(b).rstrip(b"=").decode()

    return json.dumps({
        "ev": ev,
        "tok": instance_token_hex,
        "enc": _b64url(nonce + ct + tag),
    }).encode()
