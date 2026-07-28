"""Locks the HMAC-SHA256 AEAD envelope construction (see src/blacksea/sdk/context.md and
src/blacksea/brain/context.md's security rationale note).
``build_encrypted_envelope`` is the *seal* half of the AEAD; the *open* half lives in
``blacksea.brain.verifier`` and is exercised end-to-end (seal → open) in
``tests/brain/test_verifier.py``. This file locks the seal in isolation: wire shape,
the underlying HMAC-SHA256 primitive, nonce randomness, and a golden wire vector.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import os
import time
from unittest import mock

from blacksea.sdk.payload.envelope import build_encrypted_envelope


def test_hmac_sha256_primitive_kat():
    """RFC 4231 test case 2 — sanity that the stdlib primitive is what we think."""
    key = b"Jefe"
    data = b"what do ya want for nothing?"
    expected = bytes.fromhex(
        "5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843"
    )
    assert hmac.new(key, data, hashlib.sha256).digest() == expected


def _decode_enc(enc_b64: str) -> bytes:
    return base64.urlsafe_b64decode(enc_b64 + "=" * (-len(enc_b64) % 4))


def test_wire_shape():
    key_hex = os.urandom(32).hex()
    tok_hex = os.urandom(8).hex()
    body = b'{"hostname":"victim-box"}'
    wire = build_encrypted_envelope(body, key_hex, tok_hex, session_id=os.urandom(8), seq_no=3)

    outer = json.loads(wire)
    assert set(outer) == {"ev", "tok", "enc"}
    assert outer["ev"] == 2
    assert outer["tok"] == tok_hex

    blob = _decode_enc(outer["enc"])
    # nonce(12) + core(21 header + body) + tag(16)
    assert len(blob) == 12 + (21 + len(body)) + 16


def test_empty_body_shape():
    key_hex = os.urandom(32).hex()
    tok_hex = os.urandom(8).hex()
    wire = build_encrypted_envelope(b"", key_hex, tok_hex)
    outer = json.loads(wire)
    blob = _decode_enc(outer["enc"])
    assert len(blob) == 12 + 21 + 16  # header only, no body


def test_nonce_is_96_bit_and_random_per_call():
    key_hex = os.urandom(32).hex()
    tok_hex = os.urandom(8).hex()
    nonces = set()
    for _ in range(50):
        wire = build_encrypted_envelope(b"x", key_hex, tok_hex)
        blob = _decode_enc(json.loads(wire)["enc"])
        nonce = blob[:12]
        assert len(nonce) == 12
        nonces.add(nonce)
    assert len(nonces) == 50  # no collisions across 50 draws


def test_session_id_random_when_omitted():
    key_hex = os.urandom(32).hex()
    tok_hex = os.urandom(8).hex()
    wire_a = build_encrypted_envelope(b"x", key_hex, tok_hex)
    wire_b = build_encrypted_envelope(b"x", key_hex, tok_hex)
    assert json.loads(wire_a)["enc"] != json.loads(wire_b)["enc"]


def test_golden_wire_vector():
    """Fixed inputs (key, tok, session_id, seq_no, body, nonce, sensor_time) must produce a
    fixed ``enc``. This locks the wire format against silent drift."""
    key_hex = "11" * 32
    tok_hex = "22" * 8
    session_id = b"\x33" * 8
    seq_no = 7
    body = b"golden-body"
    fixed_nonce = b"\x44" * 12
    fixed_now_ms = 1_700_000_000_000

    with mock.patch("os.urandom", return_value=fixed_nonce), \
         mock.patch("time.time", return_value=fixed_now_ms / 1000):
        wire = build_encrypted_envelope(
            body, key_hex, tok_hex, session_id=session_id, seq_no=seq_no
        )

    outer = json.loads(wire)
    assert outer == {
        "ev": 2,
        "tok": "2222222222222222",
        "enc": "REREREREREREREREp5j0tP3Ni7eERm7fruxatIUP7J9kergqg76KLfoZkiAGS79k_72jZ6tjnFUM1UMD",
    }
