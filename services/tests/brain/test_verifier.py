"""verifier.py — HMAC-SHA256 AEAD decryption (inv 13) and envelope reconstruction.

The brain has the final word on authenticity: it is now the ONLY place decryption
happens (the edge never holds `_KEY` — see edge/context.md and
src/blacksea/brain/context.md).
"""

from __future__ import annotations

import base64
import os
from unittest import mock

import pytest

import blacksea.brain.verifier as verifier_mod
from blacksea.brain.verifier import (
    KeyDirectory,
    VerificationError,
    instance_status_for,
    verify,
)

from _helpers import (
    dir_entry,
    encrypted_https_envelope,
    gen_key,
    tier0_dns_envelope,
)


def test_tier0_is_unencrypted_and_bodyless():
    """Tier-0 DNS: sig_valid is always False (§1.3); body comes from obs_body
    in the pool, so verify() returns an empty body here."""
    kd = KeyDirectory({})
    env, body, sig_valid = verify(tier0_dns_envelope(), kd)

    assert sig_valid is False
    assert env.sig_valid is False
    assert body == b""
    assert env.assurance_tier == 0
    assert env.channel == "dns"
    assert env.instance_token.hex() == "1122334455667788"
    assert env.session_id.hex() == "aabbccddeeff0011"
    assert env.observed_source.source_type == "resolver"
    assert env.edge_recv_time == 1_700_000_000_000


def test_tier0_routing_from_directory():
    """bait_id/campaign_id come from the authoritative key-directory entry (the edge sends neither
    — it holds no directory). The token is the only routing input on the wire."""
    tok = "1122334455667788"
    kd = KeyDirectory({bytes.fromhex(tok): dir_entry(bait_id="real-bait", campaign_id="C9")})
    env, _, _ = verify(tier0_dns_envelope(instance_token=tok), kd)
    assert env.bait_id == "real-bait"
    assert env.campaign_id == "C9"


def test_tier1_valid_decryption():
    """A correctly encrypted tier-2 hit decrypts and the body is decoded from the
    decrypted fixed binary core (§1.4)."""
    key = gen_key()
    tok = "1122334455667788"
    kd = KeyDirectory({bytes.fromhex(tok): dir_entry(key=key)})

    queued = encrypted_https_envelope(key, instance_token=tok)
    env, body, sig_valid = verify(queued, kd)

    assert sig_valid is True
    assert env.sig_valid is True
    assert body == b'{"hostname":"victim-box"}'
    assert env.seq_no == 7
    assert env.sensor_time == 1_700_000_000_123
    assert env.channel == "https"
    assert env.observed_source.ja3 == "771,4865-4866"


def test_tier1_tampered_ciphertext_is_not_valid():
    """A tampered ciphertext must yield sig_valid=False — and the body is NOT
    trusted/decoded (§1.4: only authenticated cores are read)."""
    key = gen_key()
    tok = "1122334455667788"
    kd = KeyDirectory({bytes.fromhex(tok): dir_entry(key=key)})

    queued = encrypted_https_envelope(key, instance_token=tok, corrupt_ct=True)
    env, body, sig_valid = verify(queued, kd)

    assert sig_valid is False
    assert env.sig_valid is False
    assert body == b""


def test_tier1_distinct_tamper_attempts_get_distinct_session_ids():
    """Two distinct failed-decryption attempts against the same token must not collapse
    to the same envelope session_id (and therefore the same record_id, §3.2) — otherwise
    storage's ON CONFLICT DO NOTHING silently drops every attempt after the first."""
    key = gen_key()
    tok = "1122334455667788"
    kd = KeyDirectory({bytes.fromhex(tok): dir_entry(key=key)})

    env_a, _, sig_valid_a = verify(
        encrypted_https_envelope(key, instance_token=tok, corrupt_ct=True), kd
    )
    env_b, _, sig_valid_b = verify(
        encrypted_https_envelope(key, instance_token=tok, corrupt_ct=True), kd
    )

    assert sig_valid_a is False and sig_valid_b is False
    assert env_a.session_id != b"\x00" * 8
    assert env_a.session_id != env_b.session_id


def test_tier1_wrong_key_is_not_valid():
    """Encrypted with one key, directory holds another → sig_valid False."""
    encrypt_key = gen_key()
    other_key = gen_key()
    tok = "1122334455667788"
    kd = KeyDirectory({bytes.fromhex(tok): dir_entry(key=other_key)})

    _, _, sig_valid = verify(encrypted_https_envelope(encrypt_key, instance_token=tok), kd)
    assert sig_valid is False


def test_tier1_unknown_token_is_structural_error():
    """A tier≥1 hit whose token is not in the directory cannot be decrypted at
    all — structural error, caller dead-letters."""
    key = gen_key()
    kd = KeyDirectory({})  # empty
    with pytest.raises(VerificationError):
        verify(encrypted_https_envelope(key), kd)


def test_tier1_missing_enc_field_is_structural_error():
    tok = "1122334455667788"
    kd = KeyDirectory({bytes.fromhex(tok): dir_entry()})
    queued = {
        "assurance_tier": 2,
        "instance_token": tok,
        "channel": "https",
        "edge": {
            "recv_time": 1,
            "source": {"ip": "1.2.3.4", "source_type": "client"},
            "edge_id": "e",
        },
    }
    with pytest.raises(VerificationError):
        verify(queued, kd)


def test_bad_instance_token_hex_is_structural_error():
    kd = KeyDirectory({})
    queued = tier0_dns_envelope(instance_token="nothex!!")
    with pytest.raises(VerificationError):
        verify(queued, kd)


def test_keydir_from_file_roundtrip(tmp_path):
    """The directory loads the brain-only JSON keydir format (§5.11)."""
    import json

    p = tmp_path / "brain_keydir.json"
    p.write_text(
        json.dumps(
            [
                {
                    "instance_token": "1122334455667788",
                    "key": "00" * 32,
                    "status": "active",
                    "bait_id": "hostname-probe",
                    "campaign_id": "camp-1",
                    "assurance_tier": 2,
                    "default_channel": "https",
                    "valid_from": 0,
                    "valid_until": None,
                }
            ]
        )
    )
    kd = KeyDirectory.from_file(str(p))
    entry = kd.lookup(bytes.fromhex("1122334455667788"))
    assert entry is not None
    assert entry.bait_id == "hostname-probe"
    assert entry.key_bytes == b"\x00" * 32


def test_keydir_missing_file_is_empty_not_fatal(tmp_path):
    """A missing keydir is a warning, not a crash — tier-0 baits still work."""
    kd = KeyDirectory.from_file(str(tmp_path / "does-not-exist.json"))
    assert kd.lookup(b"\x00" * 8) is None


# ── HMAC-SHA256 AEAD regression locks (see src/blacksea/brain/context.md's security rationale) ───

def _tamper_enc(queued: dict, index: int) -> dict:
    """Return a copy of ``queued`` with one byte of its ``enc`` blob flipped."""
    enc = queued["enc"]
    blob = bytearray(base64.urlsafe_b64decode(enc + "=" * (-len(enc) % 4)))
    blob[index] ^= 0xFF
    tampered = dict(queued)
    tampered["enc"] = base64.urlsafe_b64encode(bytes(blob)).rstrip(b"=").decode()
    return tampered


def test_tier1_empty_body_round_trip():
    key = gen_key()
    tok = "1122334455667788"
    kd = KeyDirectory({bytes.fromhex(tok): dir_entry(key=key)})

    env, body, sig_valid = verify(encrypted_https_envelope(key, instance_token=tok, body=b""), kd)

    assert sig_valid is True
    assert env.sig_valid is True
    assert body == b""


def test_tier1_large_body_round_trip():
    key = gen_key()
    tok = "1122334455667788"
    kd = KeyDirectory({bytes.fromhex(tok): dir_entry(key=key)})
    big_body = os.urandom(150_000)

    env, body, sig_valid = verify(
        encrypted_https_envelope(key, instance_token=tok, body=big_body), kd
    )

    assert sig_valid is True
    assert body == big_body


def test_tier1_tampered_nonce_is_not_valid():
    """Flipping a byte inside the 12 B nonce (not the ciphertext or tag) must also fail
    authentication — the tag covers the nonce."""
    key = gen_key()
    tok = "1122334455667788"
    kd = KeyDirectory({bytes.fromhex(tok): dir_entry(key=key)})
    queued = _tamper_enc(encrypted_https_envelope(key, instance_token=tok), 0)

    env, body, sig_valid = verify(queued, kd)

    assert sig_valid is False
    assert body == b""


def test_tier1_tampered_tag_is_not_valid():
    key = gen_key()
    tok = "1122334455667788"
    kd = KeyDirectory({bytes.fromhex(tok): dir_entry(key=key)})
    queued = _tamper_enc(encrypted_https_envelope(key, instance_token=tok), -1)

    env, body, sig_valid = verify(queued, kd)

    assert sig_valid is False
    assert body == b""


def test_tier1_verify_before_decrypt():
    """Tamper detection happens before the keystream is ever computed (encrypt-then-MAC,
    verify-before-decrypt, §1.4) — no plaintext is produced on a failed authentication."""
    key = gen_key()
    tok = "1122334455667788"
    kd = KeyDirectory({bytes.fromhex(tok): dir_entry(key=key)})
    queued = _tamper_enc(encrypted_https_envelope(key, instance_token=tok), -1)

    with mock.patch.object(verifier_mod, "_keystream") as ks:
        _, _, sig_valid = verify(queued, kd)
        assert sig_valid is False
        ks.assert_not_called()


# ── §5.7 revocation / status gating ───────────────────────────────────────────


@pytest.mark.parametrize("status", ["active", "revoked", "burned", "retired", "draft"])
def test_instance_status_for_reflects_brain_directory(status):
    """The record's instance_status is the brain's authoritative directory status, not the
    edge-stamped value (§5.7) — so a revoked/burned/retired instance's hits are flagged."""
    tok = "1122334455667788"
    kd = KeyDirectory({bytes.fromhex(tok): dir_entry(status=status)})
    # The edge sends no status at all now — the brain's directory is the sole authority.
    queued = tier0_dns_envelope(instance_token=tok)
    assert instance_status_for(kd, queued) == status


def test_instance_status_for_unknown_when_not_in_directory():
    kd = KeyDirectory({})
    assert instance_status_for(kd, tier0_dns_envelope(instance_token="1122334455667788")) == "unknown"
    # Malformed token → "unknown", never a crash.
    assert instance_status_for(kd, {"instance_token": "nothex!!"}) == "unknown"


def test_revoked_instance_still_decrypts_but_is_flagged():
    """§5.7: a revoked instance's hit is NOT dropped — it still decrypts + authenticates (so the
    intel is captured), and the brain-authoritative status marks it revoked for heavy-sampling."""
    key = gen_key()
    tok = "1122334455667788"
    kd = KeyDirectory({bytes.fromhex(tok): dir_entry(key=key, status="revoked")})
    queued = encrypted_https_envelope(key, instance_token=tok)

    env, body, sig_valid = verify(queued, kd)

    assert sig_valid is True                       # decryption unaffected by status
    assert body == b'{"hostname":"victim-box"}'
    assert instance_status_for(kd, queued) == "revoked"


def test_out_of_window_hit_is_logged_not_dropped(caplog):
    """§5.3 defense in depth: a tier≥1 hit outside the validity window still decrypts and is stored
    (the edge is the hard enforcer, §5.9-e; a brain-side drop would lose hits on clock skew) — the
    brain just logs the anomaly."""
    key = gen_key()
    tok = "1122334455667788"
    # recv_time in the fixture is 1_700_000_000_999; put valid_until well before it.
    entry = verifier_mod.DirEntry(
        key_bytes=key, status="active", bait_id="b", campaign_id="c",
        assurance_tier=2, default_channel="https", valid_from=0, valid_until=1_000_000,
    )
    kd = KeyDirectory({bytes.fromhex(tok): entry})
    queued = encrypted_https_envelope(key, instance_token=tok)

    with caplog.at_level("WARNING"):
        env, body, sig_valid = verify(queued, kd)

    assert sig_valid is True                       # not dropped
    assert any("outside validity window" in r.message for r in caplog.records)
