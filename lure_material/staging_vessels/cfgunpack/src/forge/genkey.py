#!/usr/bin/env python3
"""
Generates bundle/defaults.go.
The bundle-binding key is derived at startup via SHA-256 from eight
package-level variables declared individually; the key never appears
verbatim in the binary, and the inputs are not adjacent in .rodata.

Usage: python3 forge/genkey.py --out FILE [--seed-material STRING]
       Writes the Go init function to FILE, prints the 32-char hex seed to stdout.

With --seed-material the eight format-binding constants (and therefore the
printed seed) are derived deterministically from STRING instead of the system
CSPRNG, so a build driven by a fixed seed is byte-reproducible. Without it the
constants come from secrets.randbits (the original standalone behaviour).
"""
import argparse, hashlib, secrets, struct

def main():
    p = argparse.ArgumentParser()
    p.add_argument('--out', required=True, metavar='FILE')
    p.add_argument('--seed-material', default=None, metavar='STRING',
                   help='derive the constants deterministically from STRING (reproducible builds)')
    args = p.parse_args()

    if args.seed_material is not None:
        # Deterministic: expand STRING into eight 32-bit words via SHA-256.
        material = hashlib.sha256(('cfgunpack-genkey|' + args.seed_material).encode()).digest()
        iv = list(struct.unpack('>8I', material))
    else:
        iv = [secrets.randbits(32) for _ in range(8)]

    # Derive seed: SHA-256 of big-endian packed words, first 16 bytes as hex.
    raw = struct.pack('>8I', *iv)
    seed_hex = hashlib.sha256(raw).digest()[:16].hex()

    # Emit each constant as a separate package-level var so the linker
    # does not coalesce them into a single contiguous .rodata block.
    var_decls = '\n'.join(f'\tv{i} uint32 = 0x{iv[i]:08x}' for i in range(8))
    var_refs  = ', '.join(f'v{i}' for i in range(8))

    go_code = f'''\
package bundle

import (
\t"crypto/sha256"
\t"encoding/hex"
)

// Format-binding constants; individual declarations prevent coalescing.
var (
{var_decls}
)

func init() {{
\tv := [8]uint32{{{var_refs}}}
\tvar b [32]byte
\tfor i, u := range v {{
\t\tb[i<<2], b[i<<2|1], b[i<<2|2], b[i<<2|3] = byte(u>>24), byte(u>>16), byte(u>>8), byte(u)
\t}}
\tsum := sha256.Sum256(b[:])
\tbuildSeed = hex.EncodeToString(sum[:16])
}}
'''
    with open(args.out, 'w') as f:
        f.write(go_code)

    print(seed_hex, end='')

if __name__ == '__main__':
    main()
