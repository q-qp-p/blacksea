"""Agent-harness fingerprint listener.

Interprets HTTPS beacon hits from ``payload.py``. The wire-format JSON carries two
kinds of field: a few computed locally and sent as-is (``host_lit``, ``pkg``, ``bins``,
``model``), and raw precursor material for the rest (``envk``, ``boolenv``, ``cwdnames``,
``valenv``) that this listener reduces into the same ``ns``/``ns_n``/``disc_k``/``cwd``/
``cwd_n``/``valtok`` fields the payload used to compute itself. ``_resolve_report()`` does
that reduction; the resulting Report is then scored exactly as before by the deterministic,
abstention-capable ``RuleInference`` engine.

**Why the split (2026-07-23).** The noise-filtering knowledge base this reduction needs
(which env vars / cwd entries / value tokens are generic OS clutter vs. harness-owned
signal) was originally payload-side, making it part of the embedded delivery artifact.
Some staging vessels have a small embedding budget (e.g. pwcrypt's 4096-byte vault
header), and that knowledge base was ~45% of the bundled payload's size. Moving it here
costs nothing extra to run (the brain, unlike the target worker, isn't resource-bounded)
and only grows the per-hit wire body -- still far under the edge's HTTPS body cap. The
inference engine, Report wire format, and harness knowledge base (signatures.yaml) are
otherwise unchanged and ported verbatim from the upstream ``fingerprint_engine`` research
prototype (its ``inference.py`` and ``report.py``, plus the ``signatures.yaml`` that now
ships beside this file); this split only moves *where* the Report's fields get computed,
not the fields themselves or how they're scored. That prototype is not part of this
repository — later "ported/verbatim from" comments below refer back to it.

**Operator recon (2026-07-23, additive) is a separate, out-of-band channel.** The wire body
may also carry ``cred_surface``, ``locale``, and ``history`` -- operator/actor-intel signals
useful regardless of which harness is driving the worker (credential/access-surface
presence, timezone/locale, shell-history metadata). These are deliberately **not** part of
the ``FIELDS`` vocabulary and never reach ``RuleInference``: ``interpret()`` lifts them
straight out of the wire body into ``AnalyzerOutput.details`` before the harness-attribution
Report is even built, so they can't pollute the ``fields`` evidence list or accidentally
factor into a harness score. See ``payload.py``'s module docstring for what each field
contains and why it stops short of contents/values.
"""

from __future__ import annotations

import json
import re
from collections import Counter
from dataclasses import dataclass, field, fields
from pathlib import Path
from typing import Any

import yaml

from blacksea.sdk.listener import (
    ANY,
    AnalyzerOutput,
    BodyDecodeError,
    Envelope,
    GoldenCase,
    Listener,
    test_envelope,
)

SIGNATURES_PATH = Path(__file__).parent / "signatures.yaml"


# ═════════════════════════════════════════════════════════════════════════════
# Report — the wire-format contract between payload (grabber) and listener
# (inference). Ported from the upstream prototype's report.py (see module docstring).
# ═════════════════════════════════════════════════════════════════════════════

# key -> (kind, meaning). kind is "structural" (survives a rename) or
# "literal" (exact strings; discriminative now, brittle across versions).
FIELDS: dict[str, tuple[str, str]] = {
    # --- structural: cheap, small, generalizes -------------------------------
    "ns_n":   ("structural", "size of the largest harness-owned env namespace"),
    "dot_n":  ("structural", "size of the largest same-prefixed dotfile family"),
    "role_n": ("structural", "count of role-named *_MODEL vars with no shared prefix"),
    "disc":   ("structural", "an unconditional self-disclosure marker is present"),
    "host":   ("structural", "hostname shape: hex8 | hex12 | named-suffixed | plain"),
    "dens":   ("structural", "harness-attributable signal density (0 => separated worker)"),
    "prov":   ("structural", "LLM provider prefixes present, sorted"),
    "nbin":   ("structural", "count of non-shell binaries in the process tree"),
    "haspkg": ("structural", "a package manifest is readable"),
    "hasvcs": ("structural", "a custom VCS attribution namespace exists"),
    "cwd_n":  ("structural", "size of the largest same-prefixed CWD-local file/dir family"),
    # --- literal: exact strings ----------------------------------------------
    "ns":     ("literal", "the env namespace prefix itself, e.g. 'CAI'"),
    "dot":    ("literal", "the dotfile family name, e.g. '.cai'"),
    "pkg":    ("literal", "package manifest name"),
    "bins":   ("literal", "non-shell binary basenames in the process tree"),
    "flags":  ("literal", "distinctive long argv flags"),
    "model":  ("literal", "model string, when directly readable"),
    "envk":   ("literal", "raw env var NAMES, no values; agent_fp's grabber sends this "
                          "instead of pre-filtering -- _resolve_report() reduces it into ns/ns_n"),
    "paths":  ("literal", "raw filesystem paths (baseline grabbers only)"),
    "disc_k": ("literal", "the self-disclosure marker's variable name"),
    "cwd":    ("literal", "the CWD-local family's shared name prefix, e.g. 'mantis'"),
    "valtok": ("literal", "candidate name-tokens found in env VALUES"),
    "host_lit": ("literal", "literal, non-hex prefix of hostname, e.g. 'strix-scan'"),
    # --- raw wire precursors (agent_fp's grabber only; consumed by _resolve_report(),
    #     never scored directly by RuleInference) -----------------------------
    "cwdnames": ("literal", "raw cwd-local basenames -- resolved into cwd/cwd_n"),
    "boolenv":  ("literal", "raw {name: value} for env vars whose value is a boolean-ish "
                            "flag ('1'/'true'/'True') -- resolved into disc_k"),
    "valenv":   ("literal", "raw {name: value} for PS1 + *_PASSWORD/_PASS/_URI/_URL/_DSN "
                            "env vars -- resolved into valtok"),
}


class FieldError(KeyError):
    pass


@dataclass
class Report:
    """A grabber's transmitted payload. Small by construction, or it is a bug."""

    grabber: str = "?"
    data: dict[str, Any] = field(default_factory=dict)

    def put(self, key: str, value: Any) -> None:
        if key not in FIELDS:
            raise FieldError(
                f"{key!r} is not in the grabber/inference vocabulary. Adding a field "
                "is a design change -- document it in FIELDS first."
            )
        if value is None or value == [] or value == {} or value == "":
            return          # never pay bytes for an empty finding
        self.data[key] = value

    def get(self, key: str, default: Any = None) -> Any:
        return self.data.get(key, default)

    def has(self, key: str) -> bool:
        return key in self.data

    def wire(self) -> str:
        """Canonical serialization. This is what crosses the wire."""
        return json.dumps(self.data, sort_keys=True, separators=(",", ":"), default=list)

    def size(self) -> int:
        return len(self.wire().encode())

    def __str__(self) -> str:
        return f"<Report {self.grabber} {self.size()}B {sorted(self.data)}>"


# ═════════════════════════════════════════════════════════════════════════════
# Server-side reduction (2026-07-23 split, see module docstring) — the noise-filtering
# knowledge base and the fp_* functions that apply it, moved here from payload.py.
# Verbatim from the upstream prototype's probes/__init__.py; behavior is unchanged, only the
# input shape differs (a raw wire precursor instead of a live env/files/procs snapshot).
# ═════════════════════════════════════════════════════════════════════════════

GENERIC_ENV = {
    "PATH", "HOME", "HOSTNAME", "PWD", "OLDPWD", "SHLVL", "TERM", "USER", "LOGNAME",
    "SHELL", "TMPDIR", "TEMP", "TMP", "EDITOR", "VISUAL", "PAGER", "MAIL", "_", "TZ",
    "DEBIAN_FRONTEND", "PYTHONUNBUFFERED", "PYTHONWARNINGS", "PYTHONPATH", "LS_COLORS",
    "HOSTTYPE", "MACHTYPE", "OSTYPE", "COLUMNS", "LINES", "DISPLAY", "COLORTERM",
    "PYTHONDONTWRITEBYTECODE", "PYTHONIOENCODING", "PYTHONHASHSEED", "NODE_OPTIONS",
    "SSL_CERT_FILE", "SSL_CERT_DIR", "REQUESTS_CA_BUNDLE", "CURL_CA_BUNDLE",
}

GENERIC_PREFIXES = {
    "LC", "LANG", "XDG", "SSH", "GIT", "NPM", "NODE", "PYTHON", "JAVA", "GO", "GOPATH",
    "RUST", "CARGO", "DOCKER", "KUBERNETES", "K8S", "AWS", "AZURE", "GCP", "HTTP",
    "HTTPS", "NO", "FTP", "ALL", "CI", "TERM", "COLOR", "LESS", "SYSTEMD", "DBUS",
    "HOME", "USER", "PATH", "SHELL", "PWD", "TMP", "TEMP", "DEBIAN", "PS1", "PS2",
    "VIRTUAL", "CONDA", "PIP", "SETUPTOOLS", "LD", "PKG", "MANPATH", "INFOPATH",
}

PROVIDER_PREFIXES = {
    "OPENAI", "ANTHROPIC", "OPENROUTER", "GEMINI", "GOOGLE", "OLLAMA", "LITELLM",
    "PERPLEXITY", "DEEPSEEK", "BEDROCK", "GROQ", "MISTRAL", "XAI", "COHERE",
    "TOGETHER", "FIREWORKS", "VERTEX", "HUGGINGFACE", "HF", "AZUREOPENAI", "NVIDIA",
    "REPLICATE", "CEREBRAS", "SAMBANOVA", "LMSTUDIO", "VLLM",
}

GENERIC_CWD_TOKENS = {
    "src", "test", "tests", "docs", "doc", "readme", "config", "node", "dist",
    "build", "index", "main", "app", "lib", "bin", "tmp", "cache", "log", "logs",
    "data", "out", "output", "vendor", "assets", "public", "scripts", "script",
    "utils", "util", "common", "workspace", "project", "projects", "engagement",
    "engagements", "report", "reports", "results", "result", "backup", "backups",
    "old", "new", "final", "draft", "notes", "misc", "tools", "shared", "target",
    "env", "venv", "node_modules", "github", "examples", "example", "exploit",
    "dev", "agents", "agent", "version",
}

_CWD_TOKEN = re.compile(r"^\.?([A-Za-z][A-Za-z0-9]*)")
_SLUG = re.compile(r"[a-z][a-z0-9]{3,15}")

GENERIC_VALUE_TOKENS = {
    "http", "https", "host", "docker", "internal", "webhooks", "webhook",
    "redacted", "local", "localhost", "default", "admin", "user", "root",
    "pass", "true", "false", "null", "none", "proxy", "cache", "redis",
    "mysql", "postgres", "mongo", "graph", "service", "secret", "token",
    "auth", "index", "www", "com", "org", "net", "bolt", "neo4j",
}

MARKER_MAXLEN = 16


def fp_prefix(name):
    """Extract the underscore-separated prefix of a name."""
    return name.split("_", 1)[0]


def fp_harness_env_names(envk):
    """Env names that are neither generic OS noise nor provider-owned. ``envk`` is a
    raw list of env var NAMES (the wire field payload.py sends) -- values are never
    seen here, matching what the original function read from a live env dict too."""
    return [
        k for k in envk
        if k not in GENERIC_ENV
        and fp_prefix(k) not in GENERIC_PREFIXES
        and fp_prefix(k) not in PROVIDER_PREFIXES
    ]


def fp_env_namespace(envk, min_size=2):
    """Largest same-prefixed, harness-owned env family."""
    counts = Counter(fp_prefix(k) for k in fp_harness_env_names(envk) if len(fp_prefix(k)) >= 2)
    if not counts:
        return None, 0
    name, n = counts.most_common(1)[0]
    return (name, n) if n >= min_size else (None, 0)


def fp_self_disclosure_marker(boolenv):
    """Unconditional single var announcing agent-controlled-shell presence. ``boolenv``
    is the wire field payload.py sends: only the env entries whose value already looked
    boolean-ish ('1'/'true'/'True') -- narrower than the live env this function
    originally scanned, but the value-shape prefilter it needs is identical."""
    for k, v in sorted(boolenv.items()):
        if k in GENERIC_ENV or fp_prefix(k) in GENERIC_PREFIXES or len(k) > MARKER_MAXLEN:
            continue
        if str(v) not in ("1", "true", "True"):
            continue
        if (k.endswith(("_CLI", "_CODE", "_AGENT", "_ACTIVE"))
                or k in ("AGENT", "ACTIVE")
                or (k.endswith("CODE") and k[:-4].isalpha() and len(k) <= 12)):
            return k
    return None


def fp_cwd_family(cwdnames, min_size=2):
    """Largest shared-prefix family among cwd-local basenames. ``cwdnames`` is the wire
    field payload.py sends -- already basename-extracted, so this operates directly on
    names instead of the {path, in_cwd} entries the original local version read."""
    counts = Counter()
    for base in cwdnames:
        m = _CWD_TOKEN.match(base)
        if not m:
            continue
        tok = m.group(1).lower()
        if tok in GENERIC_CWD_TOKENS or len(tok) < 4:
            continue
        counts[tok] += 1
    if not counts:
        return None, 0
    name, n = counts.most_common(1)[0]
    return (name, n) if n >= min_size else (None, 0)


def fp_env_value_tokens(valenv):
    """Candidate name-tokens found in env VALUES. ``valenv`` is the wire field
    payload.py sends: only the PS1 / *_PASSWORD/_PASS/_URI/_URL/_DSN entries -- the
    exact narrow value set this function originally scanned a live env for."""
    out = set()
    for v in valenv.values():
        if not isinstance(v, str):
            continue
        for tok in _SLUG.findall(v.lower()):
            if tok not in GENERIC_VALUE_TOKENS:
                out.add(tok)
    return sorted(out)


def _resolve_report(data: dict) -> dict:
    """Fill in ns/ns_n, disc_k, cwd/cwd_n, and valtok from their raw wire precursors
    (envk/boolenv/cwdnames/valenv) when the resolved field itself isn't already present
    in the wire body. A grabber that ever sends the resolved fields directly (as every
    existing golden case here does) is honored as-is -- this is purely additive. The raw
    precursor keys are stripped from the result: they're wire-format plumbing, never part
    of the Report RuleInference scores or the details.fields evidence list.

    Each raw field is resolved independently and defensively: a malformed or
    unexpectedly-shaped precursor (a future grabber version, a hand-authored fixture
    mistake) costs only its own field, never the others -- interpret() wraps this whole
    call too, but resolving field-by-field means e.g. a bad `envk` still leaves `cwd`/
    `valtok` resolvable from otherwise-good `cwdnames`/`valenv`."""
    resolved = dict(data)

    if "ns_n" not in resolved and "envk" in data:
        try:
            ns, ns_n = fp_env_namespace(data["envk"])
        except Exception:
            ns, ns_n = None, 0
        if ns is not None:
            resolved["ns"] = ns
        resolved["ns_n"] = ns_n

    if "disc_k" not in resolved and "boolenv" in data:
        try:
            disc_k = fp_self_disclosure_marker(data["boolenv"])
        except Exception:
            disc_k = None
        if disc_k is not None:
            resolved["disc_k"] = disc_k

    if "cwd_n" not in resolved and "cwdnames" in data:
        try:
            cwd, cwd_n = fp_cwd_family(data["cwdnames"])
        except Exception:
            cwd, cwd_n = None, 0
        if cwd is not None:
            resolved["cwd"] = cwd
        resolved["cwd_n"] = cwd_n

    if "valtok" not in resolved and "valenv" in data:
        try:
            valtok = fp_env_value_tokens(data["valenv"])
        except Exception:
            valtok = []
        if valtok:
            resolved["valtok"] = valtok

    for raw_key in ("envk", "boolenv", "cwdnames", "valenv"):
        resolved.pop(raw_key, None)

    return resolved


# ═════════════════════════════════════════════════════════════════════════════
# Inference — runs OFF the worker, sees only the Report. Ported verbatim from
# the upstream prototype's inference.py.
# ═════════════════════════════════════════════════════════════════════════════

# Weights for literal and structural field matches
W_LITERAL = {
    "ns": 0.55, "dot": 0.25, "pkg": 0.30, "bins": 0.20, "flags": 0.45,
    "disc_k": 0.35, "model": 0.05, "cwd": 0.30, "valtok": 0.30, "host_lit": 0.35
}
W_STRUCTURAL = {
    "ns_n": 0.10, "dot_n": 0.08, "role_n": 0.18, "disc": 0.10,
    "host": 0.08, "prov": 0.08, "nbin": 0.05, "haspkg": 0.05, "hasvcs": 0.15,
    "cwd_n": 0.10
}

CONFIDENCE_FLOOR = 0.45
MARGIN_FLOOR = 0.10
SEPARATED_DENSITY = 2
WRAPPER_EVIDENCE_FLOOR = 0.30
MISMATCH_PENALTY = 1.0
SPECIFICITY_FLOOR = 0.10

# An ordinary machine with no agentic harness on it.
GENERIC_BASELINE: dict[str, Any] = {
    "ns": None, "ns_n": 0, "dot": None, "dot_n": 0, "role_n": 0,
    "disc": False, "disc_k": None, "host": "plain", "dens": 0,
    "prov": [], "bins": [], "nbin": 0, "flags": [], "pkg": None,
    "model": None, "haspkg": False, "hasvcs": False,
    "cwd": None, "cwd_n": 0, "valtok": [], "host_lit": None,
}

# Composition relationships (harness -> list of tools it can wrap)
COMPOSITION = {
    "PentestGPT": ["claude_code", "cline", "aider"],
    "oh-my-open-pentest": ["opencode", "codex"],
    "mantis": ["aider", "cline"],
}


@dataclass
class Verdict:
    harness: str | None = None
    family: str | None = None
    model: str | None = None
    confidence: float = 0.0
    runner_up: str | None = None
    wrapper: str | None = None
    evidence: list[str] = field(default_factory=list)

    @property
    def abstained(self) -> bool:
        return self.harness is None

    def __str__(self) -> str:
        who = self.harness or f"unknown[{self.family or 'unattributed'}]"
        m = f" model={self.model}" if self.model else ""
        w = f" wrapper={self.wrapper}" if self.wrapper else ""
        return f"{who} conf={self.confidence:.2f}{m}{w}"


@dataclass
class Signature:
    harness: str
    population: str = "pentest"
    literal: dict[str, Any] = field(default_factory=dict)
    structural: dict[str, Any] = field(default_factory=dict)
    notes: str = ""
    fixture: str | None = None

    @property
    def untested(self) -> bool:
        return self.fixture in (None, "none")


def load_signatures(path: Path | str = SIGNATURES_PATH) -> list[Signature]:
    """Load harness signatures from YAML file."""
    raw = yaml.safe_load(Path(path).read_text()) or []
    out = []
    for entry in raw:
        unknown = set(entry) - {f.name for f in fields(Signature)}
        if unknown:
            raise ValueError(f"{path}: signature {entry.get('harness')!r} has unknown "
                             f"key(s) {sorted(unknown)}; valid keys are "
                             f"{sorted(f.name for f in fields(Signature))}")
        out.append(Signature(**entry))
    return out


def _match_literal(key: str, expected: Any, got: Any) -> float | None:
    """1.0 match / 0.0 mismatch / None if not comparable."""
    if got is None or expected in (None, [], ""):
        return None
    if key in ("bins", "flags", "valtok"):
        exp = set(expected)
        gotset = set(got if isinstance(got, (list, set)) else [got])
        if not exp:
            return None
        return len(exp & gotset) / len(exp)
    if key == "model":
        return 1.0 if any(str(e).lower() in str(got).lower() for e in
                          (expected if isinstance(expected, list) else [expected])) else 0.0
    return 1.0 if str(got) == str(expected) else 0.0


def _match_structural(key: str, expected: Any, got: Any) -> float | None:
    """Match a structural field expectation against a received value."""
    if got is None or expected is None:
        return None
    if isinstance(expected, list) and len(expected) == 2 and all(
            isinstance(x, (int, float)) for x in expected) and isinstance(got, (int, float)):
        lo, hi = expected
        return 1.0 if lo <= got <= hi else 0.0
    if isinstance(expected, list):
        if key == "prov":
            exp, g = set(expected), set(got if isinstance(got, list) else [got])
            return len(exp & g) / len(exp) if exp else None
        return 1.0 if got in expected else 0.0
    if isinstance(expected, bool):
        return 1.0 if bool(got) == expected else 0.0
    if isinstance(expected, (int, float)) and isinstance(got, (int, float)):
        return 1.0 if got == expected else 0.0
    return 1.0 if str(got) == str(expected) else 0.0


def _family(r: Report) -> str:
    """Infer the high-level family/architecture of the report."""
    if r.has("dens") and r.get("dens") <= SEPARATED_DENSITY and r.get("cwd_n", 0) < 2:
        return "separated-worker"
    if r.get("role_n", 0) >= 2 and r.get("ns_n", 0) < 3:
        return "wrapper-supervisor"
    if r.get("ns_n", 0) >= 3:
        return "prefixed-namespace-harness"
    if r.get("nbin", 0) >= 2 or r.get("bins"):
        return "composition"
    return "unattributed"


class RuleInference:
    """Deterministic, evidence-carrying, abstention-capable inference engine."""

    name = "rules"

    def __init__(self, signatures: list[Signature] | None = None,
                 allowed_fields: set[str] | None = None) -> None:
        self.signatures = signatures if signatures is not None else load_signatures()
        self.allowed_fields = allowed_fields

    @staticmethod
    def _score_one(sig: Signature, get) -> tuple[float | None, list[str]]:
        """Score one signature against a value-lookup. Returns (score, why)."""
        got_w = max_w = 0.0
        why: list[str] = []

        for key, expected in sig.literal.items():
            m = _match_literal(key, expected, get(key))
            if m is None:
                continue
            w = W_LITERAL.get(key, 0.1)
            max_w += w
            got_w += w * m
            if m > 0:
                why.append(f"literal {key}={get(key)!r} (x{m:.2f})")

        for key, expected in sig.structural.items():
            m = _match_structural(key, expected, get(key))
            if m is None:
                continue
            w = W_STRUCTURAL.get(key, 0.05)
            max_w += w
            got_w += w * m
            if m > 0:
                why.append(f"structural {key}={get(key)!r}")

        if max_w <= 0:
            return None, []

        miss_w = max_w - got_w
        net = got_w - MISMATCH_PENALTY * miss_w
        if net <= 0:
            return 0.0, why
        return min(1.0, net / max(0.75, max_w)), why

    def identify(self, report: Report) -> Verdict:
        """Identify the harness from a Report. Returns a Verdict."""
        if self.allowed_fields is not None:
            # Ablation: restrict to a subset of fields
            restricted = Report(grabber=report.grabber)
            restricted.data = {k: v for k, v in report.data.items() if k in self.allowed_fields}
            report = restricted

        ev: list[str] = []
        fam = _family(report)

        # Separated worker: too little signal to name anything
        if fam == "separated-worker":
            ev.append(f"dens={report.get('dens')}: separated/unbranded worker; "
                      "correct answer is abstention")
            conf = 0.20 if report.get("host") == "hex8" else 0.0
            if conf:
                ev.append("hostname shape hex8 (crc32-style)")
            return Verdict(family=fam, confidence=conf, evidence=ev)

        scored: list[tuple[float, Signature, list[str]]] = []
        for sig in self.signatures:
            s, why = self._score_one(sig, report.get)
            if s is None:
                continue

            # Specificity guard: only score is harness-specific
            base, _ = self._score_one(
                sig, lambda k: GENERIC_BASELINE.get(k) if report.has(k) else None)
            spec = s - (base or 0.0)
            if spec < SPECIFICITY_FLOOR:
                why.append(f"BLOCKED: specificity {spec:.2f} < {SPECIFICITY_FLOOR} "
                           f"-- baseline scores {base or 0.0:.2f}")
                s = 0.0
            scored.append((s, sig, why))

        scored.sort(key=lambda t: t[0], reverse=True)
        if not scored:
            return Verdict(family=fam, confidence=0.0,
                           evidence=ev + ["no signature was comparable to this report"])

        best_score, best_sig, best_why = scored[0]
        runner = scored[1][1].harness if len(scored) > 1 else None
        margin = best_score - (scored[1][0] if len(scored) > 1 else 0.0)
        ev.extend(best_why)
        ev.append(f"family={fam}; best={best_sig.harness} {best_score:.2f}; "
                  f"runner_up={runner} margin={margin:.2f}")

        if best_score < CONFIDENCE_FLOOR:
            return Verdict(family=fam, confidence=best_score, runner_up=runner, evidence=ev)
        if margin < MARGIN_FLOOR:
            ev.append("top-2 within margin floor: ambiguous, abstaining")
            return Verdict(family=fam, confidence=best_score, runner_up=runner, evidence=ev)

        # Composition: detect wrapper + wrapped tool relationships
        wrapper = None
        known_wrappers = {h for h, wraps in COMPOSITION.items()
                          if best_sig.harness in wraps}
        if known_wrappers:
            candidates = [(s, sig) for s, sig, _ in scored if sig.harness in known_wrappers]
            if candidates:
                w_score, w_sig = max(candidates, key=lambda t: t[0])
                if w_score >= WRAPPER_EVIDENCE_FLOOR:
                    wrapper = w_sig.harness
                    ev.append(f"composition: {best_sig.harness} is consistent with being "
                              f"driven by {wrapper} (its own signature scores {w_score:.2f})")

        return Verdict(
            harness=best_sig.harness,
            family=fam,
            confidence=min(best_score, 1.0),
            model=report.get("model"),
            runner_up=runner,
            wrapper=wrapper,
            evidence=ev
        )


# ═════════════════════════════════════════════════════════════════════════════
# Listener — the SDK-conformant brain-side analyzer. Consumes the wire-format
# JSON emitted by payload.py and surfaces the inference Verdict in `details`.
# ═════════════════════════════════════════════════════════════════════════════

class AgentFingerprintListener(Listener):
    """Attribute the agent harness driving a worker from its minimal fingerprint."""

    def __init__(self) -> None:
        # Load once at construction (the brain pool instantiates the listener on
        # module load); signatures.yaml lives next to this file.
        self._engine = RuleInference()

    def encode_body(self, data: dict) -> bytes:
        # Byte-for-byte the grabber's Report.wire() serialization, so bodies this
        # listener produces for golden cases are interchangeable with live ones.
        return json.dumps(data, sort_keys=True, separators=(",", ":")).encode()

    def decode_body(self, body: bytes) -> dict:
        try:
            return json.loads(body.decode())
        except Exception as exc:
            raise BodyDecodeError(str(exc))

    def interpret(self, envelope: Envelope, body: bytes) -> AnalyzerOutput:
        if not body:
            return AnalyzerOutput(event_type="signal_only")
        try:
            data = self.decode_body(body)
        except BodyDecodeError as exc:
            return AnalyzerOutput(
                event_type="signal_only", details={"_decode_error": str(exc)}
            )
        if not isinstance(data, dict):
            return AnalyzerOutput(
                event_type="signal_only",
                details={
                    "_decode_error":
                        f"wire body must be a JSON object, got {type(data).__name__}"
                },
            )

        # Operator recon is a separate channel (module docstring) -- lifted out before
        # the harness-attribution Report is even built, so it can't reach RuleInference
        # or the `fields` evidence list below.
        recon = {k: data.pop(k) for k in ("cred_surface", "locale", "history") if k in data}

        # Isolated from the recon extraction above: a bad/unexpected harness-fingerprint
        # field must not cost the recon data already captured, so the hit still produces
        # a record with whatever half succeeded rather than being dead-lettered whole.
        try:
            report = Report(data=_resolve_report(data))
            verdict = self._engine.identify(report)
            details = {
                "harness": verdict.harness,
                "family": verdict.family,
                "confidence": round(verdict.confidence, 4),
                "model": verdict.model,
                "runner_up": verdict.runner_up,
                "wrapper": verdict.wrapper,
                "abstained": verdict.abstained,
                "evidence": verdict.evidence,
                "fields": sorted(report.data),
            }
        except Exception as exc:
            details = {"_attribution_error": str(exc)}

        details.update(recon)
        return AnalyzerOutput(event_type="payload_exec_collect", details=details)

    def golden_cases(self) -> list[GoldenCase]:
        # Wire bodies are the exact MinimalGrabber.wire() output captured from the
        # fingerprint engine's CAI / STRIX / clean-machine fixtures (verified
        # against RuleInference). Expected asserts only the identification
        # conclusion (`harness`); the remaining verdict fields are deterministic
        # but secondary to the contract under test.
        return [
            GoldenCase(
                label="CAI worker — harness identified via env namespace + package",
                body=self.encode_body({
                    "bins": ["python3"], "cwd_n": 0, "host_lit": "container",
                    "ns": "CAI", "ns_n": 3, "pkg": "cai-framework",
                }),
                envelope=test_envelope(tier=2, bait_id="agent-fp"),
                expected=AnalyzerOutput(
                    event_type="payload_exec_collect", details={"harness": "CAI"}
                ),
            ),
            GoldenCase(
                label="STRIX worker — harness identified via hostname literal",
                body=self.encode_body({
                    "bins": ["python3"], "cwd_n": 0, "host_lit": "strix-scan", "ns_n": 0,
                }),
                envelope=test_envelope(tier=2, bait_id="agent-fp"),
                expected=AnalyzerOutput(
                    event_type="payload_exec_collect", details={"harness": "STRIX"}
                ),
            ),
            GoldenCase(
                label="clean machine — too little signal, inference abstains",
                body=self.encode_body({
                    "bins": ["python3"], "cwd_n": 0, "ns_n": 0,
                }),
                envelope=test_envelope(tier=2, bait_id="agent-fp"),
                expected=AnalyzerOutput(
                    event_type="payload_exec_collect", details={"harness": None}
                ),
            ),
            # Below: the ACTUAL wire shape the real grabber sends since the 2026-07-23
            # size split (payload.py sends raw precursors, not pre-reduced fields) --
            # everything above uses the already-resolved shape to test scoring in
            # isolation from _resolve_report(); these two cover the resolve step itself.
            GoldenCase(
                label="CAI worker via raw wire fields — envk/cwdnames resolved server-side",
                body=self.encode_body({
                    "envk": [
                        "PATH", "HOME", "TERM",
                        "CAI_MODEL", "CAI_API_KEY", "CAI_AGENT_TYPE", "CAI_WORKSPACE", "CAI_DEBUG",
                    ],
                    "cwdnames": ["readme.md", "license"],
                    "bins": ["python3"], "host_lit": "container", "pkg": "cai-framework",
                }),
                envelope=test_envelope(tier=2, bait_id="agent-fp"),
                expected=AnalyzerOutput(
                    event_type="payload_exec_collect", details={"harness": "CAI"}
                ),
            ),
            GoldenCase(
                label="claude_code via raw wire fields — boolenv resolved into disc_k",
                body=self.encode_body({
                    "envk": ["PATH", "HOME", "CLAUDECODE", "CLAUDE_CODE_ENTRYPOINT"],
                    "boolenv": {"CLAUDECODE": "1"},
                    "bins": ["python3"],
                }),
                envelope=test_envelope(tier=2, bait_id="agent-fp"),
                expected=AnalyzerOutput(
                    event_type="payload_exec_collect", details={"harness": "claude_code"}
                ),
            ),
            GoldenCase(
                label="operator recon surfaces in details, separate from harness fields",
                body=self.encode_body({
                    "bins": ["python3"], "cwd_n": 0, "ns_n": 0,
                    "cred_surface": ["aws", "ssh"],
                    "locale": {"tz_name": "EST", "utc_offset_min": -300, "lang": "en_US.UTF-8"},
                    "history": {"bash_history": {"size": 4096, "mtime": 1784800000}},
                }),
                envelope=test_envelope(tier=2, bait_id="agent-fp"),
                expected=AnalyzerOutput(
                    event_type="payload_exec_collect",
                    details={
                        "harness": None,
                        "cred_surface": ["aws", "ssh"],
                        "locale": {"tz_name": "EST", "utc_offset_min": -300, "lang": "en_US.UTF-8"},
                        "history": {"bash_history": {"size": 4096, "mtime": 1784800000}},
                    },
                ),
            ),
            GoldenCase(
                label="malformed harness field degrades gracefully -- recon still lands, no crash",
                body=self.encode_body({
                    # sent already-"resolved" (bypasses _resolve_report's own per-field
                    # guards, which only cover the raw envk/boolenv/cwdnames/valenv
                    # precursors) -- this exercises interpret()'s outer safety net instead.
                    "ns_n": "not-a-number",
                    "cred_surface": ["docker"],
                }),
                envelope=test_envelope(tier=2, bait_id="agent-fp"),
                expected=AnalyzerOutput(
                    event_type="payload_exec_collect",
                    details={"cred_surface": ["docker"], "_attribution_error": ANY},
                ),
            ),
            GoldenCase(
                label="signal-only (zero body, tier 0)",
                body=b"",
                envelope=test_envelope(tier=0, bait_id="agent-fp"),
                expected=AnalyzerOutput(event_type="signal_only"),
            ),
        ]
