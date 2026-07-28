# edge/ — Go dumb edge binary

**Status:** implemented.
**Language:** Go 1.22+
**Contracts:** the sensor→edge envelope wire format (frozen field set, assurance tiers,
versioning rule, replay/dedup tuple), the DNS and HTTPS channel projections, the edge's
crypto-passive validation scope, and the `QueuedEnvelope` the edge forwards to the single
`bait._ingest` subject — all specified in full below, so this file is readable without any other
design document. The edge holds **no** key directory of any kind (the dead-drop model): all
routing is resolved by the brain from the outer `tok` against its own (sole) key directory — see
`brain/context.md`.

> **On the `§1.x` citations** scattered through `edge/*.go` and `edge_test.go`: they are stable
> internal cross-reference labels inherited from a plan document that has since been retired, its
> content folded into this file. Read them as pointers to the matching material below — `§1.1`
> the frozen field set, `§1.2` routing/token resolution, `§1.3` assurance tiers, `§1.4` the
> encrypted core + AEAD, `§1.5` the channel projections, `§1.6` the versioning rule, `§1.7` the
> validation/publish pipeline, `§1.8` the replay/dedup tuple, `§1.9` observed source. There is no
> longer any external document to look them up in.

## Scope

The dumb internet-facing receiver — now a pure **dead-drop** (inv 3, revised: it once did a
cheap crypto pre-check and a routing-directory lookup; both are gone — the brain is the sole
cryptographic authority *and* the sole router). It holds **no** key directory of any kind and
derives **no** routing facts. It does exactly four things now:

1. Accepts DNS queries and HTTPS POSTs, and parses the minimal wire format (`ev`, `tok`, and the
   opaque `enc` blob — plus, for DNS tier-0, the unencrypted header fields).
2. Applies hard size + rate limits (and the tier-0 sample gate) before any heavy work — the DoS
   shield.
3. Stamps the `edge` group (`edge_recv_time`, `observed_source`, `edge_id`) — the only
   observed-tier facts in the whole record, appended outside the encrypted core (inv 17).
4. Forwards `enc` (tier ≥ 1) opaquely — and the DNS tier-0 fields — to the single NATS subject
   `bait._ingest` (under the `bait.>` namespace, so the stream + brain subscription are unchanged).

The edge never decodes `body`, never touches `enc` beyond forwarding it as opaque bytes, never
runs any per-bait logic, holds no key material, and — since the brain became the sole
cryptographic authority — never performs any cryptographic verification at all. It derives NO
routing facts (bait_id, campaign_id, assurance_tier, instance_status) from the token: the brain
resolves all of that from the outer `tok` against its own key directory — now the SOLE key
directory in the system — where it also holds the only copy of `_KEY` (the HMAC-SHA256 master
key). See `brain/context.md`.

## Envelope wire format

This is the logical envelope every sensor hit reduces to, regardless of channel. It is the
contract the edge's parsers, the `QueuedEnvelope` it publishes, and the brain's decoder all
share.

### Frozen field set

| Field | Group | Signed/authenticated | Wire location | Purpose / invariant |
|---|---|---|---|---|
| `ev` envelope_version | outer + encrypted-core | yes (inner copy is authoritative) | top-level `ev`; also inside the encrypted core | schema/version; additive-only routing |
| `instance_token` (`tok`) | outer | no | top-level `tok` | master lookup key: brain-side key-directory lookup → `_KEY`, bait_id, campaign_id, assurance_tier |
| `session_id` | encrypted-core | encrypted | inside `enc` (AEAD plaintext) | intra-sensor session correlation |
| `seq_no` | encrypted-core | encrypted | inside `enc` (AEAD plaintext) | event order within a session; 0 = single-shot tripwire |
| `sensor_time` | encrypted-core | encrypted | inside `enc` (AEAD plaintext) | sensor-claimed time — claimed-tier, never trusted like `edge_recv_time` |
| `body` | encrypted-core | encrypted | inside `enc` (AEAD plaintext) | the bait's private payload; may be empty |
| `enc` | ciphertext | n/a | top-level `enc`; omitted for tier-0 | HMAC-SHA256-AEAD(nonce ‖ ciphertext ‖ tag) over the fixed binary encrypted-core, with `tok` bound into the tag |
| `bait_id` | derived | n/a | never transmitted | derived **by the brain** from `tok` via its key directory; the brain routes on this (never the edge) |
| `campaign_id` | derived | n/a | never transmitted | derived **by the brain** from `tok`; compartment scope |
| `channel` | derived | n/a | edge-set on the `QueuedEnvelope` | authoritative value = the edge receiver that actually handled the hit; the brain uses it to pick tier-0 vs tier≥1; the brain keydir's `default_channel` is for anomaly detection only |
| `assurance_tier` | derived | n/a | never transmitted | derived **by the brain**: tier-0 vs tier≥1 from the delivery channel (DNS ⇒ tier-0), the record's authoritative value taken from the key-directory entry |
| `edge_recv_time` | edge | no | inside `edge` group | edge-stamped receive time — observed-tier, trusted (sensor cannot forge it) |
| `observed_source` | edge | no | inside `edge` group | edge-stamped src IP / TLS-JA3 — observed-tier |
| `edge_id` | edge | no | inside `edge` group | which edge node received the hit |

**Frozen rules:** the field set is additive-only forever; group membership never changes; the
encrypted core is always `{ev, session_id, seq_no, sensor_time, body}` packed into a fixed
binary layout, then HMAC-SHA256-AEAD sealed. The edge only ever sees `ev`, `tok`, and the opaque
`enc` blob (plus, for DNS tier-0, the unencrypted header fields — see below); everything in the
encrypted core is invisible to it by construction, not by policy.

### Assurance tiers

| Tier | Name | Outer | encrypted-core | `enc` | `body` | Typical channel | Trust |
|---|---|---|---|---|---|---|---|
| 0 | signal-only | `{ev, tok}` | `{ev, session_id, seq_no, sensor_time}` (cleartext) | — (omitted) | — | DNS | observed-tier only |
| 1 | authenticated-signal | `{ev, tok, enc}` | `{ev, session_id, seq_no, sensor_time}` | present | — | HTTPS/TCP | + confidentiality + authenticity |
| 2 | full-payload | `{ev, tok, enc}` | `{ev, session_id, seq_no, sensor_time, body}` | present | present | HTTPS/TCP | + rich claimed-tier intel |

Tier 0 is unencrypted by definition and rides the rate-limit + sample gate (never fully
persisted by itself, inv 6). **DNS is the sole tier-0 channel** — HTTPS has no unencrypted form:
every HTTPS hit is tier ≥ 1 and always carries `enc` (`receiver_https.go` rejects an empty-`enc`
POST outright rather than forwarding it; the old plaintext HTTPS tier-0 fallback was removed).

### Versioning rule

`ev` is a uint8 schema version, present in every projection. It is **additive-only forever**: a
new `ev` may only add new optional fields or new flag/enum values — it may never remove, rename,
renumber, or repurpose an existing field, or change a field's group/signed status. Both ends
must be able to parse all historical versions: an unknown-but-newer `ev` from an old edge should
in principle pass through for the brain to handle; unknown fields are preserved (forward-compat);
fields introduced by a newer version are treated as absent/default when read by older code
(backward-compat). In practice the edge currently enforces a tight allowlist rather than the
full pass-through rule — see "Two judgment calls" below.

### Replay / dedup

The dedup key is `(instance_token, session_id, seq_no)` — distinct from the per-message AEAD
`nonce` inside `enc` (the nonce prevents keystream reuse; the dedup tuple prevents double-
counting a legitimate resend). Dedup happens consumer-side, in the brain, not at the edge: a
replayed encrypted hit re-presents the same tuple and is counted once, with the surplus dropped
(but still logged as a replay signal). Tier-0 unencrypted replay is cheap but bounded by the
rate-limit + sample gate; it can't poison correlation because tier-0 is observed-tier-only and
never anchors an actor edge.

## Channel projections (sensor → edge wire formats)

Both projections below reconstruct the same logical envelope above — a DNS tier-0 hit and an
HTTPS tier-2 hit for the same session differ only in which fields are present vs. derived vs.
absent.

### HTTPS projection (tiers 1–2)

`Content-Type: application/json`. The sensor POSTs `{ev, tok, enc}`:

```json
{
  "ev": 2,
  "tok": "9f86d081884c7d65",
  "enc": "AhZ9k2...base64url(nonce(12B) ‖ HMAC-SHA256-AEAD ciphertext ‖ tag(16B))..."
}
```

The edge appends the `edge` group (`recv_time`, `source: {ip, ja3, source_type}`, `edge_id`)
before publishing — the sensor never sends it. `bait_id`/`campaign_id`/`channel`/
`assurance_tier` are never transmitted. `body` (when present) lives inside `enc`. The edge reads
only `ev` + `tok`; it never touches `enc` beyond forwarding it verbatim
(`httpsEnvelope` in `receiver_https.go` has exactly these three fields — no `body` field exists
at this layer). HTTPS has no unauthenticated form: a POST with an empty `enc` is dropped, not
forwarded — this also closes an injection vector where a bare `tok` sniffer could otherwise mint
attacker-chosen tier-0 records.

### DNS projection (tier 0, signal-only) — three modes

Beacon name: `<base32(header ‖ payload)>.<canary-zone>`, using standard base32 (5 bits/char,
DNS-safe, case-insensitive — the edge upper-cases labels before decoding). One DNS label is
≤ 63 chars, i.e. 39 usable payload bytes once base32-expanded.

Every DNS query carries this mandatory 19-byte header, packed ahead of any payload bytes:

```
[ev:4 | flags:4](1B) ‖ instance_token(8B) ‖ session_id(8B) ‖ seq_no(2B)   =  19 B
```

`ev` occupies the high 4 bits of byte 0; `flags` the low 4 bits. Flag bit 0 (`LAST`) marks the
last chunk of a DNS sequence (mode 3 below); bits 1–3 are reserved, must be zero when sent, and
are ignored on read. Everything else — bait_id, campaign_id, assurance_tier (always 0 on this
channel) — is derived **by the brain** from `instance_token`, never carried on the wire; `channel`
is set to `dns` by the edge (which receiver handled the hit) and forwarded on the `QueuedEnvelope`.
The edge still stamps `edge_recv_time` + `observed_source`, but on DNS the observed
source is the **recursive resolver's** IP, not the attacker's client (recursive DNS hides the
true client) — so DNS's `observed_source` is weaker-observed-tier than HTTPS's, and
`ObservedSource.SourceType` is set to `"resolver"` rather than `"client"` so the brain can weight
it accordingly.

Free budget after the header is 20 bytes (160 bits) per single-label query:

- **Mode 1 — single query:** `label = base32(header[19B] ‖ payload[≤20B])` → ≤ 63 chars, one
  lookup.
- **Mode 2 — multi-label query** (~110B free, still one round-trip): additional data labels
  before the zone, e.g. `base32(chunk1) . base32(chunk2) . ... . <zone>`, up to the ≤ 253-char
  total name limit. No cross-query reassembly is needed — the edge decodes every data label of
  a single query independently and concatenates the raw bytes before the zone boundary. **Label
  boundaries must fall on base32 group boundaries** (a multiple of 8 encoded chars / 5 raw
  bytes) since each label is decoded as an independent base32 string, not sliced out of one
  continuous encoded stream — `receiver_dns.go`'s `parseDNS` chunks at 39 raw bytes per label
  (the largest chunk whose base32 form is still ≤ 63 chars) for exactly this reason. (An earlier
  version of the SDK sender chunked the encoded string at 63 chars instead of the raw bytes at
  39, which silently corrupted any payload spilling past one label; fixed 2026-07-14 in
  `src/blacksea/sdk/payload/dns.py`, regression-locked by `e2e_tests/hostname_grab_dns/`.)
- **Mode 3 — DNS sequence** (bulk fallback when HTTPS is blocked): one query per chunk, `seq_no`
  increments per query, the last query sets `LAST=1`. Reassembly keys on
  `(instance_token, session_id)` + `seq_no`. See "Two judgment calls" below — this is done in
  the **brain**, not the edge, despite an older design note suggesting the edge would reassemble.

Effective DNS throughput is roughly 20×N bytes across N queries.

## Edge validation scope (revised — the edge is fully crypto-passive and holds no directory)

The edge does ONLY the following per hit:

1. Check `ev` is a known version; the projection parses to the routing-critical subset (`tok`,
   and for DNS tier-0 the packed header fields).
2. Enforce size + rate caps (hard, pre-parse, before touching the body/labels) plus the tier-0
   sample gate.
3. Forward `enc` opaquely — never attempt decryption. For tier-0 unencrypted hits (DNS), carry
   the header-derived fields (`session_id`, `seq_no`, `flags`, `obs_body`) instead.
4. Stamp the `edge` group (`recv_time`, `observed_source`, `edge_id`).
5. Publish to the single queue subject `bait._ingest`.

The edge never: looks up a directory (it holds none), derives any routing fact (bait_id/
campaign_id/assurance_tier/instance_status), decodes `body`, touches `enc` beyond forwarding it,
runs per-bait logic, or performs any cryptographic verification. It forwards **every** well-formed
hit regardless of token — the brain resolves the token against its own key directory and decides
routable vs. orphan (an unknown/malformed `tok` maps to `""` and dead-letters at the brain). The
brain is the sole verifier and the sole router now. Kept at the edge: the `ev` allowlist, the
size+rate+sample DoS shield, the empty-`enc` HTTPS drop (shape validation), and the edge stamp.

## Scope boundary (what this module is NOT)

- Not a brain: no interpretation, no record assembly, no storage writes.
- Not a control plane: no registry access, no lifecycle commands.
- Not a router: the edge holds **no** key directory of any kind and resolves nothing from `tok`
  — the brain does all routing. With nothing to distribute to the edge, the diode is intact by
  construction (inv 2, inv 18): there is no edge-facing distribution channel at all.

## Plan

Build order:

1. `envelope.go` — logical envelope types; stamp logic for the `edge` group; the `QueuedEnvelope`
   edge→brain message.
2. `ratelimit.go` — per-IP + global rate limiter + size cap (pre-parse, hard limits) + tier-0
   sample gate.
3. `receiver_https.go` — HTTPS projection parser (see "Channel projections" above); parses
   `ev` + `tok` (`decodeToken` lives here), forwards `enc` opaquely, stamps edge, publishes;
   rejects an empty-`enc` POST.
4. `receiver_dns.go` — DNS projection parser (modes 1–2, above); parses the packed header, stamps
   edge, carries the tier-0 header fields, publishes. Uses `miekg/dns`.
5. `queue.go` — NATS JetStream publisher; publishes to the single `bait._ingest` subject.
6. `core.go` — `Edge` struct bundling shared deps (limiter, sampler, publisher, metrics) that
   both receivers use; minimal named-counter metrics. No key directory — the edge holds none.
7. `main.go` — wires everything together; config is loaded by `config.go` (`loadConfig`).
   **Runs directly on the host** (systemd/process supervisor), no container — a deliberate
   decision. No `Dockerfile`.

### Edge→brain queue message (`QueuedEnvelope`, defined in `envelope.go`)

The edge publishes a normalised JSON `QueuedEnvelope` to the single subject `bait._ingest` —
**not** one of the locked sensor→edge wire projections above. It carries only what the edge can
see without a key or a directory: `ev`, `channel` (which receiver handled the hit),
`instance_token` (`tok`, opaque to the edge), the opaque `enc` material forwarded **verbatim**
(HTTPS/tier≥1 only — the brain decrypts it against its own key directory; the edge has no key to
do so), the DNS-derived tier-0 per-hit fields (`session_id`, `seq_no`, `flags`, `obs_body`), and
the `edge` group. It carries **no** routing or trust facts — no `bait_id`, `campaign_id`,
`assurance_tier`, `instance_status`, `revoked`, `orphan`, or `sig_valid` — the brain derives every
one of those from `tok` against its own key directory. The edge never decodes `enc`/`body`. HTTPS
is always tier≥1/encrypted — an empty-`enc` POST (the old plaintext tier-0 fallback) is rejected,
not forwarded. Hits with an unknown/malformed `tok` are forwarded like any other well-formed hit;
the brain maps `tok`→`""` and dead-letters them (orphan handling is brain-side now — there is no
separate `bait._orphan` subject).

### Two judgment calls (deviations from a literal reading of the original design doc)

- **DNS sequence (mode 3) reassembly is done in the brain, not the edge.** A literal reading of
  the DNS projection design says "the edge reassembles" a mode-3 sequence, but that requires
  per-`(instance_token, session_id)` state, which conflicts with the stronger locked **inv 3**
  (stateless dumb edge). The edge therefore forwards each chunk independently carrying `seq_no`
  + the `LAST` flag + its payload bytes; the brain reassembles using the dedup tuple
  (`instance_token`, `session_id`, `seq_no`) it already holds state for. Modes 1–2
  (single-query, possibly multi-label) are fully handled at the edge since they need no
  cross-query state.
- **Unknown `ev` is logged + dropped at the edge, not passed through.** `main.go`'s `knownEV`
  allowlist is `{1: true, 2: true}` — `ev=2` (the HMAC-SHA256 AEAD envelope, landed 2026-07-14,
  see `src/blacksea/brain/context.md`'s security rationale note) was added alongside `ev=1`, consistent with the
  additive-only versioning rule above (neither version is ever removed). The edge still does not
  interpret either version's `enc` — this allowlist only gates the routing-critical fast-parse
  check (step 1 of "Edge validation scope"). The versioning rule's "pass unknown-but-newer `ev`
  through for the brain" ideal remains unimplemented here — a true `ev=3` would still be logged
  + dropped at the edge today; revisit if that's needed.

Exit criterion: hand-craft a tier-2 HTTPS POST encrypted with a test `_KEY`; it hits
the edge and is forwarded opaquely (the edge does not decrypt — that happens in the brain)
to `bait._ingest`, and the `edge` fields appear on the queued NATS message. Then fire a DNS
beacon; it arrives in the queue carrying its header fields (`session_id`/`seq_no`/`flags`/
`obs_body`) + the edge stamp — the brain fills in the routing facts from `tok`.

## Note on routing (formerly a routing key-directory snapshot)

The edge holds **no** key directory and derives **no** routing. All routing is resolved by the
brain from the outer `tok` against its own (sole) key directory — see `brain/context.md`
(`verifier.bait_id_for` / `verify` / `instance_status_for`). The prior edge-facing routing
directory — a signed `snapshot.json` (deterministic CBOR + Ed25519 over a `dirsign` key, with
anti-rollback `seq` + freshness `expires_at` + pinned-key rotation) and the flat `keydir.json`
stub it replaced — **no longer exists**. The whole snapshot/signing apparatus, the `dirsign` key,
and the per-status *edge* routing table were deleted with the dead-drop change: the edge forwards
every well-formed hit to `bait._ingest` regardless of instance status, and the brain applies all
status logic (`orphan`/`burned`/`retired`/`revoked`) from its own key directory. Revocation now
propagates via the brain's key-directory poll, not an edge poll.

## BAITS stream disk caps

`queue.go`'s `NewNATSPublisher` provisions the shared `BAITS` JetStream stream (subjects `bait.>`)
via `CreateOrUpdateStream` using the config built by **`baitsStreamConfig`** (split out so the exact
limit fields live in one place and are unit-tested by `queue_stream_test.go` without a live NATS).
The stream is bounded on two dimensions — **`MaxBytes`** (disk cap, `NATS_MAX_BYTES`, default 1 GiB)
and **`MaxAge`** (age cap, `NATS_MAX_AGE_S`, integer seconds, default 604800s = 7 days) — with
`Discard: DiscardOld` so a full stream trims its **oldest** messages instead of rejecting new
publishes. Retention stays `LimitsPolicy`; storage stays `FileStorage`. `NATS_MAX_AGE_S` is parsed
as an **integer** on both sides (Go `ParseInt`, Python `_int`) so a fractional value can't be honored
by one provisioner and silently rejected→defaulted by the other; the Go conversion also guards
against `int64` overflow in the `×time.Second` multiply (`durationSecondsOr`).

Residual risk of the cap-based approach (vs `WorkQueuePolicy`): `DiscardOld` drops the oldest
messages, which in steady state are already consumed (the brain persists to Postgres in
near-real-time) but during a **flood that outpaces the consumer** can include legitimate
not-yet-consumed hits. Bounding disk is worth that trade; a consumer lag/drop alert is a
production-hardening follow-on.

Why this is mandatory, not a tuning knob: under `LimitsPolicy` a consumer ack does **not** evict a
message — only a size/count/age limit can. Without a cap the stream is an append-only log of every
hit ever published, bounded only by host disk, and the edge's own beacon endpoints let an
**unauthenticated** party (no key, no valid `tok`, no NATS credential) publish one permanent message
per request before any brain-side validation — an unbounded disk-exhaustion DoS. The per-stream caps
here are the primary fix; `scripts/nats-server.conf`'s server-level `max_file_store` is a hard
backstop under them — **env-overridable** via `$NATS_MAX_FILE_STORE` (docker-compose passes it,
default 4GB) so it can be raised in lockstep with `NATS_MAX_BYTES`. That coupling is load-bearing:
`max_file_store` MUST stay above the per-stream `MaxBytes`, or NATS rejects stream creation and the
edge exits — raising `NATS_MAX_BYTES` past 4GB without also raising `NATS_MAX_FILE_STORE` takes the
edge down.

These two defaults **MUST** equal the brain's `settings.NATS_MAX_BYTES` / `NATS_MAX_AGE_S`
(`_baits_stream_config` in `src/blacksea/brain/pool.py`) — both sides provision the same stream, and
`CreateOrUpdateStream` re-applies the edge's caps on every edge start, so a mismatch means whichever
side runs last silently re-widens the stream. `0` for either dimension is the "unbounded" escape
hatch (reopens the gap — not recommended). Setting these was a deliberate reversal of the edge's
former "retention is a brain/control-plane policy; edge does not bound it" stance: the edge now
bounds it too (defense in depth), since it is the reachable, unauthenticated publish path.

## Authentication to NATS

The edge authenticates to NATS with a username/password (`NATS_USER` / `NATS_PASS`, both
**required** — `NewNATSPublisher` refuses to connect if either is empty; there is no anonymous
fallback). Credentials are passed as separate process env vars, never embedded in `NATS_URL`, so
they cannot leak into the URL the edge logs on a connection error. Locally they come from
`config/blacksea.env` (`make init`) and are wired by `blacksea up` (which runs the edge as a dumb
dead-drop forwarding to `bait._ingest`).

### HARDENING (not yet built) — edge is publish-only on `bait._ingest`  ← important

The edge is the internet-facing, least-trusted node (inv 2/3). The single shared NATS credential
used today is the minimal "no anonymous access" step, **not** the end state. At the hardening
milestone, split the NATS users so the **edge credential can only _publish_ to the single subject
`bait._ingest` and cannot subscribe to anything** — if the edge box is compromised, the attacker
must not be able to read (exfiltrate) honeypot telemetry off the queue or observe the brain's
traffic. Now that the edge is a dead-drop forwarding to exactly one subject, this ACL is simpler
than before: a single publish grant, no `bait.>` wildcard. Forged publishes are already
neutralised downstream (the brain re-verifies + decrypts every hit against its own key, inv 13),
so locking the edge to publish-only closes the remaining read-side exposure. This requires
per-role NATS users plus JetStream `$JS.API.>` / `_INBOX.>` ACL tuning (the PubAck path), which is
why it is deferred to a change that can be tested end-to-end rather than folded into the initial
auth wiring. The shared NATS config lives in `scripts/nats-server.conf`.

## Dependencies

- `miekg/dns` — DNS server + query parsing
- `nats.io/nats.go` — NATS client
- Standard library: `net/http`, `encoding/binary`, `log/slog`, `crypto/tls` (`main.go`, to
  terminate the HTTPS listener's own transport-layer TLS when `TLS_CERT`/`TLS_KEY` are set — this
  is unrelated to sensor-payload crypto). Beyond that TLS termination, the edge imports **no
  crypto** for sensor traffic (the brain is the sole decryptor) or a directory signature (there is
  no directory to verify). The prior `crypto/ed25519` (directory-signing snapshot verification)
  and `fxamacker/cbor` (signed-span decode) dependencies were both removed with the dead-drop
  change; earlier still, `crypto/ed25519` had been used in `receiver_https.go` for per-sensor
  signature verification, also long gone. (`go.mod`/`go.sum` carried `fxamacker/cbor` as a stale,
  unused direct dependency for a while afterwards; `go mod tidy` has since dropped it.)
- No dependency on any other module in this codebase (Go binary is self-contained).

## Invariants enforced here

- inv 2: edge is internet-facing; brain is not reachable from the edge.
- inv 3 (revised): dumb edge — no per-bait logic, no body decode, no interpretation, **no key
  directory, no routing derivation**, and (since the brain became the sole cryptographic
  authority) no cryptographic verification of sensor traffic at all. The edge is a pure dead-drop.
- inv 4: one fixed set of receivers shared by all baits; adding a bait never changes the edge.
- inv 6: tier-0 unencrypted traffic → rate-limit + sample gate; never fully persisted by itself.
- inv 7: sensors are outbound-only → edge only accepts inbound; it never initiates connections
  to sensors.
- inv 9 (revised): per-instance HMAC-SHA256 key `_KEY` — the edge never holds it; only `tok`
  crosses the wire in the clear, and only the brain resolves `_KEY` from it, via the brain's own
  key directory — now the sole key directory in the system (see `brain/context.md`).
- inv 13 (revised): the edge no longer verifies anything — it forwards `enc` opaquely. The
  brain is now the **sole** decryptor; there is no "edge's accept" to be a non-final word about.
- inv 18 (trivial now): the edge holds no directory, so there is nothing to distribute to it and
  no reverse-dead-drop poll — the diode is intact by construction. The brain's key directory (the
  sole directory) is populated directly by the factory at build time and never crosses the
  edge-facing diode.

## File list

| File | Description |
|---|---|
| `go.mod` / `go.sum` | Module `blacksea/edge`; deps `miekg/dns`, `nats-io/nats.go` (no crypto/CBOR deps — dead-drop) |
| `main.go` | Entry point: wiring receivers + NATS + rate limiter (config from `config.go`); host run + graceful shutdown. No key directory — the edge holds none |
| `config.go` | The edge's single config surface: `config` struct + `loadConfig` (moved out of `main.go`), reading every env var — listen addrs, `NATS_STREAM` (default `BAITS`, was `BAIT`, to match the brain), `NATS_MAX_BYTES`/`NATS_MAX_AGE_S` (BAITS-stream disk caps, must match the brain), HTTP server/shutdown timeouts, and the `RL_*` rate-limit tunables. Go-side mirror of `blacksea.config.settings` (which the Go edge cannot import). The snapshot/keydir/dirsign env vars (`SNAPSHOT_FILE`, `SNAPSHOT_POLL_S`, `SNAPSHOT_SEQ_FILE`, `KEYDIR_FILE`, `DIRSIGN_PUBKEYS`) were **removed** with the dead-drop change; the ingest subject is the `ingestSubject` const in `queue.go`, not an env var |
| `core.go` | `Edge` struct (shared deps — limiter, sampler, publisher, metrics; no key directory) + `publish` helper + minimal named-counter metrics |
| `envelope.go` | Logical envelope types + `edge` group stamp + the `QueuedEnvelope` edge→brain message (no routing/trust facts — see "Edge→brain queue message" above) |
| `receiver_https.go` | HTTPS POST handler: parse JSON envelope (`ev`+`tok`; `decodeToken` lives here now), forward `enc` opaquely (no verification), stamp, publish; rejects an empty-`enc` POST — HTTPS is always tier≥1/encrypted now, the plaintext tier-0 fallback was removed |
| `receiver_dns.go` | DNS query handler: parse packed header/labels (modes 1–2), carry the tier-0 fields, stamp, publish; answers a sink record. Derives no routing (the brain does) |
| `ratelimit.go` | Per-IP + global token-bucket rate limiter; hard size cap (pre-parse); tier-0 sample gate; per-source `IdleEviction` of stale buckets; `RateLimitConfig` tunables wired from env via `config.go` |
| `queue.go` | NATS JetStream publisher: publishes every hit to the single `ingestSubject` (`bait._ingest`) const; provisions the `BAITS` stream via `baitsStreamConfig` with `MaxBytes`/`MaxAge` disk caps; `Publisher` interface for tests |
| `queue_stream_test.go` | Locks `baitsStreamConfig`: asserts the `BAITS` stream carries a positive `MaxBytes`/`MaxAge` + `DiscardOld` (disk-exhaustion regression guard); mirror of `tests/brain/test_stream_config.py` |
| `edge_test.go` | Exit-criterion tests: encrypted tier-2 HTTPS (forwarded opaquely, never verified) + DNS beacon → the single `bait._ingest` subject; rate limit, sampler, empty-`enc` drop, out-of-zone |
