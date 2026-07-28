# hostname_grab_dns — hostname-beacon-dns end-to-end test

> **DNS sibling of `hostname_grab`:** same collected field (attacker hostname), same
> `staging_vessels/identity` NOP vessel, different wire channel — tier-0 DNS instead of tier-2
> HTTPS. `payload.py`/`listener.py` live in
> `../../../lure_material/payloads/hostname_grab_dns/` (see `lure_material/README.md`).
> `manifest.yaml`'s `payload_file`/`listener_class`/`staging_vessel` fields point there via
> plain `../`-relative paths, same mechanism `hostname_grab/manifest.yaml` uses.
>
> **Why this entry exists:** DNS tier-0 was non-functional end-to-end until 2026-07-14 — the
> SDK's `send_dns()` never built the mandatory DNS wire header (`ev|flags ‖ instance_token ‖
> session_id ‖ seq_no`, base32-packed across the beacon-name labels — see `edge/context.md`'s
> DNS projection spec) that `edge/receiver_dns.go` requires; it just fired an arbitrary
> sanitized string as a DNS label. See `src/blacksea/sdk/payload/dns.py` for the sender side of
> that header. This entry is both the fix's regression lock and the first
> real DNS-channel e2e test in the suite.

Demonstrates the full Blacksea pipeline for a tier-0 DNS bait:
`payload.py` → control-plane factory (bundle + stage) → `registry/artifacts/hostname-beacon-dns/…/bait.py`
→ edge (DNS) → NATS → brain → Postgres.

The bait packs `base32(header ‖ json-body)` across one or more beacon-name labels (`edge/context.md`'s
DNS projection, mode 1/2 — a single query, no reassembly) and fires it as a raw UDP DNS packet
straight at the dev edge's `DNS_ADDR` (`_DNS_SERVER`, since the test zone `cb.example.com` isn't
really delegated anywhere — see "Local testing vs. real deployment" below). Envelope
construction lives in `blacksea.sdk.payload.dns.send_dns` (inlined by the bundler) — pure
stdlib, no third-party DNS library, no `enc`/signature (tier-0 is unsigned by channel
definition).

The `blacksea` console is the single operator front door — bring the stack up, forge the bait,
and read the records all through the one command. (`make install` below is the only `make` step;
it just creates the venv that puts `blacksea` on your PATH.)

---

## Prerequisites

```
make install       # from services/  — creates .venv, installs the blacksea distribution
```

After this, `blacksea` is on your PATH (`.venv/bin`). `blacksea up`, used below, builds the edge
binary itself; its default `DNS_ADDR=:15353` / `DNS_ZONES=cb.example.com` are what this entry's
manifest targets.

---

## Local testing vs. real deployment

DNS is the one channel where "point the callback at 127.0.0.1" (as `hostname_grab`'s HTTPS
entry does) isn't enough — a DNS beacon only reaches the edge if either (a) the zone is really
delegated to the edge's public IP over DNS, so the attacker's OS resolver recurses there
naturally, or (b) something sends the query directly to the edge's address. Locally, neither the
`services/` repo nor `cb.example.com` provides (a), so this entry uses (b): `_DNS_SERVER` (a new
manifest build_var, `deploy.build_vars._DNS_SERVER: "127.0.0.1:15353"`) makes `send_dns` skip
`socket.getaddrinfo` and instead hand-roll a raw UDP DNS query straight at that address.

For a **real** deployment, drop `_DNS_SERVER`: pass `--set _DNS_SERVER=` (empty) at forge time,
delegate the real zone's NS records to the edge's public IP on port 53, and the payload's
`socket.getaddrinfo(qname, None)` fallback will resolve it exactly like a normal DNS lookup.

---

## Prepare a deployable instance (no trigger)

```
blacksea forge e2e_tests/hostname_grab_dns/manifest.yaml --callback dns=cb.example.com
```

Registers `hostname-beacon-dns`, builds a fresh per-instance artifact (real per-instance token;
DNS has no per-instance key — tier-0 is unsigned), and approves it — all in one step. Does
**not** run/trigger the payload. To fire it by hand afterwards, run the artifact `forge` printed
and read the record back with `blacksea events ls --bait hostname-beacon-dns`.

For the full automated fire-and-verify test, see below.

---

## Full E2E test

Tests the complete stack: bait fires → edge parses the DNS labels → NATS → brain interprets →
record in Postgres.

### One command

```
./e2e_test.sh
```

Brings up the dev stack if it isn't already (`blacksea up`), forges an
instance (register the design under campaign `e2e-test`, build, approve), waits for the edge and
brain to hot-swap in the new snapshot/key, triggers the payload, and polls Postgres until the
resulting record shows up (or fails after ~10s). Safe to re-run. Override the campaign with
`CAMPAIGN=my-campaign ./e2e_test.sh` or the zone with `./e2e_test.sh cb.mytest.invalid` (also
update the manifest's `deploy.callbacks.dns` if you do, so `DNS_ZONES` on the edge still matches).

### Step 4 — trigger the payload (the DNS-specific part)

Run the built artifact `forge` printed as `artifact:` (`blacksea instances artifact
<instance_token>` prints the exact path):

```
.venv/bin/python registry/artifacts/hostname-beacon-dns/<timestamp>/to_stage/bait.py
```
(from `services/`)

The payload collects the hostname, JSON-encodes it, builds the DNS wire header (`ev|flags(1B) ‖
instance_token(8B) ‖ session_id(8B) ‖ seq_no(2B)`), base32-encodes `header ‖ body` and splits it
across ≤63-char labels, then sends one UDP packet to `127.0.0.1:15353` (`_DNS_SERVER`) containing
a hand-built DNS A-query for `<labels>.cb.example.com`. No output on success — errors are
swallowed by design (same convention as the HTTPS payload).

### Step 5 — verify the record

Read it back with the console — newest first, filtered to this bait:

```
blacksea events ls --bait hostname-beacon-dns
blacksea events show <record_id>     # full record incl. details.hostname
```

`sig_valid` is always `false` for this record — DNS is tier-0 and unsigned by channel definition,
not a verification failure. `details.hostname` still carries the collected value, from
the observed-tier body the edge recovered from the beacon-name labels. Note the DNS caveat
(see `edge/context.md`'s DNS projection spec): `source_ip` here is the **resolver**, not the
attacker's client, since recursive DNS hides the original client IP. The dev edge answers the
beacon with a benign sink A-record either way, so the beacon resolves like an ordinary DNS lookup.

---

Done testing? `blacksea reset` clears the registry, keydirs, Postgres records, and NATS
backlog this walkthrough created, and `blacksea down` stops any processes still running.

---

## Files

| File | Role |
|---|---|
| `manifest.yaml` | Bait metadata; `payload_file`/`listener_class`/`staging_vessel` point into `lure_material/`; `build_vars` adds `_DNS_SERVER` alongside the standard `_ZONE`/`_TOKEN` |
| `e2e_test.sh` | Automated test: forges an instance (`CHANNEL=dns`), triggers the payload, verifies a record lands in Postgres. Picked up by `make test-e2e`. Sources `../lib.sh`. |

## SDK modules involved

| Module | Role |
|---|---|
| `blacksea.sdk.payload.dns` | `send_dns` — packs the DNS wire header + body, base32-encodes across labels, sends via a raw UDP query (`server` given) or the OS resolver (production) |
