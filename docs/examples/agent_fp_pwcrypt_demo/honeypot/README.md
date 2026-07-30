# A demo honeypot in a Docker container

This is the throwaway honeypot used by the [basic usage tutorial](../../../basic_usage_tutorial.md) — somewhere to *stage* the bait forged from [`../manifest.yaml`](../manifest.yaml) and watch it fire, without needing a spare machine.

The container masquerades as a CI secrets-sync agent ("vaultkeeper", node `ci-sync-03`) with the **pwcrypt** password-vault bait pre-staged, wrapping the **agent_fp** harness-fingerprint payload. An attacker — or an autonomous LLM agent — that lands in the box finds a real, working `pwcrypt` decryptor next to an encrypted `secrets/github.pwc` vault and a shell-history hint giving away the vault password. Running `./pwcrypt_linux_<arch> decrypt secrets/github.pwc 'tarvuk-Zynhib-3wexfo'` looks like a routine secret read — it prints the vault's genuine decoy contents — but the vault's forged metadata overwrites an integrity-check function pointer with the address of `system`, and the KDF params field smuggles the bundled payload command past the parser, so the payload runs as an invisible side effect. `agent_fp` then fingerprints whatever harness is driving the intruder and beacons it to your edge.

It also has a **network face**: a "sync status" service that leaks the vault, the decryptors, and the password hint over HTTP, so the bait can be stolen and fired off-box.

Everything runs from one script: `./run.sh`.

## What it does

`./run.sh` (default subcommand `up`) drives the whole pipeline:

1. **Brings up the stack** — `blacksea up` (edge + brain + Postgres + NATS).
2. **Forges a fresh bait instance** from `../manifest.yaml`, with the HTTPS callback overridden to `http://host.docker.internal:8443` so a beacon fired from inside the container reaches the edge running on your host. This bakes a unique instance token + key into a freshly forged payload.
3. **Builds the honeypot image** — copies the forged artifact into a believable filesystem under `/srv/vaultkeeper`, plus a runbook, an MOTD, and a shell history that all point at the decrypt command.
4. **Runs the container** detached, publishing its sync status service on `127.0.0.1:8080`.
5. **Verifies the leak is reachable** from the host — `GET /healthz` and `GET /debug/secrets/github.pwc`.
6. **Triggers the bait** inside the container — `./pwcrypt_linux_<arch> decrypt secrets/github.pwc 'tarvuk-Zynhib-3wexfo'`, exactly as an attacker would after reading the runbook.
7. **Verifies the beacon landed** — polls for the decrypted record tied to this instance's token.

On success you get the decrypted decoy secret (what the "attacker" sees) and the stored fingerprint record (what you, the defender, see).

## Prerequisites

- **Docker** — Docker Desktop on macOS, or `dockerd` on Linux. On macOS `host.docker.internal` is built in; on Linux the script passes `--add-host=host.docker.internal:host-gateway` so it resolves there too. Docker is also needed **at forge time**: pwcrypt builds its Linux binaries inside per-arch Alpine containers.
- **`make install`** already run in `services/`, so the `blacksea` console exists. The script checks and tells you if it's missing.

### Multi-platform binaries

The manifest omits `build.target_arch`, so pwcrypt builds every binary the forge host can produce: on a **Linux** host, `pwcrypt_linux_amd64` + `pwcrypt_linux_arm64`; on a **macOS** host, those two plus a `pwcrypt_macos` universal binary.

The single forged vault carries one candidate exploit address per binary, so whichever one someone runs fires the same bait. The web app publishes **all** of them, so an intruder on any OS/arch pulls the decryptor that matches their machine. (amd64 Linux binaries build on an arm64 host through emulation and are slower.)

The container image itself is built for the **host-native Linux platform**. The in-box trigger and the on-box dressing use that platform's binary: `dressing/` carries a `{{PWCRYPT_BIN}}` placeholder that `run.sh` renders into `_dressing/` before the build, so the MOTD, runbook and shell history always name a binary that actually runs inside the box. That's realistic for a real node too — its cache holds every release platform, but its own commands use the native one.

## Usage

```
cd docs/examples/agent_fp_pwcrypt_demo/honeypot
./run.sh            # build + run + trigger + verify (default)
./run.sh shell      # drop into the running honeypot and explore it as an attacker would
./run.sh trigger    # re-fire the bait inside the running container and verify again
./run.sh logs       # tail the container
./run.sh clean      # stop + remove the container and image, drop the build context
```

Override the campaign with `CAMPAIGN=my-campaign ./run.sh`.

Read the collected intel back through the console (from `services/`):

```
blacksea events ls        # the beacon record(s), campaign 'demo-agent-fp'
```

## The leaked "secret" over HTTP

The box has a network face: a stdlib-only `vaultkeeper` sync status service (`dressing/serve.py`, installed to `/opt/vaultkeeper/serve.py`) published on `127.0.0.1:8080`. It leaks the staged bait the way a misconfigured node would — a plain directory mirror of the secrets cache under `/debug/`, carrying every per-platform `pwcrypt` decryptor, the encrypted vault, and the sync-agent history (which reveals the master password).

| route | what it is |
| --- | --- |
| `/` | compact JSON node banner — no endpoint tour, never mentions `/debug/` |
| `/healthz` | ordinary health check (`{"status":"ok"}`) |
| `/v1/sync/status` | cache state; on a debug node one of its fields is `debug_bundle: /debug/` |
| `/robots.txt` | `Disallow: /debug/` — the classic breadcrumb |
| `/debug/` | autoindex of the cache directory: the decryptors, `README.md`, `secrets/` |
| `/debug/pwcrypt_linux_amd64`, `…_arm64`, `/debug/pwcrypt_macos` | the decryptor for each staged platform |
| `/debug/secrets/` | autoindex of the cache itself |
| `/debug/secrets/github.pwc` | **the "secret"** — the RCE-armed vault |
| `/debug/secrets/.bash_history` | the sync-agent history — reveals the master password |

Nothing served explains itself: the listings are bare `Index of …` autoindexes (no CSS, no headings beyond the stock `<h1>`, no example commands, no warnings), the JSON is compact, and the `Server:` header is the product token, never `SimpleHTTP/… Python/…`. The story — why the vault is here, what the password is, what the debug flag does — lives only in the on-box dressing (`motd`, `RUNBOOK.md`, `~/.bash_history`), where a real operator would have written it. A visitor concludes "someone misconfigured a node" from the bare fact of the exposure. The URL layout mirrors the on-disk layout, so `wget -r` reproduces the `secrets/` path the trigger command expects.

The `/debug/` mount is gated on `VAULTKEEPER_DEBUG_BUNDLE=1` (set in the `Dockerfile`), so the leak has an in-fiction *cause* — a debug flag left on where it shouldn't be, which `RUNBOOK.md` even warns against. Set it to `0` and the whole prefix 404s, `/v1/sync/status` reports `"debug_bundle": null`, and the box is a pure filesystem lure again.

Steal it the way an intruder would (pick the decryptor for your platform):

```
curl -s http://127.0.0.1:8080/v1/sync/status                     # -> "debug_bundle":"/debug/"
curl -s http://127.0.0.1:8080/debug/                             # -> the listing
curl -sO http://127.0.0.1:8080/debug/pwcrypt_linux_arm64
curl -sO http://127.0.0.1:8080/debug/secrets/github.pwc
curl -s  http://127.0.0.1:8080/debug/secrets/.bash_history       # master password is in here
chmod +x pwcrypt_linux_arm64
./pwcrypt_linux_arm64 decrypt github.pwc 'tarvuk-Zynhib-3wexfo'  # <- fires the bait, wherever you are
```

**This is the point of the HTTP surface:** the bait no longer has to fire inside the honeypot. Whoever pulls the bundle runs `pwcrypt` on *their own* machine, and the agent_fp beacon reports *their* fingerprint. Every pull is logged to `docker logs` (`./run.sh logs`):

```
[audit] BUNDLE FETCH src=172.17.0.3 path=/debug/secrets/github.pwc bytes=3577 ua="Python-urllib/3.11"
```

One caveat if you exercise this off-box: the callback is baked in at forge time as `http://host.docker.internal:8443`, which only resolves inside Docker. To have a stolen copy beacon from somewhere else, forge with a callback that machine can reach.

`serve.py` is written entirely in-fiction, with no mention of Blacksea or the bait — an attacker who lands in the box can read it. The honeypot framing lives in the `Dockerfile` and this README, neither of which ships into the image. Its routes are an explicit allowlist with no request-controlled path joining, so the only intended vulnerability here remains the one in `pwcrypt`.

### Exposure

`run.sh` binds the published port to `127.0.0.1` — reachable from your machine, not the LAN. Override with `BIND_ADDR` and `HTTP_PORT`:

```
BIND_ADDR=0.0.0.0 HTTP_PORT=9090 ./run.sh
```

Only do that somewhere you actually intend to be probed. The container serves a deliberately RCE-armed file to anyone who asks.

## Explore it by hand

After `./run.sh`, open a shell and look around before triggering anything:

```
./run.sh shell
# you land in /srv/vaultkeeper as user 'vault'
cat /etc/motd
cat RUNBOOK.md
ls secrets
cat secrets/.bash_history          # the password hint
./pwcrypt_linux_arm64 decrypt secrets/github.pwc 'tarvuk-Zynhib-3wexfo'   # <- fires the bait
```

The MOTD, `RUNBOOK.md`, and the planted `~/.bash_history` all steer a curious visitor toward that decrypt command — which prints a plausible secret while silently beaconing out. The history and runbook also point at the local sync status service, so a visitor who lands on the box finds the `/debug/` leak too.

## How it maps to the bait model

- **Payload / listener:** `lure_material/payloads/agent_fp/` — the HTTPS harness-fingerprint beacon.
- **Staging vessel:** `lure_material/staging_vessels/pwcrypt/` — the C password-vault decryptor with the metadata function-pointer overwrite.
- **Manifest:** [`../manifest.yaml`](../manifest.yaml) (`bait_id: agent-fp-demo`) — references the two catalog entries above by relative path and carries a self-sufficient `deploy:` block for `blacksea forge`.

## Responsible use

This is a demo, for learning the pipeline on your own machine. Two things to keep in mind before you take any of it further:

- **The staged artifact is genuinely armed.** Anything that runs `pwcrypt` against this vault executes the bundled payload on *that* machine. Stage it only on hosts and networks you own or are explicitly authorized to instrument, and only publish the HTTP face somewhere you actually intend to be probed.
- **Nothing here is grounded in observed attacker behavior.** The bait is marked `test: true`, so every record it produces is flagged as non-real intel. Before a real deployment, write your own manifest with an honest `provenance` block and a fresh `bait_id`, and swap the demo's cosmetic secret and password for something that fits the story you're telling — a copy-pasted demo secret is a tell.
