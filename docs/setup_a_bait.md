# Setting up a bait — host-based deception in Blacksea

This guide teaches the idea behind host-based deception in Blacksea and walks through one concrete example end to end. It's a companion to [`bait-authoring.md`](./bait-authoring.md) (how to *author* a payload/listener/staging vessel) and [`console.md`](./console.md) (the full `blacksea` command reference); this guide only covers "take a design and put it in front of an attacker."

---

## 1. The lifecycle, and what it's for

A bait is a **design** — a payload/listener/staging-vessel triple plus a manifest — that you write or reuse once, then deploy as any number of independently-tracked **instances**, each with its own key and each producing attributable intel when tripped:

```
forge the bait
        │
        ▼
place it on a machine or honeypot
        │
        ▼
an attacker finds it, downloads it, and runs it
        │
        ▼
the bait beacons home
        │
        ▼
you get the packet
```

`forge` (§6) collapses register → build → approve into one command — each call stamps out a fresh **instance** (its own token + key), so the same `agent_fp` design below can back a dozen differently-placed instances across a dozen hosts, each tracked and independently burnable/retirable/revocable (§7) once you're done with it.

Nothing requires the attacker to be sophisticated or even aware they're interacting with a honeypot — the premise is that a curious or acquisitive process (human- or LLM-driven) that stumbles on the artifact and does the obvious thing with it triggers the beacon. The staging vessel is what decides *what the artifact looks like*: a plain script is the least convincing shape; a vessel like `pwcrypt` (used below) forges a plausible vulnerable tool plus a "secret" worth stealing, so an attacker's normal behavior — run the tool, decrypt the thing that looks valuable — is what trips it.

---



## 2. Prerequisites

- `make install` **has run** from `services/` (creates the venv, puts `blacksea`/`bs-bundle` on `PATH`) — see [`services/README.md`](../services/README.md)'s Prerequisites and Quick start for the full requirement list (Python 3.11+, `make`, Go, Docker). Pass `PYTHON=` if `python3` on your PATH isn't the interpreter you want the venv built from, e.g. `make install PYTHON=python3.12`.
- **A running stack**: `make init` (once) then `blacksea up` — brings up Postgres + NATS + the edge + the brain; `blacksea status` confirms everything is healthy.
- **The build toolchain for whichever staging vessel you use.** The `pwcrypt` vessel in this walkthrough compiles real binaries at forge time, so your build host needs **Docker** for the Linux binaries and, on macOS, the **Xcode Command Line Tools** for the macOS build. A pure-script vessel like `identity` needs nothing beyond `python3`. Every vessel's requirement is listed in [the bait catalog](../lure_material/README.md) and in [`services/README.md`](../services/README.md#optional-extras). This is a *build-host* requirement only — the artifact you plant is self-contained, and the target never needs a compiler.
- **Know where your edge actually listens.** The single most commonly-missed step (see §4 below): the payload you forge tries to reach a specific address over the network. For a same-machine test that's `127.0.0.1`; for anything else, it has to be an address the *target* machine can actually route to.
- **Nothing to know about the target's OS/architecture up front.** A compiled staging vessel like `pwcrypt` below builds a fixed portable-release matrix (Linux amd64/arm64 plus a macOS universal binary) sharing one forged vault, so you deploy the whole `to_stage/` directory and whichever binary matches the target host is the one that actually runs — see §5's placement walkthrough. A pure-script vessel has no compiled-binary concerns at all — stdlib Python 3.11+, runs anywhere; `agent_fp` itself ships this way too, paired with the plain `identity` vessel, at `services/e2e_tests/agent_fp/`.
- **This is for machines and networks you control or are explicitly authorized to deceive on** — your own lab, a segmented honeypot host, or an environment you have a mandate to seed baits in. Nothing here is designed for, or should be pointed at, systems you don't have permission to place files on.

---



## 3. The three components, briefly

A bait is `payload.py` (runs on the target, collects a fact and beacons it home) + `listener.py` (runs in your brain, decodes the beacon into a record) + a staging vessel (`setup.sh`, runs at build time, wraps the bundled payload into whatever shape the attacker actually finds) + `manifest.yaml` (ties the three together). Writing these from scratch is a separate topic, covered in full in [`bait-authoring.md`](./bait-authoring.md) §3 (payload), §4 (listener), and §5 (staging vessel) — for your first bait, reuse an existing catalog pair instead:

- `../lure_material/payloads/agent_fp/` — Blacksea's flagship payload: collects a narrow harness fingerprint (plus a few operator-recon signals) from whatever process runs it and beacons it over HTTPS; the listener then attributes *which* LLM-driven agent harness tripped the bait, with a confidence level and the evidence behind the call. See `lure_material/README.md` for the full catalog description.
- `../lure_material/staging_vessels/pwcrypt/` — delivers it via a forged, deliberately-vulnerable password-vault binary rather than a plain file drop, so the attacker trips the beacon by doing the obvious thing (decrypting what looks like a secret) instead of just running a script. Full mechanics: `lure_material/README.md`'s `staging_vessels/` section and `bait-authoring.md` §5.

Payload and vessel are independent catalog entries (see `lure_material/README.md`), so this pairing isn't a shipped test fixture — each piece is separately tested (`agent_fp` behind the plain `identity` vessel at `services/e2e_tests/agent_fp/`, `pwcrypt` behind the `hostname_grab` payload at `services/e2e_tests/pwcrypt_vault/`), and this guide combines them the same way you'd combine any payload with any vessel of your own. §5 gives you a ready-to-forge manifest for this exact combination to edit, rather than a test fixture to modify in place.

---



## 4. The manifest — what to actually set

A bait is declared by one `manifest.yaml` (see `bait-authoring.md` §6 for the complete field reference; this section only calls out what you'll actually touch for a first deployment). The fields you *will* change:


| Field                                                | What it is                                                       | What to set it to                                                                                              |
| ---------------------------------------------------- | ---------------------------------------------------------------- | -------------------------------------------------------------------------------------------------------------- |
| `bait_id`                                            | unique routing key (`bait.<bait_id>` subject)                    | something distinct — don't reuse `agent-fp`/`pwcrypt-vault`/`agent-fp-demo`, those are the shipped examples     |
| `deploy.callbacks.https`                             | **the address the payload phones home to**                       | see below — this is the one field every real deployment must change                                            |
| `deploy.campaign`                                    | a label grouping instances deployed together                     | anything meaningful to you, e.g. `field-2026q3` — used later to filter `events`/`health`/`sessions`            |
| `build.target_arch`                                  | which architecture(s) the vessel compiles for                    | optional for pwcrypt — omit for the full portable multi-binary matrix (default), or list specific values (e.g. `[aarch64-linux]`) to build only those and skip the rest (§6) |
| `provenance.behavior` / `.source` / `.observed_date` | required citation — registration fails without a non-empty value | describe why this bait exists (real deployments should cite an observed attacker behavior, not just "example") |
| `test`                                               | marks the bait as example/non-real intel                         | `true` while you're learning the pipeline; a real deployment should be `false`                                 |


**The server address, specifically.** `deploy.callbacks.https` is the URL the bundled payload is built with (injected as `_SERVER_URL`) — it has nothing to do with where you run `blacksea`; it's where the *target* machine will send its HTTPS beacon. Three cases:

- **Same machine, local test** — `http://127.0.0.1:8443` (the edge's default HTTPS listen address).
- **A separate machine on the same LAN** — the edge host's LAN IP, e.g. `http://192.168.1.20:8443`.
- **A real, network-separated target** (a real honeypot, a remote lab box) — a publicly-*reachable* address for your edge: a public IP/DNS name and a port that's actually open from where the target sits. If your edge runs behind NAT, that means port-forwarding, a reverse tunnel, or running the edge itself on a public host — the payload has no fallback if it can't reach this address, it just fails silently (by design — a bait must never surface errors to the attacker).

Everything else the factory resolves for you at build time (the instance token, the AEAD key) — see `bait-authoring.md` §1's "Standard build variables" table.

---



## 5. A premade manifest to start from

Rather than hand-editing either shipped test fixture, start from a dedicated bootstrap copy that already combines them:

[`docs/examples/agent_fp_pwcrypt_demo/manifest.yaml`](./examples/agent_fp_pwcrypt_demo/manifest.yaml)

It's the `agent_fp` payload/listener delivered via the `pwcrypt` vessel, pre-filled with a `deploy:` block so it's forgeable in one command with no flags. Edit it in place (simplest — no path adjustment needed) or copy it elsewhere first:

```bash
cp -r docs/examples/agent_fp_pwcrypt_demo services/e2e_tests/my-first-bait   # a manifest can live in any directory
```

Then edit the copy's `manifest.yaml`: change `bait_id` to something of your own, point `deploy.callbacks.https` at your real edge address (§4), leave `build.target_arch` unset (builds the full portable matrix) or restrict it to just the platform(s) you're placing the artifact on (§6), and fill in `provenance` honestly once this stops being a test run.

(`payload_file`/`listener_class`/`staging_vessel` stay as `../../../lure_material/...` as-is only if your copy sits **three directories** below the repo root, same depth as `docs/examples/` and `services/e2e_tests/<name>/` — see `bait-authoring.md` §2 on path depth. If you place it deeper or shallower, adjust the `../` count to match. Note that `services/e2e_tests/` is auto-scanned by `make test-e2e` for `e2e_test.sh` files, not `manifest.yaml` — a bare manifest there is harmless and won't be picked up as a test.)

---



## 6. Forge it, then place it

From `services/`:

```bash
blacksea forge <path-to-your-manifest.yaml>
```

This registers the design (running its golden tests — no registration succeeds if they fail), builds a fresh instance (real per-instance token + AEAD key, the vessel compiles `pwcrypt` for every platform in its release matrix and forges the one shared vault), and approves it — the explicit human gate that makes the key live in the brain. It prints the instance token and the artifact directory:

```bash
blacksea instances artifact <instance_token>
```

```
╭─ artifact for <instance_token> ──────────────────────────────────────────────╮
│ primary_file      pwcrypt_linux_amd64                                        │
│ to_stage_dir      …/registry/artifacts/agent-fp-demo/<ts>/to_stage           │
╰────────────────────────────────────────────────────────────────────────────╯
```

`to_stage_dir` is what you deploy — for the `pwcrypt` vessel that's three binaries (`pwcrypt_linux_amd64`, `pwcrypt_linux_arm64`, `pwcrypt_macos`) sharing one `secrets/` directory (`github.pwc`, `.bash_history`) plus `README.md`. `primary_file` just names the conventional default (most common honeypot target); the other two binaries are equally real, not fallbacks. **Copy the whole directory, preserving its internal layout** — each binary expects `secrets/github.pwc` at a path relative to itself, not the source paths printed above (those are absolute build-host paths and won't resolve unchanged on another machine — see `console.md`'s "Deploying an artifact" section).

### Placing it in a fictional defender's system

The point of a staging vessel like `pwcrypt` is that it already looks like something that belongs somewhere — the placement is what completes the story. Give it a plausible home instead of dropping it in an empty directory. For example, playing a sysadmin who keeps ad-hoc tools and forgot to clean up a vault, on a Linux honeypot (pick whichever of the three staged binaries matches the target — `pwcrypt_linux_amd64` here):

```bash
# on the target host (or a directory tree that stands in for one, e.g. a scratch VM):
sudo -u deploy mkdir -p /home/deploy/tools/pwcrypt
scp -r registry/artifacts/agent-fp-demo/<ts>/to_stage/* deploy@honeypot:/home/deploy/tools/pwcrypt/
ssh deploy@honeypot chmod +x /home/deploy/tools/pwcrypt/pwcrypt_linux_amd64
```

The staged `.bash_history` under `secrets/` is meant to be merged into (or placed as) the `deploy` user's real shell history, so a shell-history-reading attacker finds the exact decrypt command that fires the RCE — that's the "hint" the vessel already bakes in (it names `pwcrypt_linux_amd64`; edit it if you're placing a different one of the three binaries). Where you actually put the tree is the deception: a `~/tools/` directory next to other real-looking scripts is more convincing than a bare `/tmp/pwcrypt/`. If you don't have a separate honeypot host yet, you can rehearse the whole flow by standing up a scratch directory that stands in for one (e.g. `/tmp/fake-honeypot/home/deploy/tools/pwcrypt/`) and firing it yourself before pointing it at a real target.

For the plain-drop `agent_fp` example (no `pwcrypt`, `staging_vessel: identity` — see `services/e2e_tests/agent_fp/`), placement is simpler — the artifact is a single self-contained `bait.py`; anywhere a curious attacker (human- or LLM-driven) would run a Python script (a "diagnostics" folder, a cron job they'd inspect, etc.) works.

---



## 7. Wait, then read the record

Once it's placed, nothing else is required on your end — the brain already picked up the new instance's key (about ten seconds after `approve`, when it next polls its key directory). When the bait fires (an attacker runs `pwcrypt_linux_amd64 decrypt secrets/github.pwc 'tarvuk-Zynhib-3wexfo'` — or whichever of the three staged binaries matches their machine, or for the plain example, executes `bait.py`), read it back:

```bash
blacksea events tail --bait agent-fp-demo     # follow live, Ctrl-C to stop
blacksea events ls --bait agent-fp-demo       # newest first
blacksea events show <record_id>              # full record, incl. details.harness/.confidence/.evidence
```

The record's `details` carries the attribution itself: `harness` (the agent-harness name it thinks tripped the bait, or `null` if it isn't confident enough), `confidence`, `runner_up`, and `evidence` (the exact literal/structural clues that drove the call), plus a few separate operator-recon fields (`cred_surface`, `locale`, `history`). If you fire the bait from an ordinary shell, expect `harness: null` with `abstained: true` — that's an honest "not enough signal," not a bug; fire it from inside an AI coding assistant's own shell instead and watch it name that assistant directly.

`blacksea logs` shows the brain-side confirmation too (`stored record … (bait=agent-fp-demo sig_valid=True event=payload_exec_collect)`). `blacksea health --bait agent-fp-demo` gives hit-rate over time once you have more than one hit.

When you're done with an instance: `blacksea instances burn --instance <token> --reason "..."` (or `retire`/`revoke` for the whole design/key — see `console.md`). Don't run `blacksea reset` against anything but a local dev/test stack — it wipes the registry, key directories, Postgres records, and NATS backlog outright.

---



## Things worth deciding before you start

A few points that are easy to skip past and cause confusion later:

- **Reachability, not just correctness.** A manifest with every field "correct" still produces a silently-dead bait if `deploy.callbacks.https` isn't actually reachable from where you place the artifact (NAT, firewalls, a honeypot on an isolated VLAN). Test reachability *before* placing the bait — the payload swallows all errors by design, so a bait that can't phone home gives you no signal that anything is wrong.
- **Compiled vessels vs. pure-script ones.** `pwcrypt` ships a whole portable-release matrix (building the two Linux binaries needs Docker on your build host), so there's no architecture parity to plan around; deploy the whole `to_stage/` tree and run whichever binary matches the target. The plain `identity` vessel (pure Python) has no compiled-binary concerns at all — worth picking if you want the absolute simplest artifact.
- `approve` **is a manual gate, on purpose.** `forge` approves by default; pass `--no-approve` if you want to inspect a built instance before it goes live in the brain.
- `test: true` **matters.** It's what marks every record this bait produces as non-real intel in the observer/console (`TEST` badge). Flip it to `false` deliberately once this is a real deployment, not a rehearsal — and at that point, also swap the forged vault's cosmetic secret (the fake `ghp_...` token, the password `tarvuk-Zynhib-3wexfo`) for something that fits the story you're telling, since a copy-pasted demo secret is a tell.
- `bait_id` **and campaign are your filtering handles later.** Pick names you'll still recognize in `blacksea events ls --campaign …` weeks from now, especially if you plan to place several instances of the same design.
- **Authorization.** This system exists to catch LLM-driven attackers on infrastructure you're responsible for defending — place baits only on hosts/networks you own or are explicitly authorized to instrument.

