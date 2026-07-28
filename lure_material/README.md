# lure_material — payload and staging-vessel catalog

This directory is the catalog of **bait implementations** — the payload/listener pairs and the staging vessels that turn them into deliverable artifacts. It's kept separate from the control-system code in `services/` so the same payload or delivery mechanism can back more than one bait without copying files.

Everything here is **decoy material for defensive honeypot use**: deliberately enticing artifacts you plant on hosts you own or are authorized to test, so that an LLM-driven attacker who takes the bait reveals itself. Read the [Security & Responsible Use](../README.md#security--responsible-use) section of the top-level README before deploying any of it.

A bait is declared by a single `manifest.yaml` — which can live anywhere (e.g. `services/e2e_tests/<name>/` or `services/test_fixtures/baits/<name>/`) — that references its payload/listener pair and staging vessel *here* by a `../`-relative path. Nothing is ever copied into a bait directory; there is no dedicated `baits/` directory. See [Authoring a bait](../docs/bait-authoring.md) for the full model.

```
lure_material/
├── payloads/
│   └── <name>/
│       ├── payload.py       # standalone payload (imports blacksea.sdk.payload.* at build time)
│       └── listener.py      # Listener subclass — interprets the payload's hits
└── staging_vessels/
    └── <name>/
        └── setup.sh         # wraps a bundled payload into a delivery artifact
```

These are plain files, not an installable package. A catalog entry only needs to be a directory of files: manifests reference each entry by file path, so nothing here needs packaging.

## `payloads/<name>/`

One entry is a `(payload.py, listener.py)` pair — never split further, because the listener's decode must match the payload's serialization byte-for-byte (the golden tests catch any drift; see [Authoring a bait](../docs/bait-authoring.md)). A pair is independent of its delivery mechanism: the same pair can be staged as a shell script, a fake binary, and so on — see [`staging_vessels/<name>/`](#staging_vesselsname) below. Nothing here is exhaustive, either: write your own `payload.py`/`listener.py` pair against the SDK and it plugs into the catalog the same way — see [Authoring a bait](../docs/bait-authoring.md) §3–§4.

- `payloads/agent_fp/` — **the flagship payload**, and the one built directly for what Blacksea exists to do: not just recording that a hit happened, but attributing *which LLM-driven agent harness* tripped it. When triggered, it collects a narrow set of fingerprint-shaped facts about the process that ran it — environment-variable *names* (never arbitrary values), the shape of the working directory, child-process binaries, a package-manifest name, and a small allowlist of env values worth reading at all (`PS1`, credential-shaped suffixes like `*_PASSWORD`) — and beacons them home encrypted over HTTPS. The listener resolves that raw material and runs a deterministic, evidence-carrying rule engine against a knowledge base of ~30 known coding-agent and autonomous-pentest-agent signatures (including widely-used ones like `claude_code`, `aider`, `opencode`, `gemini-cli`, `cline`), producing a harness name, a confidence level, and the exact evidence behind the call — including an honest "abstained" result when the signal is too thin, rather than guessing. Alongside harness attribution it also collects a small, separate set of operator/actor-intel signals — which well-known credential surfaces exist (cloud CLI configs, SSH keys), locale/timezone, and shell-history file metadata — presence and size only, never file contents, secret values, or command text. Staged with the `identity` vessel: the payload script itself already is the artifact here.
- `payloads/hostname_grab/` — a minimal example: collects the target host's hostname and reports it home over HTTPS. The simplest possible payload — a good first read before `agent_fp`.
- `payloads/hostname_grab_dns/` — the DNS (signal-only) variant of the same idea: collects the hostname and beacons it out over DNS as packed base32 labels, with no encrypted blob or signature (that's the DNS channel by definition). Staged with the `identity` no-op vessel; this is the pair the reference test bait (`services/test_fixtures/baits/hostname_probe/`) and the `services/e2e_tests/hostname_grab_dns/` example use.

## `staging_vessels/<name>/`

A staging vessel is the *delivery* half of a bait — it decides what the artifact looks like and how it lands on a target, completely independent of what the payload inside it actually does. That's deliberate: the same `payload.py`/`listener.py` pair can ship behind more than one vessel with no changes to the payload itself — a plain script today, a forged decryptor tomorrow — because a vessel has no idea which payload it's carrying, it just wraps whatever bundled payload it's handed. See "Referencing a catalog entry" below for how a manifest picks a payload and a vessel independently of each other.

Concretely, one entry is a `setup.sh` that wraps a bundled payload into the artifact you plant, following the staging-vessel contract (the full spec is in [Authoring a bait](../docs/bait-authoring.md), §5). Each vessel also writes a per-build `how_to_stage.md` next to its actual artifact with that specific build's exact placement and trigger instructions — check there, not here, for a real deployment. The summaries below cover what ships out of the box today; a growing set of vessels is planned, and you're free to author your own against the same contract — see [Authoring a bait](../docs/bait-authoring.md) §5.

Some of these are **deliberately-vulnerable decoy tools**: an artifact that looks like exactly the kind of security-relevant utility an attacker wants to run (a vault decryptor, say), does what it claims when run against a benign input, but carries a planted flaw that fires the embedded payload when run against the forged companion file the vessel ships. A genuine file never triggers it.

**Build-host requirements.** A vessel that ships a compiled binary compiles it on *your* build host when you forge the bait, so that host needs the vessel's toolchain — listed with each entry below, and collected in one table in [`services/README.md`](../services/README.md#optional-extras). None of this is needed to install or run Blacksea itself, and none of it is needed on the *target*: the artifact you plant is self-contained, so the machine you plant it on never needs a compiler. The pure-script vessel (`identity`) needs nothing beyond `python3`.

- `staging_vessels/identity/` (🚨 ONLY FOR TESTING) — the no-op vessel: copies the bundled payload to `bait.py` unchanged. Use it when the payload script *is* the artifact you plant. **Build host needs:** nothing beyond `python3`.
- `staging_vessels/pwcrypt/` — a fake C "password-vault decryptor." Ships a portable binary (Linux amd64/arm64 plus a macOS universal build) and a companion encrypted vault; decrypting the planted vault triggers a memory-corruption RCE that runs the embedded payload, while a real vault would decrypt normally. Trigger: `pwcrypt_<platform> decrypt secrets/github.pwc 'hunter2'`. **Build host needs:** Docker for the Linux binaries (built inside Alpine containers, which fetch packages from the network at build time); on macOS, the Xcode Command Line Tools for the macOS binary.
- `staging_vessels/db-restore/` — a fake C "encrypted database-backup restore tool." Ships the real, working `db-restore` binary plus one forged backup (`prod-nightly-2026-06-14.dbk`) and a restore runbook. Running `db-restore info`/`list`/`verify` on the backup is genuine, harmless recon that prints a convincing prod snapshot and service-account DSNs; running `db-restore restore <backup>.dbk` decrypts the dump *and* fires the embedded payload as an invisible forked-child side effect — the backup body carries a planted "native restore driver" (AArch64 shellcode) that the tool maps executable and calls. A genuine backup would decrypt without side effects. **Linux ARM64 targets only** (the binary is a static aarch64 ELF and the planted driver is AArch64 Linux shellcode; other `target_arch` values fail fast). Trigger: `./db-restore restore prod-nightly-2026-06-14.dbk`. **Build host needs:** a C compiler (`cc`) and `python3` — no Docker or cross-toolchain (the binary ships prebuilt; only the backup is forged per build).
- `staging_vessels/cfgunpack/` — a fake Go "release-config bundle (un)packer." Ships static Linux binaries (`cfgunpack_linux_amd64` + `cfgunpack_linux_arm64`, built pure-Go with `CGO_ENABLED=0` so each is a fully static ELF with no libc dependency) plus one forged config bundle (`prod-config.enc`) and a project README that reads like the genuine internal tool. Running `cfgunpack decrypt prod-config.enc` (or `info`/`list`/`verify`) prints a convincing set of AWS/Stripe/Okta/etc. production secrets **and** fires the embedded payload via a GNU tar `--to-command` shell injection: the bundle's `extras_transform_digest` header field — which reads like an integrity tag — is actually ChaCha20-Poly1305 ciphertext, decrypted under a key bound to the binary's build seed, of shell arguments spliced into the tool's sidecar-extraction command. A genuine bundle would just decrypt. The build compiles the binary and forges the bundle in one pass keyed to a single per-build seed, so the one bundle drives every binary produced. **Linux targets only** (the exploit needs GNU tar's `--to-command`, a GNU extension absent from BSD/macOS and BusyBox tar); the target also needs `python3` on PATH (the payload is a `python3 -c` one-liner, same as any hostname_grab-based bait). Trigger: `./cfgunpack_<arch> decrypt prod-config.enc`. **Build host needs:** `go` and `python3` — no Docker or cross-toolchain (pure-Go `CGO_ENABLED=0` cross-compiles both Linux arches; module dependencies are vendored for offline builds).

## Referencing a catalog entry from a bait manifest

A manifest's `payload_file` / `listener_class` / `staging_vessel` fields are `../`-relative paths out to this catalog; the number of `../` segments just has to match the manifest's depth. For example, the reference test bait at `services/test_fixtures/baits/hostname_probe/manifest.yaml` (four levels below the repo root) uses four `../` segments:

```yaml
listener_class: ../../../../lure_material/payloads/hostname_grab_dns/listener.HostnameGrabDNSListener
payload_file:   ../../../../lure_material/payloads/hostname_grab_dns/payload.py
staging_vessel: ../../../../lure_material/staging_vessels/identity
```

An entry one level shallower — e.g. `services/e2e_tests/<name>/manifest.yaml` — uses three `../` segments instead. See [Authoring a bait](../docs/bait-authoring.md) for the full manifest schema.
