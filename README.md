<p align="center">
  <a href="https://cracken.ai">
    <picture>
      <source media="(prefers-color-scheme: dark)" srcset="./assets/cracken-logo-dark.svg">
      <img alt="Cracken" src="./assets/cracken-logo.svg" width="170">
    </picture>
  </a>
</p>

<p align="center">
  <picture>
    <source media="(prefers-color-scheme: dark)" srcset="./assets/blacksea-logo-dark.svg">
    <img alt="Blacksea" src="./assets/blacksea-logo.svg" width="520">
  </picture>
</p>

# Project Blacksea (where AI attacks drown)
by Cracken; Core team: [Dario Pasquini](https://pasquini-dario.github.io/me/) and [Michal Bazyli](https://www.linkedin.com/in/punishell/)

Blacksea is an active honeypot and canary-bait control system built to detect and drown LLM-driven attackers: autonomous AI agents and LLM-assisted operators that scan and exploit systems. **Blacksea doesn't stop at watching LLM attacks. It exploits flaws in the attacker's LLM judgment to gain arbitrary code execution on their machines, collect intel passive defenses can't reach, and make sure they don't come back.**

**The technique.** An LLM-driven attacker works an engagement by reasoning toward the assets that move it forward: credentials to reuse, a decryptor for an encrypted blob, a key-derivation tool, a config unpacker, a token minter, an internal API client. Blacksea turns that reasoning into a trap. You seed **baits**, artifacts crafted to look exactly like the high-value, security-relevant assets such an agent is hunting for, staged in the places it will look and wrapped in the context that sells them: a plausible filename, a companion ciphertext blob, a README that explains what the tool is "for." Discovering one, the agent reasons that downloading and running it is the fastest route to what it wants, and because the artifact is deliberately expensive to reverse or reimplement, running the real thing genuinely *is* the path of least resistance. There's no prompt and no "please run me": the bait wins on technical plausibility alone.

What the agent can't see is that the bait is also a canary (what we like to call LLM-malware). Hidden inside the artifact, engineered to stay invisible to an LLM reading or reasoning about it, is a **payload**: arbitrary code of your choosing that runs the moment the bait is tripped and **beacons** home. Blacksea turns that beacon into a structured intel **record**, the raw material for attribution.

## How it works

🚨For an end-to-end example check: [basic_usage_tutorial.md](./docs/basic_usage_tutorial.md).

Blacksea is three things: **a server** you run on infrastructure you trust, **baits** you build with it and plant where an attacker will find them, and **records** that come back when one is tripped. It is not a passive sensor. The whole design is aimed at one moment, the attacker's own machine running your code. Everything else exists to make that moment happen and to get the result back to you safely.

### What a bait is made of

A bait is a single artifact an attacker finds, and two independent choices define it:

- **The payload.** The code that runs on whatever machine trips the bait. It's arbitrary: you write it, or you use the one Blacksea ships. This is what turns a detection into a foothold on the attacker's side.
- **The staging vessel.** What decides the *shape* the artifact takes: a password-vault decryptor, a database-backup restore tool, a release-config unpacker, a plain script. A vessel has no idea which payload it's carrying, which is why any payload can ship in any shape. Pick whichever shape is most plausible where you're seeding it.

Every time you build a bait you get an **instance**: one planted copy, carrying its own signing and encryption key. That's why a beacon can never be ambiguous about which copy fired, however many you have in the field, and why you can burn a single compromised copy without touching the rest.

### What you set up

```
  1  YOUR SERVER              2  BAITS                  3  WHAT YOU DEFEND
  ┌──────────────────┐        ┌─────────────┐          ┌────────────────────┐
  │ blacksea up      │ forge  │  artifact   │  stage   │ honeypots, or the  │
  │ trusted host,    │ ─────► │  + payload  │ ───────► │ real assets        │
  │ reachable        │        └─────────────┘          └────────────────────┘
  └──────────────────┘                                           │
           ▲                                                     │ an attacker
           │                                                     ▼ takes one
           └───────────────── beacon ◄───────────────── attacker's machine
```

1. **Run Blacksea where you're trusted.** `blacksea up` on a SOC server or similar host you control, never on a honeypot. It has to be reachable from wherever you plant baits, over HTTPS or DNS, because that's where beacons land. Nothing else about it faces the attacker.
2. **Forge as many bait instances as you want.** One `blacksea forge` per instance: it builds the artifact, mints that copy's key, and tells you where to find the files. The payload is your choice. Blacksea ships `agent_fp`, which fingerprints the agent harness that ran it, but the payload is arbitrary code, so it can just as well burn the attacker's compute, or do whatever else you need done on that host (see [Deploy your first bait](./docs/setup_a_bait.md)).
3. **Stage the baits where an attacker will look.** Honeypots you stand up for the purpose, or the real assets you're defending. A staged bait does nothing until someone runs it against the forged file it ships with, so it can sit on a live box without touching how that box works.

### What happens when a bait is tripped

From here it runs itself. This is the path a beacon takes home:

```
  attacker host               INTERNET                TRUSTED PLANE                     YOUR SOC
  ┌──────────┐    beacon    ┌──────────┐   queue    ┌──────────┐  ┌──────────┐         ┌──────────┐
  │  bait    │ ─DNS/HTTPS─► │   edge   │ ────────►  │  brain   │─►│ Postgres │ ┄OTLP┄► │  SIEM /  │
  │ payload  │              │   (Go)   │            │ (Python) │  │ records  │         │   SOC    │
  └──────────┘              └──────────┘            └──────────┘  └──────────┘         └──────────┘
     tripped                dumb dead-drop:         decrypts, interprets,              optional:
                            holds no keys           writes the record                  stream via OTLP
```

1. **The payload fires** on the attacker's machine, collects whatever you told it to, encrypts and signs the result under that instance's own key, and sends it out as a **beacon** over HTTPS or DNS, whichever channel the bait was built for. If it can't reach home it fails silently, by design: a bait never surfaces an error to the attacker.
2. **The edge catches it.** This is the only part of Blacksea that faces the internet, and it is deliberately dumb: it holds no keys, decrypts nothing, and derives nothing from the beacon. It stamps the source address and arrival time (facts the attacker can't shape, because the attacker never supplies them), drops the opaque bytes on a queue, and never talks back.
3. **The brain reads it.** On your side of the line, the brain authenticates the beacon, decrypts it, and interprets it, turning the raw bytes back into whatever the payload actually found.
4. **A record lands in Postgres.** That's the durable intel unit: which bait fired, what the payload found, from where, when, and whether the beacon authenticated. You browse records, tail them live, or stream every one to your SIEM over OpenTelemetry.

The edge/brain split is the security property worth understanding: everything that could be captured sits on the machine most exposed to attackers, and it's worth nothing. Compromise the edge and you get a mailbox, not the intel: no keys, no records, no way to forge a hit or read someone else's. It's also why the edge can run on a completely different, untrusted network from the brain.

### The vocabulary, in one table

That's the whole mechanism. Everything below is the same story told concretely, in the terms this README and every guide use. Keep this table handy and nothing later will be a surprise.

| Term | What it means |
| --- | --- |
| **Bait** | One deceptive lure, and the design behind it: a payload, its listener, and the staging vessel that gives it a shape. |
| **Payload** | The code hidden inside the bait. It runs on whatever machine trips the bait, then beacons home. Arbitrary code: you decide what it does. |
| **Listener** | The payload's other half, running inside the brain: it turns a raw beacon back into meaning. A payload and its listener are written together and ship as a pair. You only meet this one when you author a bait of your own. |
| **Staging vessel** | What decides the *shape* a bait takes on the target (a forged decryptor, a config unpacker, a plain script), independently of the payload inside it. |
| **Beacon** | The callback a tripped bait sends home, signed and encrypted under that copy's own key. |
| **Edge** | The internet-facing receiver that catches beacons. Deliberately dumb: holds no keys, decrypts nothing, learns nothing. |
| **Brain** | The trusted service that authenticates and decrypts each beacon, runs the listener, and writes the record. |
| **Record** | The structured intel unit a beacon becomes: which bait fired, what the payload found, from where, when, how confidently attributed. Everything you read or export reads records. |
| **Instance** | One planted copy of a bait, with its own key and token. Ten instances of one design are ten independently tracked, independently burnable traps. |
| **Campaign** | A label grouping instances deployed together, so you can filter records by it later. |
| **`forge`** | The one command that takes a bait design and produces a planted-ready instance (register → build → approve). |

## What it looks like end to end

That's the mechanism. Here it is concretely, with a bait that ships today: Blacksea's own `agent_fp` payload, which fingerprints the agent harness that runs it, delivered by the `pwcrypt` staging vessel, which dresses it as a password-vault decryptor.

### 1. A bait, on disk

Here's what `forge` hands you. Four files that have to be believable together:

```
pwcrypt                 a password-vault decryptor: a real, working tool
secrets/github.pwc      an encrypted vault, the "secret worth stealing"
secrets/.bash_history   a stray shell history, with the decrypt command and password in it
README.md               the tool's own project README
```

Nothing here is a mockup. The decryptor really decrypts, the vault really holds a secret, and the password in that history file really opens it. An agent that finds this set has everything it needs to reach one conclusion: run the tool on the vault.

Which is the point. Hidden inside the decryptor is the **payload**: code you wrote, invisible to an LLM reading the binary, wired to a flaw that only this vault can reach. Decrypt this vault and your code runs. Decrypt a genuine one and nothing happens at all.

A decryptor is only what *this* bait happens to look like, and that's the vessel's doing rather than the payload's. Swap the vessel and the same payload ships behind a release-config unpacker, a database-backup restore tool, or the plain script itself. All three are in [the catalog](./lure_material/README.md) today, and the rest of this walkthrough is identical either way.

### 2. You plant it, and supply the story

Blacksea hands you those files along with instructions: where each one goes, and the exact command that trips it. But the placement is yours, and it's what makes an agent run it. Dropped in `/tmp`, the set proves nothing. Give it a host with a reason to exist. Here that's `ci-sync-03`, a CI node that caches release secrets:

```
/srv/vaultkeeper/
├── pwcrypt                ← the bait
├── secrets/github.pwc     ← the bait
├── README.md              ← the bait
├── RUNBOOK.md             ← yours: why this box exists, and how to read the vault
└── release.env            ← yours: the CI config that references the cache
/etc/motd                  ← yours: greets every shell with the decrypt command
/home/vault/.bash_history  ← yours, with the bait's hint merged in
```

The dressing is the deception. The runbook is what turns a stray binary into the obvious next move:

> The vault is AEAD-encrypted; `openssl`, `gpg` and `file` cannot read it, and the bundled `pwcrypt` binary is the only supported reader. […] The master password for this node's cache is the one last used; see the shell history the sync agent leaves under `secrets/`.

Three things cooperate there: a reason the vault is valuable, a reason the bundled binary is the only way in, and the password within reach. An agent working this box isn't tricked into running the decryptor. Running it *is* the correct next step.

### 3. An agent takes the bait

```
  LLM-driven attacker
        │   probes your system
        ▼
  finds the staged lure
        │   reasons that running it is the way forward
        ▼
  the attacker downloads it
        │
        ▼
  runs it: YOU get arbitrary code execution on the attacker's machine
        │
        ▼
  your payload runs and beacons home  ──►  your record
```

And it often takes the artifact with it, pulling the decryptor and the vault back to its own infrastructure to work on them there. That detail matters more than it looks.

That's the real primitive here: **a tripped bait executes code of your choosing on the machine that tripped it.** When that machine is the agent's own (a container inside the attacker's harness, their operator box, wherever they run untrusted binaries), you have arbitrary code execution inside the attacker's infrastructure, on their side of the engagement.

What you spend that on is yours to decide. The payload in this example, `agent_fp`, spends it on a narrow and deliberately conservative read of the environment: which harness is driving, and a little about the operator behind it. A different payload asks different questions.

```
$ cat secrets/.bash_history
./pwcrypt decrypt secrets/github.pwc 'tarvuk-Zynhib-3wexfo'
$ ./pwcrypt decrypt secrets/github.pwc 'tarvuk-Zynhib-3wexfo'
ghp_PROD_4Z2cM9pXqLkR8sTnW1vYbU3aFhJgEoIdC0
```

A production token, from a tool that behaved exactly as documented. Nothing else printed, exit 0. What the agent can't see: parsing that vault's metadata also ran the payload embedded in the binary, which read its surroundings and beaconed home. A genuine vault decrypts with no side effect at all.

### 4. You read the record

```
$ blacksea events tail --bait agent-fp-demo
2026-07-27 14:02:11  f92cae98b0d9fa70-3b1d0c5a7e2f9418-0001  agent-fp-demo  payload_exec_collect  203.0.113.44  ok  https
```

`blacksea events show <record_id>` opens the whole thing. Every record has two halves. The **framework half** is the same for every bait: who fired it, from where, whether it authenticated. The **`details` half** depends entirely on which bait fired. For `agent_fp`, `details` is an attribution:

```json
{ "harness": "claude_code", "family": "composition", "confidence": 0.4667,
  "runner_up": "Decepticon", "abstained": false,
  "evidence": ["literal disc_k='CLAUDECODE' (x1.00)",
               "family=composition; best=claude_code 0.47; runner_up=Decepticon margin=0.33"],
  "cred_surface": ["aws", "ssh"],
  "locale": {"tz_name": "CEST", "utc_offset_min": 120, "lang": "en_US.UTF-8"},
  "history": {"bash_history": {"size": 18422, "mtime": 1784800000}} }
```

Reading it, starting with the framework half:

- **`instance_token`.** Which planted copy fired. Every copy carries its own key, so a hit is never ambiguous, however many baits you have in the field.
- **`source_ip`, `edge_recv_time`.** Stamped on arrival by the internet-facing edge, not reported by the payload. The attacker can't shape them.
- **`sig_valid`.** The beacon was signed and encrypted under that copy's key; nothing was forged or replayed.
- **`event_type`.** Here it's `payload_exec_collect`: the payload actually ran and collected on the target, as opposed to `signal_only`, a bare "something fired."

Then `agent_fp`'s own findings:

- **`harness` / `confidence` / `runner_up` / `evidence`.** *Who* tripped it. Here the fingerprint carried Claude Code's own self-disclosure marker, so the call is `claude_code` over its nearest rival by a clear margin, and `evidence` shows exactly what drove it. When the signal is too thin, `agent_fp` returns `abstained: true` and `harness: null` rather than guessing.
- **`cred_surface` / `locale` / `history`.** The operator behind the agent: AWS and SSH credentials on the box, a CEST timezone, an 18 KB shell history. A long-lived operator machine, not throwaway infra. Presence and metadata only, never file contents or command text.

That's the attribution material: a named harness with the evidence behind the call, a source address the attacker didn't choose, and a shape for the machine it ran on. Every record also streams to your SIEM over OTLP.

Walk this through yourself, on your own machine, in [deploying your first bait](./docs/setup_a_bait.md).

## Quick start

You'll need **Python 3.11+**, **`make`**, **Go 1.22+** (the edge daemon is a Go binary that `blacksea up` builds for you), and **Docker** with the **`docker compose`** plugin (Blacksea runs Postgres and NATS in containers by default; point it at your own instead and Docker becomes optional). Every Python dependency is installed for you into a project-local virtualenv, so there's nothing to `pip install` by hand, and nothing to install on a target host.

```bash
cd services
make install    # installs the `blacksea` command onto your PATH
make init       # choose how Blacksea gets Postgres and NATS (run it once)
blacksea up     # brings up everything: Postgres, NATS, the edge, and the brain
blacksea status # check that the stack is healthy
```

That's the whole system running. `make init` asks the one question that forks the setup, whether Blacksea should run Postgres and NATS for you in Docker or connect to your own, and writes `config/blacksea.env`. Skip it and `blacksea up` writes a working Docker-mode config for you on first run.

If `python3` on your PATH isn't the interpreter you want the virtualenv built from, pass `PYTHON=`:

```bash
make install PYTHON=python3.12                  # a specific minor version on your PATH
make install PYTHON=/usr/local/bin/python3.11   # or an explicit interpreter path
```

Baits that ship as a *compiled* artifact, a fake decryptor rather than a plain script, each need their own build toolchain: Docker, a C or Go compiler, or whatever else the vessel calls for. That's a build-host requirement only, and the target never needs a compiler. None of it is required to get running or to deploy a script-based bait, and the full per-vessel list is in [the operator guide](./services/README.md#optional-extras).

Now plant your first bait and watch a hit land: follow the [deploy-a-bait walkthrough](./docs/setup_a_bait.md), which forges a demo bait, fires it, and shows the record arriving. Day to day, `blacksea logs` tails the daemons, `blacksea events tail` follows hits live, `blacksea web-ui` opens the read-only web observer, `blacksea down` stops the stack, and `blacksea reset` wipes test state. `blacksea --help` prints the full command tree.

Before you point any of this at something outside your own lab, read [Security & Responsible Use](#security--responsible-use).

## Documentation

| Guide | What it covers |
| --- | --- |
| [Deploy your first bait](./docs/setup_a_bait.md) | **Start here.** The friendliest on-ramp: forge a demo bait, plant it, fire it, and watch the record land. |
| [Operator guide](./services/README.md) | Install and configure the stack, deploy and manage baits, run the edge on a separate network from the brain, and read the intel. The in-depth companion to the quick start above. |
| [Operator console](./docs/console.md) | Every `blacksea` command in depth: infra lifecycle, bait and instance lifecycle, `events`, `health`, and `--json` scripting. |
| [Authoring a bait](./docs/bait-authoring.md) | Write your own payloads and staging vessels: the manifest schema, golden tests, and registration. |
| [The bait catalog](./lure_material/README.md) | Every payload and staging vessel that ships today, and what each one needs to build. |
| [SIEM export over OTLP](./docs/otel-export.md) | Stream every record into your SOC, SIEM, or observability stack, with a worked Grafana Loki integration. |
| [Troubleshooting](./docs/troubleshooting.md) | Common issues and their fixes. |

The repo is a monorepo: [`services/`](./services/) holds the control system (the installable `blacksea` Python distribution plus the Go edge daemon), [`lure_material/`](./lure_material/) holds the bait catalog (the payloads and staging vessels that ship today), and [`docs/`](./docs/) holds the guides above.

## Roadmap: what's next

Blacksea is new, actively developed technology, and it's growing. What ships **today** is the full detection loop: seed baits, catch LLM-driven attackers when they trip one, turn each beacon into a structured record, watch hits land, and stream every record straight into your SIEM or observability stack over OpenTelemetry (OTLP). Every catalog entry is also yours to extend today: write your own payload or staging vessel and it plugs in the same way the built-in ones do, as described in [Authoring a bait](./docs/bait-authoring.md). On the roadmap:

- **More staging vessels, in more shapes**: the staging vessel decides what a bait *looks like* on the target. Today that's a forged password-vault decryptor, a database-backup restore tool, or a release-config unpacker. That catalog will keep growing, and the vessel format will grow with it: expect vessels that deliver a payload in artifact shapes, and with properties, well beyond the ones shipping now, so a bait can take whatever form is most plausible in the environment you're seeding. Every bait built from a vessel will also be uniquely randomized, so no two planted instances look alike. That denies attackers the cheap wins: signature matching, hash blocklists, and the other pattern-based defenses that would otherwise fingerprint and skip a known bait.
- **Event hooks & alerting**: fire a webhook or notification the moment a hit matches a condition you care about (a high-caution event, or a hit on a bait you've already revoked), instead of polling for it.
- **Deeper attribution**: a stateful engine that links individual hits into sessions and actors over time, so you can follow a single attacker across many baits. Today's attribution is a read-only view over records; this adds the connective tissue.
- **Production packaging**: a fully containerized "only Docker on the host" mode with a prebuilt, ready-to-ship edge image, and ready-made process-supervision (systemd) units, to make production deployments against your own Postgres and NATS a drop-in. (Running the edge on a separate, untrusted network from the brain already works today; see the [operator guide](./services/README.md).)
- **Sandbox-aware payloads**: agentic tooling increasingly runs untrusted artifacts inside a sandbox, where a bait can observe little and reach nothing. Planned payloads notice that and respond, for instance by fabricating an honest-looking sandbox violation that gets the artifact re-run outside the sandbox. The technique is written up in [Lying your way out of the (Claude Code) sandbox](https://pasquini-dario.github.io/me/blog/lying-your-way-out-of-the-sandbox.html).

These are planned directions, not dated commitments. Blacksea is evolving, and this list will grow with it.

## White papers

- [Red-Teaming the Agentic Red-Team](https://arxiv.org/pdf/2606.24496): Dario Pasquini, Michal Bazyli, Taras Fedynyshyn, Artem Sorokin

### Cite us

```
@misc{pasquini2026redteamingagenticredteam,
      title={Red-Teaming the Agentic Red-Team}, 
      author={Dario Pasquini and Michal Bazyli and Taras Fedynyshyn and Artem Sorokin},
      year={2026},
      eprint={2606.24496},
      archivePrefix={arXiv},
      primaryClass={cs.CR},
      url={https://arxiv.org/abs/2606.24496}, 
}
```

## Security & Responsible Use

> 🚨 **Read this before you clone, run, or deploy Blacksea.**

Blacksea is a **defensive tool**: it exists to detect and study LLM-driven attackers, not to attack anything itself.

- **Use this responsibly.** Only use Blacksea for legitimate defensive security research, honeypot operations, or authorized red-team/blue-team engagements. Never use it, or anything it builds, to attack, exploit, or gain unauthorized access to systems you don't own or don't have explicit permission to test.
- **Deploy only where you're authorized.** Baits, forged binaries, and their embedded payloads are meant for hosts and networks you own or have explicit permission to instrument: your own lab, a segmented honeypot host, or a sanctioned engagement. Never place them on systems you don't control.
- **Know your local law.** Deception technology, honeypots, and monitoring of third parties carry legal and privacy obligations that vary by jurisdiction and organization. Confirm you're compliant before deploying anything beyond your own lab.
- **No warranty.** Provided as-is for security research and defensive use. The authors accept no liability for misuse or for damage caused by deploying this outside its intended, authorized scope.
