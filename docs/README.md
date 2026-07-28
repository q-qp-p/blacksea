# Blacksea docs

Operator and author guides for running Blacksea and building baits. New to Blacksea? Start with the [top-level README](../README.md) for what it is, why you'd use it, and where the project is headed — then come back here to go deep.

| Guide | What it covers |
|---|---|
| [setup_a_bait.md](./setup_a_bait.md) | **Deploy your first bait** — the host-based-deception mental model, a worked `agent_fp` + `pwcrypt` example (Blacksea's flagship harness-attribution payload delivered via a forged decryptor), the manifest fields you actually change (including the callback address), and how to place the artifact on a target. The friendliest on-ramp; a premade bootstrap manifest lives at [`examples/agent_fp_pwcrypt_demo/`](./examples/agent_fp_pwcrypt_demo/). |
| [console.md](./console.md) | **The `blacksea` operator console** — the single command-line entry point over the whole system: infra lifecycle (`up` / `down` / `status` / `logs` / `reset`), bait + instance lifecycle (`baits` / `instances` / `forge`), `events`, `health`, `otel` control, and `--json` scripting. |
| [bait-authoring.md](./bait-authoring.md) | **Authoring a bait** end to end — the three-component model (payload / listener / staging vessel), the `manifest.yaml` schema, golden tests, cross-compiling native vessels, and registering + testing. Self-contained. |
| [otel-export.md](./otel-export.md) | **Streaming events to your SIEM / observability stack** over OpenTelemetry (OTLP) — setup, config reference, a complete Grafana Loki integration, and routing to other backends. |
| [troubleshooting.md](./troubleshooting.md) | **Common issues** and their fixes, starting with Postgres `password authentication failed` (credential drift between `config/blacksea.env` and an old `pg_data` volume). |
