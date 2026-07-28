# e2e_tests/otel_export — OTLP telemetry emitter, end-to-end

Exercises `blacksea.otel_export` across the **whole** export path, on top of a live
`blacksea up` stack:

```
bait fires ─► edge ─► NATS ─► brain ─► Postgres (records)
                                          │
                            otel_export tails the records table
                                          │  maps Record → OTLP LogRecord
                                          ▼
                              OTLP/HTTP ─► OpenTelemetry Collector ─► (debug exporter → stdout)
```

`e2e_test.sh`:

1. brings up the dev stack, forges this entry's bait, waits for the brain to hot-swap the key;
2. stands up an **OpenTelemetry Collector** container (our shipped sample config,
   `src/blacksea/otel_export/ops/collector-config.example.yaml`, routing logs to the `debug`
   exporter → the Collector's stdout) on host port **4418** (a dedicated port so it never
   collides with an operator's own Collector on 4318);
3. fires the payload (a real HTTPS beacon) and confirms a Record lands in Postgres;
4. runs `python -m blacksea.otel_export` pointed at the Collector, with the cursor seeded just
   before the fire so it backfills exactly this hit;
5. asserts the Collector received the LogRecord — by grepping its stdout for the hit's unique
   `instance_token` (which rides as `blacksea.instance_token`).

The bait itself (`otel-export-probe`) reuses the `hostname_grab` payload/listener/vessel from
`lure_material/` — the point of this entry is the *export*, not a new payload.

## Run it

```bash
make install                        # once, from services/ — puts `blacksea` on your PATH
e2e_tests/otel_export/e2e_test.sh   # automated: fire → export → assert receipt
```

To poke by hand instead, forge the bait and run the emitter yourself through the console:

```bash
blacksea up                                             # infra + edge + brain
blacksea forge e2e_tests/otel_export/manifest.yaml      # register → build → approve
# fire the artifact `forge` printed, then export it:
blacksea otel run                                       # tails records → OTLP (uses secrets/otel.env)
```

Picked up automatically by `make test-e2e`. Needs Docker (for infra **and** the Collector
container). See `e2e_tests/README.md` for the shared `lib.sh` contract.
