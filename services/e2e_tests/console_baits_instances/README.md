# e2e_tests/console_baits_instances — console bait/instance CRUD + lifecycle, end-to-end

Unlike the other `e2e_tests/` entries, the point here isn't the bait or a new delivery
technique — it's the `blacksea` console commands themselves. `console-baits-probe` (reusing the
`hostname_grab` payload/listener/vessel from `lure_material/`) is just the fixture that lets the
test drive the console's bait/instance surface against a **live** `blacksea up` stack, real
subprocess calls, no mocking:

```
baits register -> baits ls -> baits show
-> instances build -> instances ls -> instances show -> instances approve -> instances show
-> (fire the built artifact for real, verify a record lands in Postgres)
-> instances artifact
-> 3 more instances, one each through burn / retire / revoke, asserting the resulting status
```

This is the granular-verb half of `src/blacksea/console/context.md`'s "Exit criterion"
(`register → build → approve → … → burn/retire/revoke`) — it deliberately uses `baits
register`/`instances build`/`instances approve` as three separate steps instead of the `forge`
convenience wrapper, since `e2e_tests/hostname_grab/` already exercises `forge` end-to-end. The
`instances ls/show/burn/retire/revoke` transitions and `instances artifact` locator have no other
e2e coverage anywhere in the repo — `tests/console/` only exercises them in-process with a mocked
DB. See `e2e_tests/console_infra_observability/` for the sibling entry covering `status`,
`up`/`down`/`reset`, `events`, `health`, `campaigns`, `sessions`, `logs`, and `otel config`.

## Run it

```bash
make install                                  # once, from services/ — puts `blacksea` on your PATH
e2e_tests/console_baits_instances/e2e_test.sh   # automated: walks the whole command sequence above
```

To poke by hand instead, every step is a plain `blacksea` invocation:

```bash
blacksea up
blacksea baits register e2e_tests/console_baits_instances/manifest.yaml
blacksea instances build console-baits-probe --campaign my-campaign --callback https=http://127.0.0.1:8443
blacksea instances approve <instance_token>
blacksea instances show <instance_token>
blacksea instances burn --instance <instance_token> --reason testing
```

Picked up automatically by `make test-e2e`. See `e2e_tests/README.md` for the shared `lib.sh`
contract this script builds on (`bs_dev_up`/`bs_wait_hotswap`/`bs_verify_record`).
