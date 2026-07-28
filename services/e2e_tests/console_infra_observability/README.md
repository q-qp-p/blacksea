# e2e_tests/console_infra_observability — console infra lifecycle + observability, end-to-end

The sibling of `e2e_tests/console_baits_instances/` — same idea (the fixture bait,
`console-observability-probe`, is just the means to an end; the console commands are what's
under test), but this entry covers what happens **after** an instance is live: reading it back,
and operating the stack around it.

```
status (postgres)
-> forge (get a live, fired instance quickly — already covered elsewhere, not this entry's focus)
-> status (full component set, once the brain is confirmed alive)
-> events tail (backgrounded, proves it live-follows) -> fire -> events ls -> events show
-> health -> campaigns -> sessions -> logs -> config show
-> otel config set / show
-> down -> status -> up -> status   (round-trip, using each command's own JSON result +
                                      the edge's TCP-probe status component)
-> reset --yes                      (last step — see the note in e2e_test.sh on why it's safe here)
```

Together with `console_baits_instances/`, this covers most of `src/blacksea/console/context.md`'s
"Exit criterion" against a **live** stack — real subprocess calls to the installed
`blacksea` binary, not `CliRunner` (see that file's Exit-criterion note for the two verbs, `otel
run` and `otel install-unit`, that still aren't). `tests/console/` exercises all of these
commands' plumbing in-process with the DB probe mocked off; nothing before this exercised their
actual query/mutation behavior against real Postgres/NATS/edge/brain.

Not covered here:
- `blacksea init` — a bare `init` already refuses to overwrite an existing `config/blacksea.env`
  (needs `--force`, which is the actually-risky case), so it isn't excluded for safety; it's
  excluded because it's already covered in-process by `tests/console/test_lifecycle.py` and
  exercising it for real here would add nothing this entry's scope needs.
- `web-ui` — a documented TEMPORARY stopgap.
- The attribution commands (`actors`/`drafts`/`replay`) — gated off until the correlation engine lands.
- `otel run`/`otel install-unit` (the console commands themselves) — `e2e_tests/otel_export/`
  proves the underlying `python -m blacksea.otel_export` module end-to-end (everything `otel run`
  would spawn), but it invokes that module directly rather than through `blacksea otel run`, so
  the command wrapper itself has no e2e coverage yet.

## Run it

```bash
make install                                       # once, from services/
e2e_tests/console_infra_observability/e2e_test.sh   # automated: walks the whole sequence above
```

Picked up automatically by `make test-e2e`. See `e2e_tests/README.md` for the shared `lib.sh`
contract this script builds on (`bs_dev_up`/`bs_forge`/`bs_wait_hotswap`/`bs_verify_record`).
