# Blacksea build/test tooling.
#
# The Makefile covers what builds/tests/bootstraps the repo — install, `make init` (write the config
# from the repo root), run the suites, build the Go edge, clean. Everything that *operates* the
# running system (bring the stack up, forge baits, manage infra, view events, reset state) lives
# behind the single `blacksea` console:
#
#   make init                     choose docker/external infra + write config/blacksea.env (run from repo root)
#   blacksea up                   bring up Postgres + NATS + the edge + brain (`up --infra-only` = DB only)
#   blacksea forge <manifest>     register → build → approve a bait
#   blacksea status / logs        health + daemon logs
#   blacksea down / reset         stop daemons / wipe test state
#   blacksea web-ui / otel run    read-only observer UI / OTLP emitter
#
# `make install` installs everything AND symlinks the `blacksea` command onto your PATH (into
# ~/.local/bin by default — override with BINDIR=…), so it runs in any shell without activating the
# venv. After that, run `blacksea --help` from anywhere. `make uninstall` removes those symlinks.

PYTHON      := python3
VENV        := .venv
VENV_STAMP  := $(VENV)/.stamp
PY          := $(VENV)/bin/python
PIP         := $(VENV)/bin/pip
PYTEST      := $(VENV)/bin/pytest
GO          := go
# The Go dead-drop edge is a separate module (built, never installed); everything Python is the
# single `blacksea` distribution installed editable from ./pyproject.toml (src/blacksea/*).
EDGE_DIR    := edge

# `blacksea` and `bs-bundle` are symlinked into BINDIR so they resolve without `source .venv/bin/activate`
# — the console-scripts carry an absolute shebang into .venv, so the link is self-contained. BINDIR is
# user-writable and conventionally on PATH on Linux and macOS alike; override for a different location:
#   make install BINDIR=/usr/local/bin
BINDIR          ?= $(HOME)/.local/bin
VENV_BIN        := $(abspath $(VENV))/bin
CONSOLE_SCRIPTS := blacksea bs-bundle

# The ONE unified config file (BS_INFRA + coordinates + credentials), written by `make init`.
# Absent until then. Included here only so `make test` can assemble POSTGRES_DSN from the docker-mode
# coordinates below; the legacy secrets/env is included after so an un-migrated checkout still
# resolves (config values win where both set the same key).
-include secrets/env
-include config/blacksea.env

# Backing-service connection settings for the Postgres-backed suites. In EXTERNAL mode
# config/blacksea.env supplies POSTGRES_DSN verbatim; in DOCKER mode it supplies the coordinates
# below and we assemble the DSN from them. `?=` so a value the -include already set wins over these
# defaults.
POSTGRES_HOST ?= localhost
POSTGRES_PORT ?= 5432
POSTGRES_DB   ?= blacksea
POSTGRES_USER ?= blacksea
POSTGRES_DSN  ?= host=$(POSTGRES_HOST) port=$(POSTGRES_PORT) dbname=$(POSTGRES_DB) user=$(POSTGRES_USER) password=$(POSTGRES_PASSWORD)

.PHONY: install link init uninstall test test-e2e build-edge clean help

help:
	@echo "Blacksea build/test targets (everything else is the 'blacksea' console — see below):"
	@echo ""
	@echo "  install        create .venv, install the blacksea distribution editable, and symlink"
	@echo "                 'blacksea'/'bs-bundle' into $(BINDIR) so they're on PATH (run this first)"
	@echo "  init           choose docker/external infra + write config/blacksea.env (run after install)"
	@echo "  uninstall      remove those console-script symlinks (leaves .venv in place)"
	@echo "  test           run all unit suites (sdk + go edge + brain + control-plane + correlation + otel_export + console)"
	@echo "  test-e2e       run every e2e_tests/*/e2e_test.sh against a live stack (needs Docker)"
	@echo "  build-edge     compile the Go dead-drop edge to edge/bin/edge"
	@echo "  clean          remove .venv, build artefacts, and the console-script symlinks"
	@echo ""
	@echo "Operate the system with the console (on PATH after 'make install'):"
	@echo "  make init                choose docker/external infra + write config/blacksea.env"
	@echo "  blacksea up              bring up Postgres + NATS + edge + brain  (up --infra-only = DB only)"
	@echo "  blacksea forge <manif>   register + build + approve a bait"
	@echo "  blacksea status / logs   health + daemon logs   ·   blacksea down / reset"
	@echo "  blacksea --help          the full command tree"

# Use a sentinel file so a stale .venv (wrong shebangs after moving the project)
# is automatically detected and replaced — Make sees .stamp is missing and re-runs.
# One editable install of the whole distribution ("[dev]" adds pytest + the bundler's minifier);
# it makes every blacksea.* package importable and puts the `blacksea` / `bs-bundle` console-scripts
# on PATH — no PYTHONPATH, no launcher.
$(VENV_STAMP):
	rm -rf $(VENV)
	$(PYTHON) -m venv $(VENV)
	$(PIP) install -q -U pip
	$(PIP) install -q -e ".[dev]"
	touch $@

install: $(VENV_STAMP) link
	@echo ""
	@echo "Done — the 'blacksea' command is on your PATH (symlinked into $(BINDIR)); no venv activation needed."
	@echo "Next:  make init   (choose infra mode + write config/blacksea.env),  then  blacksea up"

# `make init` — the documented first-run step to choose the infra mode once and write
# config/blacksea.env. It wraps the console's init logic (`blacksea init`, now a HIDDEN command — not
# in `blacksea --help`), so external-mode connectivity validation + the interactive prompt are
# preserved. The write is package-anchored (<BS_PROJECT_ROOT>/config/blacksea.env, the same place the
# loader reads from), so correctness doesn't depend on the invoking directory. Forward flags with
# ARGS=…:
#   make init                     # interactive (or docker in a non-TTY)
#   make init ARGS="--docker -y"  # non-interactive docker quickstart
#   make init ARGS="--external --postgres-dsn '…' --nats-url nats://host:4222"
# (A pip-only install without this Makefile can still run the hidden `blacksea init` directly.)
init: $(VENV_STAMP)
	$(VENV_BIN)/blacksea init $(ARGS)

# Symlink the venv console-scripts into BINDIR so `blacksea`/`bs-bundle` work in any shell without
# `source .venv/bin/activate`. Idempotent (ln -sf). Warns — without failing — if BINDIR is off PATH.
link: $(VENV_STAMP)
	@mkdir -p "$(BINDIR)"
	@for s in $(CONSOLE_SCRIPTS); do \
	  ln -sf "$(VENV_BIN)/$$s" "$(BINDIR)/$$s"; \
	  echo "linked $(BINDIR)/$$s -> $(VENV_BIN)/$$s"; \
	done
	@case ":$$PATH:" in \
	  *":$(BINDIR):"*) : ;; \
	  *) printf '\n%s\n  %s\n%s\n' \
	       "NOTE: $(BINDIR) is not on your PATH. Add it in your shell rc (~/.zshrc or ~/.bashrc):" \
	       "export PATH=\"$(BINDIR):\$$PATH\"" \
	       "then restart your shell (or source that file)." ;; \
	esac

# Remove the console-script symlinks created by `link`/`install` — only if they are symlinks, so a
# real file of the same name is never touched. Leaves .venv in place; `make clean` removes that too.
uninstall:
	@for s in $(CONSOLE_SCRIPTS); do \
	  if [ -L "$(BINDIR)/$$s" ]; then rm -f "$(BINDIR)/$$s"; echo "removed $(BINDIR)/$$s"; fi; \
	done

# All unit suites in one target: sdk (incl. the bundler subdir), go edge, brain, control-plane,
# correlation, otel_export, console.
#  - The edge is a self-contained Go module (no venv); run from its own directory.
#  - Postgres-backed suites (brain/control-plane/correlation/otel_export/console) connect via
#    POSTGRES_DSN and skip cleanly when no database is reachable — run `make init` then
#    `blacksea up --infra-only` first for the full vertical slice.
# For a single suite during development, invoke pytest directly, e.g. `$(PYTEST) tests/brain -q`.
test: $(VENV_STAMP)
	$(PYTEST) tests/sdk -q
	$(PYTEST) tests/config -q
	cd $(EDGE_DIR) && $(GO) test ./...
	POSTGRES_DSN="$(POSTGRES_DSN)" $(PYTEST) tests/brain -q
	POSTGRES_DSN="$(POSTGRES_DSN)" $(PYTEST) tests/control_plane -q
	POSTGRES_DSN="$(POSTGRES_DSN)" $(PYTEST) tests/correlation -q
	POSTGRES_DSN="$(POSTGRES_DSN)" $(PYTEST) tests/otel_export -q
	POSTGRES_DSN="$(POSTGRES_DSN)" $(PYTEST) tests/console -q

# Real end-to-end tests: auto-discover every e2e_tests/<name>/e2e_test.sh and run it. No
# hardcoded entry list — drop in a new e2e_tests/<name>/ and it is picked up. Each script
# idempotently brings up the stack itself (via `blacksea up`), forges its bait, fires it, and
# asserts a record lands in Postgres. Needs Docker (infra) + `make install`. Runs ALL entries, then
# fails if any failed (does not stop at the first failure). See e2e_tests/lib.sh for the shared
# helper contract each e2e_test.sh builds on.
E2E_DIR ?= e2e_tests
test-e2e: $(VENV_STAMP)
	@scripts=$$(ls $(E2E_DIR)/*/e2e_test.sh 2>/dev/null); \
	if [ -z "$$scripts" ]; then echo "no e2e tests found under $(E2E_DIR)/"; exit 1; fi; \
	failed=""; \
	for t in $$scripts; do \
	  echo "════════════════════ running $$t ════════════════════"; \
	  if bash "$$t"; then echo "PASS: $$t"; else echo "FAIL: $$t"; failed="$$failed $$t"; fi; \
	done; \
	if [ -n "$$failed" ]; then echo "e2e failures:$$failed" >&2; exit 1; fi; \
	echo "all e2e tests passed"

build-edge:
	cd $(EDGE_DIR) && $(GO) build -o bin/edge .

# `uninstall` first so the console-script symlinks go before `.venv` does — otherwise they'd dangle.
clean: uninstall
	rm -rf $(VENV) $(EDGE_DIR)/bin build
	find . -name "__pycache__" -not -path './.venv/*' -exec rm -rf {} + 2>/dev/null || true
	find . -name "*.pyc" -not -path './.venv/*' -delete 2>/dev/null || true
	find . -name "*.egg-info" -not -path './.venv/*' -exec rm -rf {} + 2>/dev/null || true
