# Targets expect .venv/bin first on PATH, created by `uv sync` (see README).
.PHONY: check hooks hooks-installed pr lint types docs test mutations grep skeleton demo vectors vectors-test

check: hooks-installed lint types docs test grep mutations

hooks:   # installs every hook type named in .pre-commit-config.yaml (default_install_hook_types)
	pre-commit install

# The hooks are the only thing that runs the local denylist, so a checkout without
# them is unchecked. Fails until `make hooks` has been run and .denylist.local
# exists with at least one pattern (the --staged scan proves both).
hooks-installed:
	@for h in pre-commit commit-msg pre-push; do \
	  grep -qs 'pre-commit' "$$(git rev-parse --git-path hooks)/$$h" \
	    || { echo "hooks: $$h hook not installed; run: make hooks"; exit 1; }; \
	done
	@tools/denylist-check.sh --staged

# The PR title, the branch name and the body go through the local denylist before
# gh sees any of them.
pr:   # make pr TITLE='...' BODY=path/to/body.md
	@[ -n "$(TITLE)" ] && [ -n "$(BODY)" ] || { echo "usage: make pr TITLE='...' BODY=path/to/body.md"; exit 1; }
	@t=$$(mktemp -t pr-title-and-branch); printf '%s\n%s\n' "$(TITLE)" "$$(git branch --show-current)" > "$$t"; \
	  tools/denylist-check.sh "$$t" "$(BODY)"; rc=$$?; rm -f "$$t"; exit $$rc
	gh pr create --title "$(TITLE)" --body-file "$(BODY)"

lint:
	ruff check . && ruff format --check .

# Python roots that mypy checks: each package, app, and tool directory that holds
# at least one .py file. Derived, so a new app is checked as soon as it has code.
PY_ROOTS = $(shell for d in packages/* apps/* tools; do \
  [ -n "$$(find $$d -name '*.py' -print -quit)" ] && echo $$d; done)
SRC_PATH = $(shell ls -d packages/*/src apps/*/src | paste -sd: -)

# One mypy run per root, so test modules with the same basename in two packages
# do not collide.
types:
	@for d in $(PY_ROOTS); do MYPYPATH=$(SRC_PATH) mypy --strict $$d || exit 1; done

docs:
	interrogate --fail-under 100 packages apps tools

test:
	pytest -q

grep:
	python tools/grep_tests.py

# Applies each diff to the working tree and resets it afterwards, so it refuses
# to run on a dirty tree rather than discard uncommitted work. With no diffs yet
# (M0) it says so and passes. A kill is a suite that still collects and then fails;
# a mutation that breaks import or collection is a broken diff, not evidence that a
# test guards the mechanism (issue #27). The collect-only pass is what tells them
# apart: under -x a collection error and a failed test both exit 1.
mutations:
	@[ -z "$$(git status --porcelain)" ] || { echo "mutations: working tree not clean; commit or stash first"; exit 1; }
	@set -- mutations/*.diff; [ -e "$$1" ] || { echo "mutations: no diffs yet"; exit 0; }; \
	for d in "$$@"; do \
	  git apply --check "$$d" || { echo "stale mutation: $$d"; exit 1; }; \
	  git apply "$$d"; \
	  PYTHONDONTWRITEBYTECODE=1 pytest -q --co -p no:cacheprovider >/dev/null 2>&1; collected=$$?; \
	  PYTHONDONTWRITEBYTECODE=1 pytest -q -x -p no:cacheprovider >/dev/null 2>&1; rc=$$?; \
	  git checkout -- . && git clean -fdq; \
	  [ $$collected -eq 0 ] || { echo "mutation broke the suite instead of failing it (collection exit $$collected): $$d"; exit 1; }; \
	  [ $$rc -ne 0 ] || { echo "mutation did not fail the suite: $$d"; exit 1; }; \
	  echo "ok: $$d"; \
	done

vectors:   # regenerates everything under spec/vectors plus spec/vectors.sha256; a vector change needs a spec version bump
	rm -rf spec/vectors spec/vectors.sha256
	cd tools/vectors-go && go run . --out ../../spec/vectors

# The generator's own tests are the only check that every negative vector fails
# at the check number in its vector.expect (checks 1, 4, 5 and 9 are invisible to
# the JSON-Schema job). Not part of `make check`, which needs no Go toolchain.
vectors-test:
	cd tools/vectors-go && go test -count=1 ./...

# M1 walking skeleton: build the image, bring the gate up and wait for its health check,
# run the consumer's scenario once, then the verifier over the log; the verifier's verdict
# is the exit code. Volumes are removed afterwards so every run starts from genesis with a
# freshly drawn dev key (a second boot under a new key would fail check 5 by design).
COMPOSE = docker compose -f deploy/compose.yml
skeleton:
	$(COMPOSE) down --volumes --remove-orphans
	$(COMPOSE) up --build --detach --wait gate-stub \
	  && $(COMPOSE) run --rm consumer-stub \
	  && $(COMPOSE) run --rm verifier; rc=$$?; \
	  $(COMPOSE) down --volumes; exit $$rc

demo:       # M5
	docker compose -f deploy/compose.yml -f deploy/compose.demo.yml up --abort-on-container-exit --exit-code-from verifier
