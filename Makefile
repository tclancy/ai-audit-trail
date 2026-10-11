.PHONY: check lint types docs test mutations grep skeleton demo vectors

check: lint types docs test grep mutations

lint:
	ruff check . && ruff format --check .

# Python roots that mypy checks: each package, app, and tool directory that holds
# at least one .py file. Derived, so a new app is checked as soon as it has code.
PY_ROOTS = $(shell for d in packages/* apps/* tools/anchors-pull; do \
  [ -n "$$(find $$d -name '*.py' -print -quit)" ] && echo $$d; done)
SRC_PATH = $(shell ls -d packages/*/src | paste -sd: -)

# One mypy run per root, so test modules with the same basename in two packages
# do not collide.
types:
	@for d in $(PY_ROOTS); do MYPYPATH=$(SRC_PATH) mypy --strict $$d || exit 1; done

docs:
	interrogate --fail-under 100 packages apps

test:
	pytest -q

grep:
	python tools/grep-tests.py

# Applies each diff to the working tree and resets it afterwards, so it refuses
# to run on a dirty tree rather than discard uncommitted work. With no diffs yet
# (M0) it says so and passes.
mutations:
	@[ -z "$$(git status --porcelain)" ] || { echo "mutations: working tree not clean; commit or stash first"; exit 1; }
	@set -- mutations/*.diff; [ -e "$$1" ] || { echo "mutations: no diffs yet"; exit 0; }; \
	for d in "$$@"; do \
	  git apply --check "$$d" || { echo "stale mutation: $$d"; exit 1; }; \
	  git apply "$$d"; \
	  if pytest -q -x >/dev/null 2>&1; then echo "mutation did not fail the suite: $$d"; git checkout -- . && git clean -fdq; exit 1; fi; \
	  git checkout -- . && git clean -fdq; echo "ok: $$d"; \
	done

vectors:
	cd tools/vectors-go && go run . --out ../../spec/vectors && cd ../../spec && sha256sum vectors/*/* > vectors.sha256

skeleton:   # M1
	docker compose -f deploy/compose.yml up --abort-on-container-exit --exit-code-from verifier

demo:       # M5
	docker compose -f deploy/compose.yml -f deploy/compose.demo.yml up --abort-on-container-exit --exit-code-from verifier
