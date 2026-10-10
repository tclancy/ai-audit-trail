.PHONY: check lint types docs test mutations grep skeleton demo vectors

check: lint types docs test grep mutations

lint:
	ruff check . && ruff format --check .

types:
	mypy --strict packages apps tools/anchors-pull

docs:
	interrogate --fail-under 100 packages apps

test:
	pytest -q

grep:
	python tools/grep-tests.py

mutations:
	@for d in mutations/*.diff; do \
	  git apply --check "$$d" || { echo "stale mutation: $$d"; exit 1; }; \
	  git apply "$$d"; \
	  if pytest -q -x >/dev/null 2>&1; then echo "mutation did not fail the suite: $$d"; git checkout -- .; exit 1; fi; \
	  git checkout -- .; echo "ok: $$d"; \
	done

vectors:
	cd tools/vectors-go && go run . --out ../../spec/vectors && cd ../../spec && sha256sum vectors/*/* > vectors.sha256

skeleton:   # M1
	docker compose -f deploy/compose.yml up --abort-on-container-exit --exit-code-from verifier

demo:       # M5
	docker compose -f deploy/compose.yml -f deploy/compose.demo.yml up --abort-on-container-exit --exit-code-from verifier
