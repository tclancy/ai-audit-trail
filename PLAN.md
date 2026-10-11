# ai-audit-trail — Delivery plan v0.1 (revision 2, post-review)

Companion to `SPEC.md`. Sized for how the work actually happens: Tom directs, an agent implements, Tom reviews and tries to break it. One "unit" is roughly one focused weekend session of that loop. The honest total after review is **18–22 units**, not the 10–11 in the first draft. The ordering matters more than the number.

## 0. Ground rules

### 0.1 IP — what the contract actually says, and the rules that follow

Reviewed 2026-10-10 against the author's actual engagement terms (a platform Service Order plus the platform's Builder terms). Findings, kept generic on purpose:

- The assignment covers **Work Product** — what is produced in performing the billed services under the Service Order. There is no "conceived during the term" clause and no "related to the client's business" clause. Work done on the author's own time, hardware, and accounts, not for the engagement, is the author's.
- The terms define Background Technology as IP developed *before* the agreement; this project is developed *during* it, so it falls in a definitional gap. It is the author's under general law, but the argument against that is contamination by use: any of it written on billed hours, on a client machine, or for the client's project. **Separation of time and hardware is the legal basis, not hygiene.**
- The confidentiality clause forbids creating derivative works from the client's confidential information; the exception is independent development without use of or reference to it. Nothing in this repository may be derived from a client's systems. The PR template's leak question enforces that clause.
- Using any open-source or Builder-owned technology in the engagement requires the platform's or client's **written approval**. That approval, when the time comes, is the document that records this project as the author's independent work. Until it exists, the project is not used at work, not even for testing.
- The client's own source-code and open-source policies also apply to the author under the engagement terms; check them before the client consumes this project.

Rules that follow:

- Personal hardware, personal accounts, personal time, personal API keys. No exceptions.
- **Leak channels, each closed by a mechanism:**
  - The mock model's trace file is synthetic or recorded with the author's personal API key. Never from a client's calls.
  - Development sessions run in a dedicated project with **no notes vault and no client-context project attached**. Employer system names and phrasing leak through an agent's context otherwise.
  - A local-only denylist of client identifiers (system names, counterparty names, field names) wired into gitleaks/pre-commit, run over commit messages and PR bodies as well as code. The denylist itself is never committed.
  - PR template has a required field: "Could any sentence here only have been written by someone who saw a system outside this repository?" — a workflow checks the field is filled.
  - `reasons.txt` and the fault schedules are the two artifacts most likely to be transcribed from a client system. They are written from the spec, not from memory of a client system.
  - Git author identity set per-repo to the personal address.
- If a client later consumes this project: any fix discovered in that engagement is re-derived here from a clean problem statement, never ported; no client-context PRs flow upstream.
- Apache-2.0 from the first commit. `LICENSE`, `NOTICE`, SPDX headers on every source file.

### 0.2 Engineering rules

- No clever metaphors in identifiers. `Receipt`, `Log`, `verify`.
- The positive pinning test is written first; the mutation diff (`mutations/I*.diff`) is committed in the same PR as the mechanism it protects. CI applies each diff in a throwaway checkout and asserts the suite goes red, and separately asserts every diff still applies to HEAD (I15).
- The verifier is a separate package from day one: import root `audittrail_verify` (never `audittrail.verify`), its own lockfile and `conftest.py`, tests consume only committed fixtures under `spec/`, an isolated-venv CI job installs the built wheel with `--no-deps` plus declared deps and runs its tests there, and `import-linter` forbids any import of `audittrail` from it. **Canonicalization is deliberately duplicated** between the two packages and pinned together by the vectors plus a Hypothesis property test (random valid records → identical bytes). `audittrail-log` depends on the published `audittrail-verify` at a pinned version for the boot self-check; that direction is allowed and stated.
- "Clever" code is treated as malicious. If the agent produces something Tom can't explain in one sentence, it is rejected. This is the one judgment call that stays a judgment call.
- Docstrings enforced by tool (`interrogate --fail-under 100`); each says what the function does not do.
- **WIP limit: one open PR.** Tom's "try to break it" is written as adversarial tests the agent implements, not as manual sessions, so review does not become the bottleneck.

### 0.3 Repository layout

```
ai-audit-trail/
  LICENSE  NOTICE  README.md  SPEC.md  PLAN.md  THREATS.md  CHANGELOG.md  Makefile
  packages/
    audittrail-log/        # library
    audittrail-verify/     # verifier + reconciler CLI; import root audittrail_verify; nothing from audittrail-log
    audittrail-testkit/    # mock model, oracle stub, harness, conformance
  apps/
    gate-stub/          # minimal reference gate (Python)
    gate-stub-go/       # second-language stub (M6)
    consumer-stub/      # verifies, binds, dedups, writes its action log
  tools/
    vectors-go/         # independent vector generator (M0); seed of gate-stub-go
    anchors-pull/       # copies sink receipts to a directory for the verifier (keeps the verifier cloud-free)
  deploy/
    compose.yml  compose.demo.yml  hardening.md  schedules/
  spec/
    record.schema.json  reasons.txt  test-seed.txt  vectors/  vectors.sha256   # vectors/keyring.json is generated
  mutations/            # I*.diff
  .github/workflows/
```

### 0.4 CI (grows per milestone; listed here so nothing is unowned)

M0: lint, type check, schema validates vectors, vector manifest check, denylist/gitleaks, docstring gate, verifier import-linter.
M1: coverage gate on `audittrail-log`; mutation job.
M2: isolated-venv verifier job; benchmark job (reports records/s, does not gate).
M4: harness smoke run against the 90-second schedule.
M5: compose network-absence test; fresh-clone `make demo` job on a clean runner; manifest-list digest pin check.
M6: Go lint/test; conformance job.

## 1. Milestones

### M0 — Contract and spine (2 units)

- Repo (public is fine; see §0.1), license, layout, CI skeleton, pre-commit with gitleaks + local denylist.
- `spec/record.schema.json`, `reasons.txt`, `test-seed.txt`; `spec/vectors/keyring.json` is generated by the vector tool.
- **`tools/vectors-go`**: ~100 lines of Go (JCS library + `crypto/ed25519`) that generates every positive and negative vector in SPEC §11 from the published test seed. Committed output plus `vectors.sha256`; CI fails if a vector changes without a spec version bump. This is the independent oracle for the Python, and the seed of the Go stub.
- README with the isolation statement and "what this does not do." No feature list.
- **Done when (machine-checkable):** CI green; schema validates every positive vector and rejects every negative vector with the expected check number (a tiny JSON-schema-only checker is enough here); manifest check passes.

### M1 — Walking skeleton (2 units)

The goal is something that runs end to end by the end of unit 4, not a finished library.

- `Record` with regex validators (I8), strict parser, JCS, round-trip check, hashing, genesis.
- `Signer` protocol, `SoftwareSigner` (dev-gated, I12).
- `Log.record` with file lock, prev-from-disk, fsync, `boot` record at init (no heartbeat, no anchor yet).
- `Receipt`; `Approved.from_wire` with §6 rules 1–7 and an in-memory `SeenStore`.
- Verifier checks 1–5 only, as a CLI, in `audittrail_verify`, tested against `spec/` vectors.
- A 30-line `gate-stub` and a 30-line `consumer-stub`; two-service compose.
- Pinning tests I1, I2, I3, I4 (chain part), I8, I11, I12, I13; mutation diffs for each.
- **Done when:** `make skeleton` runs the stub, the consumer acts on one receipt and refuses a tampered one, the verifier exits 0 on the resulting log, and every M1 mutation diff turns CI red.

### M2 — Verifier complete, heartbeats, rotation (2 units)

- Verifier checks 6, 7, 9; exit codes 0/2/3/4; `prefix_unverified`; staleness.
- Heartbeats emitted from the request loop with `since_hb`; `boot` record carries the cadence parameters.
- Key rotation: `rotation` record, keyring windows, `rotate_key`, consumer grace (I14).
- Log rotation across files with `fsync(dir)`; torn-line discard at boot with `R_BOOT_TRUNCATED` (I9).
- Benchmark job (`--no-fsync` fixture generator, cached as a CI artifact).
- Pinning tests I5, I9, I14, I15; isolated-venv verifier job.
- **Done when:** fast-restart in compose (kill and restart the gate within 10 s) leaves a verifiable log; every negative vector is rejected with its check number from the isolated venv.

### M3 — Anchors and signer service (2–3 units)

- `AnchorSink` protocol; `FileAnchorSink`; `S3ObjectLockSink` against **MinIO in compose** (bucket created with object locking at creation, PutObject-only access key). The sink test attempts `DeleteObject` and overwrite and asserts they are refused; that is the property that matters, tested locally, with no cloud account.
- `tools/anchors-pull`; verifier check 8 including fork, cadence, and the sink-clock bound; `anchor_max_s` enforcement in `record()`.
- `VaultTransitSigner` against Vault dev mode in compose, sign-only policy; I13 export-path test.
- `init` one-shot container (keypair into Vault, keyring to a volume, MinIO bucket and key).
- Pinning tests I6; mutation diffs.
- **Done when:** a rewritten tail after the last anchor is reported as `anchor_gap` or `fork` by the verifier running from pulled receipts, and the gate refuses to approve once `anchor_max_s` has elapsed with the sink down.

### M4 — Reconciler and consumer (1–2 units)

- Consumer action log (§6 rule 8) with durable `SeenStore` (SQLite).
- Verifier check 10, `unlogged_approval`.
- `build_index`.
- Pinning test I7 (consumer acted, log says reject → `unlogged_approval`).
- **Done when:** a gate stub patched to hand out an unlogged receipt is caught by the reconciler and by nothing else.

### M5 — Test kit and compose demo (3 units)

- Mock model: Converse-shaped endpoint, streaming, trace-file sampling, synthetic default trace; `/chaos` all modes; `/health` reports the actual fault. Tolerance for "reproduces its trace" is numeric: p50 and p95 of `ttft_ms` and `tok_per_s` within 10% of the trace over 1,000 samples.
- Oracle stub with the same contract.
- Harness: schedule file parser; `LoadTestShape`; `/health` confirmation (fail the run within 5 s if the fault did not take); **drain in-flight requests before each mode flip**; worker→master messaging; SQLite per run.
- History check reading from the log via `build_index`; requests classified by **Locust send time joined on `request_id`**, not by gate `ts`; **per-mode expected outcomes in the schedule file** (e.g. `garbage → 0 approve, ≥N reject R_PARSE`); **liveness floor** (minimum approval rate for seeded carts during `ok/ok` windows, so a gate that rejects everything does not pass); consumer action log ⊆ log approvals; bijective diff on `request_id` including signature bytes.
- Apps advertise their dependency URLs at `/deps` so the conformance script can flip chaos on them.
- Conformance script (SPEC §6.5).
- `compose.yml` + `compose.demo.yml`, `make demo` with `--abort-on-container-exit --exit-code-from verifier`, named volumes, 90-second demo schedule, manifest-list digest pins, verifier `depends_on` completion of the harness.
- CI: network-absence test; fresh-clone `make demo` on a clean runner.
- **Done when:** the fresh-clone job passes, and sabotaging the stub in each of three ways (fail-open on oracle timeout; approve-but-log-reject; reject-everything) fails the run with the named finding.

### M6 — Second language and release (2–3 units)

- `gate-stub-go`: grows from `tools/vectors-go`; calls mock model and oracle, decides, writes canonical lines, signs via Vault, heartbeats, `/health`, `/deps`; Dockerfile; Go lint/test CI.
- Passes conformance; reproduces every positive vector byte for byte. **This is the proof that the wire format, not the Python, is the product.**
- `THREATS.md` from SPEC §10; `CHANGELOG.md`; tag `v0.1.0`.
- **Done when:** SPEC §13 acceptance criteria all pass in CI.

### Deferred to v0.2 (written down so they stop being argued about)

The ref (Cedar policy, oracle adapters, Candidate typing). `KmsSigner` (AWS KMS does support Ed25519 — `ECC_NIST_EDWARDS25519`, RAW message type only — so this is an adapter, not a schema change; it waits only for someone with an AWS account to want it). Rekor sink with inclusion proofs in `proof`. cosign signing and SBOM. Checkpoint signatures if volume ever demands.

**Typestate packages (v0.2, can start after M1 in a second session).** `Untrusted → Candidate → Validated` as a small package per language — Python, TypeScript, Rust — under `packages/typestate-*`. Enforcement strength differs and the README says so: Rust enforces it (private constructors, newtypes, no `Display` for `Untrusted`); TypeScript needs branded types *plus* a runtime wrapper, since types are erased; Python is convention plus the grep tests. Two things make them more than documentation: `Candidate.canonical_bytes()` must reproduce the `cart_hash` vectors byte for byte in every language, and `Validated` is constructible only from a verified receipt (it is `Approved.from_wire` with a different name). A language's package is "done" when it passes the vectors, not when it compiles. A Candidate is a closed, per-kind typed schema: every leaf is regex- or enum-validated, nothing is passed through from a vendor payload, and no kind nests deeper than 5 levels counting the root object as level 1, as SPEC §3.1 counts a record line (issue #11). 5 is a ceiling, not a target; it exists so that what the model requested stays glanceable by a human. Documents belong behind `input_ref`.

Blog posts: after M2 (the log and the verifier) and after M5 (the harness). Sanitized field notes, not launches.

## 2. Sequence

```
M0 ──► M1 ──► M2 ──► M3 ──► M4 ──► M5 ──► M6
                 (M5's mock model + oracle stub can start after M1 if a second session is free)
```

Roughly 15–17 units on the milestone sums; call it 18–22 with the things that always appear. At one unit per weekend that is five months. Do not plan against the number; plan against the walking skeleton being runnable by unit 4.

## 3. Risks

| Risk | Signal | Response |
|---|---|---|
| Contamination by use | any commit from billed hours, a client machine, or for a client project | Separation is the legal basis; see §0.1. Written approval before any use in an engagement. |
| Scope creep into the ref | "while we're here, policy…" | v0.2. Interface only. |
| Verifier purity eroded by tooling | any `audittrail` import in `audittrail_verify`; a fixture built by `audittrail-log` | import-linter + isolated-venv job fail the build. |
| Vectors become a snapshot of the Python | Python changes and the vectors "need updating" | Vectors come from the Go tool; a change requires a spec version bump; CI blocks otherwise. |
| Cloud dependencies stall the project | needing an AWS account to progress | None required: Vault and MinIO in compose carry v0.1. |
| Torn/partial-line handling turns into hand-editing logs | an operator opens a log in an editor | Boot discard rule + `R_BOOT_TRUNCATED` make the recovery automatic and recorded. |
| Agent-written crypto that looks fine | anything in signing/canonicalization | Go reproduces every vector byte for byte, from M0. |
| Solo-project stall | no commits for three weeks | The wall is starting, not doing. Re-entry task is always "run `make skeleton`, break one thing, write the test." WIP limit of one keeps the backlog from becoming the wall. |

## 4. Definition of done, project-wide

A thing is done when: its positive test exists and passes; its mutation diff exists, applies to HEAD, and turns CI red; the docstring gate passes; the PR template's leak question is answered; and no sentence in it would require the reader to have seen a work system to understand it. "Tom tried to break it" is satisfied by an adversarial test in the PR, not by a session.

## 5. Review log (2026-10-10)

Delivery review findings accepted: vectors generated independently in M0 (chicken-and-egg); verifier separation made mechanical (`audittrail_verify` root, lockfile, fixtures-only tests, isolated venv, import-linter, deliberate duplication of canonicalization); negative/chain vectors, published seed, keyring format, line-is-canonical; IP section rewritten after reading the actual engagement terms (no conception clause; separation-by-use and written-approval rules instead); six leak channels each closed by a mechanism; cloud items replaced by Vault + MinIO in compose, cosign/SBOM deferred (the reviewer's claim that KMS lacks Ed25519 was checked against AWS documentation and is wrong; KMS is deferred for the cloud-account reason only); perf target → benchmark with `--no-fsync` fixtures; every `docker compose up` failure mode listed by the reviewer addressed (`init` container, MinIO as the sink service, exit-code flags, verifier `depends_on`, named volumes, manifest-list digests, 90-second demo); walking skeleton by unit 4, WIP limit, adversarial tests instead of manual breaking; previously unowned items assigned (`build_index`, keyring, `DecisionFields`, heartbeat loop, rotation, `anchors-pull`, stub decision logic, CI items); mutation mechanism defined as committed diffs; judgment-call done criteria converted to machine checks; Go stub given its own milestone; `boot` field; `/deps` endpoint. Estimate raised to 18–22 units.

Rejected: none outright. One modification: the reviewer suggested Node as an alternative vector generator; Go chosen because it becomes the second-language stub.
