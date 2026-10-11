# TASKS — current milestone and the queue

Agents: take the first unchecked item in the **current** milestone. One PR per item. Do not start the next milestone until every item in the current one is checked and the milestone's "done when" in `PLAN.md` holds.

Humans: keep this file honest. Check items only when merged.

## Current milestone: M0 — Contract and spine

- [x] Repository created, Apache-2.0, cloned. (human)
- [x] Scaffold: layout, `CLAUDE.md`, `TASKS.md`, `SPEC.md`, `PLAN.md`, package skeletons, CI skeleton, `spec/record.schema.json`, `spec/reasons.txt`, `spec/keyring.example.json`. (scaffold commit)
- [x] Contract reviewed 2026-10-10. The governing terms assign Work Product (output of the billed services) only; there is no conception or related-to-business clause, so a public repository is fine. Two standing constraints from that review: (1) nothing in this repository may be derived from any client's confidential information (the PR template's leak question is a contractual requirement, not a courtesy); (2) **no use of this project in any client engagement without the client/platform's written approval**, which is also the document that records the project as the author's own. (human)
- [x] `tools/vectors-go`: Go program that generates every positive and negative vector in SPEC §11 from the published test seed in `spec/test-seed.txt`, writes them under `spec/vectors/`, and writes `spec/vectors.sha256`. Uses a JCS library and `crypto/ed25519`; no other dependencies. Include a `README.md` stating that this tool is the reference for canonical bytes and is not the code under test.
- [x] CI: `vectors` job — regenerate with `tools/vectors-go` and fail if output differs from committed vectors; `manifest` job — `sha256sum -c spec/vectors.sha256`.
- [x] CI: `schema` job — a JSON-Schema-only checker (no project code) validates every positive vector and rejects every negative vector with the expected check number recorded in each negative vector's sidecar `.expect` file.
- [x] CI: lint (`ruff`), types (`mypy --strict`), docstrings (`interrogate --fail-under 100`), `import-linter` contract forbidding `audittrail` imports from `audittrail_verify`.
- [x] Pre-commit: `gitleaks` plus a hook that runs a **local, uncommitted** denylist file (`.denylist.local`, gitignored) over staged content, commit messages, and PR bodies.
- [x] `README.md`: isolation statement (SPEC §9.4) and "what this does not do" above the fold; one-paragraph description; no feature list. Already drafted; agent reviews against SPEC §1.3 and §9.4 and fixes drift.
- [x] `SECURITY.md`: disclosure address, response commitment, supported versions, and the wire-format versioning promise (schema `v` changes only on a major release; old records verify forever).
- [X] `SECURITY.md`: the contact email is `tclancy@gmail.com`, in the file, as the route for reporters who cannot use GitHub. (Tom, 2026-10-11)
- [X] M0 done check: CI green; every positive vector validates; every negative vector rejected with its check number; manifest check passes.

## Next: M1 — Walking skeleton (see PLAN.md)

- [ ] `audittrail.Record` with regex validators for every string field (I8), strict parser (duplicate keys, floats, non-ASCII, unknown fields all rejected), JCS serialization, round-trip check, `sha256` hashing, zero-hash genesis. Tests against `spec/vectors/`.
- [ ] Nesting depth 5 and derived line length per SPEC §3.1/§3.2/§5 (issue #11): byte-level depth counter and the 1398-byte bound in `parse_line`, the matching counter in the Go checker's `roundTrips`, the three §11 vectors from `tools/vectors-go` (spec version bump: human), mutation diffs for both bounds.
- [ ] `Signer` protocol; `SoftwareSigner` gated on `AUDITTRAIL_DEV=1` (I12). Test: signs the published seed's vectors bit-identically.
- [ ] `Log.record` with file lock, prev-from-disk, `fsync`, `boot` record at init; `LogUnavailable` on any failure (I2); refuse re-genesis.
- [ ] `Receipt`; `Approved.from_wire` enforcing SPEC §6 rules 1–7 with an in-memory `SeenStore` (I1).
- [ ] `audittrail_verify` CLI: checks 1–5, exit codes 0/2/3/4; tests read only `spec/`.
- [ ] Domain separation test (I11); key-material grep test (I13).
- [ ] 30-line `apps/gate-stub` and `apps/consumer-stub`; two-service `deploy/compose.yml`; `make skeleton`.
- [ ] Mutation diffs for I1, I2, I3, I4 (chain), I8, I11, I12; CI mutation job; I15 apply-check.
- [ ] Narrated demo, five scenes: `demo/demo.sh` (≈80 lines) against `make skeleton`, printing what happened after each scene. The agent is a shell loop posting carts; the README says so and why (requests are untrusted bytes whoever produced them). Scenes: (1) cart matches oracle → approve, receipt, consumer acts — show record line and action line side by side; (2) same account, different amount → `R_ORACLE_MISMATCH`, consumer receives nothing; (3) scene-1 receipt delivered twice → refused by `SeenStore`, then with a different cart → refused by `cart_hash`; (4) `sed` one byte in the log → `audittrail-verify` exit 2 naming the line, restore → exit 0; (5) oracle down, three carts → three `R_ORACLE_UNAVAILABLE`, zero approvals. Scene 6 (signed-but-unwritten receipt caught only by the reconciler) is added in M4. No anchors in the demo until M3. `make demo` runs it; it is the M1 acceptance artifact a stranger can run.
- [ ] M1 done check per PLAN.md.

## Later milestones

M2 verifier complete + heartbeats + rotation · M3 anchors (MinIO) + Vault signer · M4 reconciler + consumer action log + demo scene 6 (`unlogged_approval`) · M5 test kit + compose demo · M6 Go stub + release · v0.2: typestate packages (`Untrusted → Candidate → Validated`) in Python, TypeScript, Rust, each proven against the `cart_hash` vectors. Details in `PLAN.md`.
