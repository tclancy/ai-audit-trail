# vectors-go

**M0 task.** A Go program (~100 lines) that generates every vector in SPEC §11 from `spec/test-seed.txt` and writes them under `spec/vectors/` plus `spec/vectors.sha256`.

Rules:
- Dependencies: one RFC 8785 (JCS) library and `crypto/ed25519`. Nothing else.
- Canonical line construction per SPEC §3.2: JCS(record minus sig) → sign(DOMAIN || body) → insert sig → JCS(full record) → `\n`.
- Domains per SPEC §3.3, exactly, including the trailing NUL.
- Negative vectors must each break exactly one rule, named in the sidecar `.expect`.
- `go run . --out <dir>` is the only interface; CI regenerates and diffs.

This tool is the oracle for the Python. When they disagree, the Python is wrong. It grows into `apps/gate-stub-go` in M6.
