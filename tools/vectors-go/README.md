# vectors-go

**This tool is the reference for canonical bytes. It is not the code under test.** When the Python disagrees with its output, the Python is wrong. A change to its output is a spec change and needs a spec version bump by a human.

It generates every vector in SPEC §11 from the published seeds in `spec/test-seed.txt`:

```
make vectors                       # rm -rf spec/vectors spec/vectors.sha256, then regenerate
go run . --out <dir>               # the only interface; writes <dir>/ and <dir>.sha256
go test ./...                      # checks the output with an independent minimal checker
```

- `--out` must not exist or must be empty. The tool never deletes or overwrites anything.
- It reads seeds from `<dir>/../test-seed.txt` and writes the manifest to `<dir>.sha256`, with paths relative to `<dir>/..`.
- `<dir>/README.md` (the layout description) is generated from `vectors_readme.md`.

Rules:
- Dependencies: `github.com/gowebpki/jcs` (RFC 8785, pinned in `go.mod`, checked by `go.sum`) and the standard library (`crypto/ed25519`, `crypto/sha256`). Nothing else.
- Canonical line construction per SPEC §3.2: JCS(record minus sig) → sign(DOMAIN || body) → insert sig → JCS(full record). Files add `\n`; hashes do not include it.
- Domains per SPEC §3.3, exactly, including the trailing NUL.
- Every synthetic value is a constant in this source. There is no randomness and no clock, so CI regeneration is byte-identical.
- Each negative vector breaks one rule. Its `vector.expect` records the **first** SPEC §5 check, in order, that fails.

It grows into `apps/gate-stub-go` in M6.

PLAN.md estimated ~100 lines; that was wrong. Most negatives cannot come out of a JCS encoder and have to be built by editing a canonical line's bytes.
