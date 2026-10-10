# ai-audit-trail

A signed, append-only, independently verifiable decision log for systems where an LLM-driven component may **request** consequential actions but never **authorize** them — plus a test kit that runs such systems under load with scheduled faults and checks the log afterward.

> **This does not make a system safe.** It makes decisions attributable, bounds how far back history can be rewritten, and makes unlogged approvals detectable. It does not judge whether a request was a good idea, it does not store content, and it contains no defense against a compromised gate other than evidence. Read `SPEC.md` §1.3 and §10 before relying on it for anything.

> **The compose topology demonstrates reach constraints. It is not a security boundary.** Containers share the host kernel. Deploying an agent or any document renderer in production requires a VM-class boundary (Firecracker, gVisor, Kata) and the hardening profile in `deploy/hardening.md`.

## Status

Pre-alpha. The wire format (`SPEC.md` §3) is the product; the Python is one implementation of it. Nothing here has been run against a real system. See `TASKS.md` for what exists.

## Documents

- `SPEC.md` — the contract: wire format, invariants, verifier checks, consumer rules, threat model.
- `PLAN.md` — milestones and the engineering rules.
- `CLAUDE.md` — instructions for agents working in this repository. Humans should read it too; it is the short version of the rules.
- `TASKS.md` — the queue.
- `SECURITY.md` — how to report a problem.

## License

Apache-2.0. See `LICENSE` and `NOTICE`.
