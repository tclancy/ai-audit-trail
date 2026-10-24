# deploy

- `compose.yml` — M1: gate-stub, consumer-stub, verifier (one-shot). Grows per milestone. `make skeleton` runs it: gate up and healthy, the consumer's scenario once, then `skeleton-verify.sh`, whose verdict is the exit code.
- `Dockerfile` — the one image the M1 services share: the workspace installed without dev tools, bases pinned by manifest-list digest.
- `skeleton-verify.sh` — reads the verifier's report and passes only when no check failed, the prefix is verified, and the log is the boot plus the scenario's one decision (the M1 verifier exits 4 on a sound log because checks 6–10 do not exist yet).
- `compose.demo.yml` — M5: full topology with explicit networks (SPEC §9.2), Vault, MinIO, mock model, oracle stub, Locust, 90-second schedule.
- `hardening.md` — the profile required for any agent or renderer container in production. The compose files are not a security boundary.
- `schedules/` — fault schedules (SPEC §6.3 format).
