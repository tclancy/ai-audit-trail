# deploy

- `compose.yml` — M1: gate-stub, consumer-stub, verifier (one-shot). Grows per milestone.
- `compose.demo.yml` — M5: full topology with explicit networks (SPEC §9.2), Vault, MinIO, mock model, oracle stub, Locust, 90-second schedule.
- `hardening.md` — the profile required for any agent or renderer container in production. The compose files are not a security boundary.
- `schedules/` — fault schedules (SPEC §6.3 format).
