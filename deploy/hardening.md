# Hardening profile (required for agent and renderer containers in production)

Not written yet. Will cover: VM-class boundary (Firecracker / gVisor / Kata), rootless, read-only root filesystem, `no-new-privileges`, all capabilities dropped, seccomp profile, no network for the renderer, egress allowlist for the agent, no secrets in environment, resource caps (CPU, memory, pids, file size) for the renderer as DoS controls.
