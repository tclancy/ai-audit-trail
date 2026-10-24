# syntax=docker/dockerfile:1
# One image for the M1 skeleton: the workspace installed without development tools. Each
# service in compose.yml picks its entry point (gate-stub, consumer-stub, the verifier
# wrapper). Both bases are pinned by manifest-list digest (SPEC §9.3); bump the tag and the
# digest together. No secrets are baked in: the gate draws its dev key at start-up.
FROM python:3.12-slim@sha256:a0f57064cbdcd6285fa45f51237ab0b35ea8ebaed06a1f5973e89e19dfb86704
COPY --from=ghcr.io/astral-sh/uv:0.8.13@sha256:4de5495181a281bc744845b9579acf7b221d6791f99bcc211b9ec13f417c2853 /uv /bin/uv

ENV UV_PROJECT_ENVIRONMENT=/opt/venv \
    UV_LINK_MODE=copy \
    PATH=/opt/venv/bin:$PATH

WORKDIR /app
COPY pyproject.toml uv.lock ./
COPY packages ./packages
COPY apps ./apps
COPY deploy/skeleton-verify.sh ./deploy/skeleton-verify.sh
RUN uv sync --locked --no-dev --all-packages --no-editable
