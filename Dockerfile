# syntax=docker/dockerfile:1

# Base images are pinned by digest, same policy as the CI container pins.
FROM ghcr.io/astral-sh/uv:latest@sha256:a7aed3216253ee804de3e2d8afa5073baa1a177335345d43845cd4165e43b711 AS uv

FROM python:3.12-slim@sha256:f77ac9e44ae96ef2c90b8053ea08c31f8be030f824196b0ae4db6d462c84e51f

LABEL org.opencontainers.image.source="https://github.com/emiliano-go/trustsight" \
      org.opencontainers.image.title="trustsight" \
      org.opencontainers.image.description="CLI-based AUR package update vetting tool" \
      org.opencontainers.image.licenses="MIT"

COPY --from=uv /uv /uvx /usr/local/bin/

ENV UV_LINK_MODE=copy \
    UV_COMPILE_BYTECODE=1 \
    # Use the base image's interpreter: a uv-managed Python lands under the
    # build user's HOME and breaks once the image runs as `ts`.
    UV_PYTHON_PREFERENCE=system
# `.python-version` pins a patch version older than the base image's, which
# would make uv download a managed interpreter; --python overrides it.

WORKDIR /app

# Install the locked dependencies before copying the source so the expensive
# layer is only invalidated when the lock or the manifest moves.  The project
# itself is installed in the second sync, after the source is present.
COPY pyproject.toml uv.lock ./
RUN uv sync --locked --no-install-project --python /usr/local/bin/python3

COPY . .
RUN uv sync --locked --python /usr/local/bin/python3

# The scanner writes its database and config under HOME; give the non-root
# user a real one with the XDG directories it creates at runtime.
RUN useradd --create-home --shell /usr/sbin/nologin ts \
    && mkdir -p /home/ts/.local/share/trustsight /home/ts/.config/trustsight \
    && chown -R ts:ts /home/ts

ENV HOME=/home/ts
USER ts

HEALTHCHECK --interval=5m --timeout=10s --retries=3 \
    CMD ["/app/.venv/bin/trustsight", "--version"]

ENTRYPOINT ["/app/.venv/bin/trustsight"]
CMD ["--help"]
