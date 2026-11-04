# syntax=docker/dockerfile:1

# --- build stage -------------------------------------------------------------
# Dependencies are built into a virtualenv here so the compiler toolchain never
# reaches the runtime image. asyncpg, cryptography and psycopg2 ship x86_64
# wheels, but keeping build-essential available means a version without one
# still installs.
FROM python:3.12-slim AS builder

ENV PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1

RUN apt-get update \
 && apt-get install -y --no-install-recommends build-essential libpq-dev \
 && rm -rf /var/lib/apt/lists/*

RUN python -m venv /opt/venv
ENV PATH="/opt/venv/bin:$PATH"

COPY requirements.txt .
# psycopg2 is needed only by Alembic: its DDL path is synchronous, while the
# application itself talks to PostgreSQL exclusively through asyncpg.
RUN pip install --upgrade pip \
 && pip install -r requirements.txt \
 && pip install "psycopg2-binary>=2.9,<3"


# --- runtime stage -----------------------------------------------------------
FROM python:3.12-slim AS runtime

# Recorded at build time so a running container can report exactly what it is,
# through /health and /shield health.
ARG APP_VERSION=dev
ARG GIT_COMMIT=unknown

ENV APP_VERSION=${APP_VERSION} \
    GIT_COMMIT=${GIT_COMMIT} \
    # Unbuffered so log lines reach `docker logs` immediately instead of sitting
    # in a pipe buffer until the process exits.
    PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    # Surfaces the faulthandler traceback if the interpreter dies hard.
    PYTHONFAULTHANDLER=1 \
    PATH="/opt/venv/bin:$PATH"

# tini reaps zombies and forwards SIGTERM to Shield as PID 1, which is what makes
# the graceful-shutdown path (close gateway, stop scheduler, dispose pool) run on
# `docker stop` instead of being killed mid-write.
RUN apt-get update \
 && apt-get install -y --no-install-recommends tini \
 && rm -rf /var/lib/apt/lists/*

COPY --from=builder /opt/venv /opt/venv

WORKDIR /app

# Unprivileged, with a fixed uid so any bind-mounted path has predictable
# ownership. Shield writes nothing to disk by default (logs go to stdout).
RUN useradd --create-home --uid 10002 --shell /usr/sbin/nologin shield

COPY --chown=shield:shield . .

USER shield

EXPOSE 8080

# Probes /ready, so the container is reported unhealthy while PostgreSQL or the
# gateway is unreachable. start-period covers migrations and the initial connect.
HEALTHCHECK --interval=30s --timeout=5s --start-period=90s --retries=3 \
    CMD ["python", "healthcheck.py"]

ENTRYPOINT ["tini", "--", "/app/deploy/docker-entrypoint.sh"]
CMD ["python", "-u", "-m", "shield"]
