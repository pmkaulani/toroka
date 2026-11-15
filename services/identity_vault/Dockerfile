# -------------------------------------------------
# Stage 1: Python dependencies
# -------------------------------------------------
FROM python:3.12-slim AS python-deps

WORKDIR /app

ENV UV_PROJECT_ENVIRONMENT=/app/.venv

RUN pip install --no-cache-dir uv

COPY pyproject.toml uv.lock ./

RUN uv sync \
    --frozen \
    --no-dev \
    --extra postgres \
    --no-install-project


# -------------------------------------------------
# Stage 2: Production runtime
# -------------------------------------------------
FROM python:3.12-slim AS runtime

WORKDIR /app

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PATH="/app/.venv/bin:$PATH" \
    PYTHONPATH="/app/services/identity_vault"

RUN groupadd --system --gid 10001 toroka && \
    useradd --system --uid 10001 \
    --gid toroka \
    --home-dir /app \
    --shell /usr/sbin/nologin toroka && \
    mkdir -p /app/tmp && \
    chown -R toroka:toroka /app

COPY --from=python-deps --chown=10001:10001 \
    /app/.venv /app/.venv

COPY --chown=10001:10001 services/identity_vault \
    /app/services/identity_vault

USER 10001:10001

EXPOSE 8200

CMD ["uvicorn", \
     "toroka_identity_vault.main:create_app_from_env", \
     "--factory", \
     "--app-dir", "services/identity_vault", \
     "--host", "0.0.0.0", \
     "--port", "8200"]
