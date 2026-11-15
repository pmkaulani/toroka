# -------------------------------------------------
# Stage 1: Build Enterprise Workbench
# -------------------------------------------------
FROM node:22-alpine AS workbench-build

WORKDIR /workbench

COPY apps/enterprise-workbench/package.json .
COPY apps/enterprise-workbench/package-lock.json .

RUN npm ci

COPY apps/enterprise-workbench/ ./

RUN npm run build


# -------------------------------------------------
# Stage 2: Python dependencies
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
# Stage 3: Production runtime
# -------------------------------------------------
FROM python:3.12-slim AS runtime

WORKDIR /app

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PATH="/app/.venv/bin:$PATH" \
    PYTHONPATH="/app/services/enterprise_api:/app/packages/enterprise:/app/packages/core"

RUN groupadd --system --gid 10001 toroka && \
    useradd --system --uid 10001 \
    --gid toroka \
    --home-dir /app \
    --shell /usr/sbin/nologin toroka && \
    mkdir -p /app/tmp && \
    chown -R toroka:toroka /app

COPY --from=python-deps --chown=10001:10001 \
    /app/.venv /app/.venv

COPY --chown=10001:10001 packages/core \
    /app/packages/core

COPY --chown=10001:10001 packages/enterprise \
    /app/packages/enterprise

COPY --chown=10001:10001 services/enterprise_api \
    /app/services/enterprise_api

COPY --from=workbench-build --chown=10001:10001 \
    /workbench/dist \
    /app/apps/enterprise-workbench/dist

USER 10001:10001

EXPOSE 8101

CMD ["uvicorn", \
     "toroka_enterprise_api.main:create_app_from_env", \
     "--factory", \
     "--app-dir", "services/enterprise_api", \
     "--host", "0.0.0.0", \
     "--port", "8101"]
