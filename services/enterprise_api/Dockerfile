FROM python:3.12-slim

WORKDIR /app

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONPATH=/app/services/enterprise_api:/app/packages/enterprise:/app/packages/core

COPY pyproject.toml uv.lock ./
RUN pip install --no-cache-dir uv && \
    uv sync --frozen --no-dev --extra postgres

COPY packages/core /app/packages/core
COPY packages/enterprise /app/packages/enterprise
COPY services/enterprise_api /app/services/enterprise_api

EXPOSE 8101

CMD ["uv", "run", "uvicorn", "toroka_enterprise_api.main:create_app_from_env", "--factory", "--app-dir", "services/enterprise_api", "--host", "0.0.0.0", "--port", "8101"]
