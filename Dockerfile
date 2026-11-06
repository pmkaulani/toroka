# Production container for Toroka
FROM python:3.12-slim

RUN apt-get update && apt-get install -y --no-install-recommends tesseract-ocr && rm -rf /var/lib/apt/lists/*

WORKDIR /app

RUN useradd -r -u 10001 -d /app ssi && mkdir -p /data/evidence && chown -R ssi:ssi /data

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt "psycopg[binary]>=3.1"

COPY packages ./packages
COPY services ./services

RUN chown -R ssi:ssi /app /data

ENV PYTHONPATH=/app/packages/rules:/app/packages/connectors:/app/services/api \
    PYTHONUNBUFFERED=1 \
    DATABASE_URL="sqlite:////data/ssi.db" \
    STORAGE_DIR="/data/evidence"

USER ssi
EXPOSE 8000

CMD ["sh", "-c", "cd services/api && alembic upgrade head && exec uvicorn app.main:app --host 0.0.0.0 --port ${PORT:-8000}"]
