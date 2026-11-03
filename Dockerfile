# Not built or run in the authoring environment (no Docker there). Review before use.
FROM python:3.12-slim
RUN apt-get update && apt-get install -y --no-install-recommends tesseract-ocr && rm -rf /var/lib/apt/lists/*
WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt "psycopg[binary]>=3.1"
COPY packages ./packages
COPY services ./services
ENV PYTHONPATH=/app/packages/rules:/app/packages/connectors:/app/services/api PYTHONUNBUFFERED=1
RUN useradd -r -u 10001 ssi && mkdir -p /data/evidence && chown ssi /data/evidence
USER ssi
EXPOSE 8000
HEALTHCHECK CMD python -c "import urllib.request, os; p = os.environ.get('PORT', '8000'); urllib.request.urlopen(f'http://localhost:{p}/v1/health')"
CMD ["sh", "-c", "cd services/api && alembic upgrade head && uvicorn app.main:app --host 0.0.0.0 --port ${PORT:-8000}"]
