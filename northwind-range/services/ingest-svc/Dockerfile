# Repo-root context (see docker-compose.yml) so telemetry_writer.py can be
# copied in alongside this service's own code -- SPEC.md §10 milestone
# 12's first shared-module dependency for this service (never needed
# policy/ before now).
FROM python:3.12-slim
WORKDIR /app
COPY services/ingest-svc/requirements.txt .
RUN apt-get update && apt-get upgrade -y && rm -rf /var/lib/apt/lists/* \
    && pip install --no-cache-dir -r requirements.txt
COPY services/ingest-svc/app.py .
COPY telemetry_writer.py /app/telemetry_writer.py
EXPOSE 8000
HEALTHCHECK --interval=5s --timeout=3s --retries=10 CMD python3 -c "import urllib.request; urllib.request.urlopen('http://localhost:8000/health', timeout=2)" || exit 1
CMD ["uvicorn", "app:app", "--host", "0.0.0.0", "--port", "8000"]
