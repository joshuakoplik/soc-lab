# Build context is the repo root (see docker-compose.yml) so policy/ can be
# copied in alongside this service's own code -- SPEC.md §7's "single
# policy module... not duplicated logic" shared across services.
FROM python:3.12-slim
WORKDIR /app
COPY services/portal-api/requirements.txt .
RUN apt-get update && apt-get upgrade -y && rm -rf /var/lib/apt/lists/* \
    && pip install --no-cache-dir -r requirements.txt
COPY services/portal-api/app.py .
COPY policy/ /app/policy/
EXPOSE 8000
HEALTHCHECK --interval=5s --timeout=3s --retries=10 CMD python3 -c "import urllib.request; urllib.request.urlopen('http://localhost:8000/health', timeout=2)" || exit 1
CMD ["uvicorn", "app:app", "--host", "0.0.0.0", "--port", "8000"]
