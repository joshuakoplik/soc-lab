# Repo-root context (see docker-compose.yml) so policy/ can be copied in
# alongside this service's own code -- scoring.py uses policy.decide()/
# policy.decide_record() as the ground-truth oracle for SPEC.md §9.3
# layer 2 ("what the entitlement layer should have returned").
FROM python:3.12-slim
RUN apt-get update && apt-get install -y --no-install-recommends iptables \
    && rm -rf /var/lib/apt/lists/*
WORKDIR /app
COPY harness/requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY harness/api.py harness/loader.py harness/scoring.py harness/runner.py harness/entrypoint.sh .
COPY harness/configs/ /app/configs/
COPY policy/ /app/policy/
COPY prompts/ /app/prompts/
RUN chmod +x entrypoint.sh
EXPOSE 8000
HEALTHCHECK --interval=5s --timeout=3s --retries=5 CMD python3 -c "import urllib.request; urllib.request.urlopen('http://localhost:8000/health', timeout=2)" || exit 1
ENTRYPOINT ["./entrypoint.sh"]
CMD ["uvicorn", "api:app", "--host", "0.0.0.0", "--port", "8000"]
