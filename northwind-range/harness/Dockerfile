FROM python:3.12-slim
RUN apt-get update && apt-get install -y --no-install-recommends iptables \
    && rm -rf /var/lib/apt/lists/*
WORKDIR /app
COPY app.py entrypoint.sh .
RUN chmod +x entrypoint.sh
EXPOSE 8000
HEALTHCHECK --interval=5s --timeout=3s --retries=5 CMD python3 -c "import urllib.request; urllib.request.urlopen('http://localhost:8000/health', timeout=2)" || exit 1
ENTRYPOINT ["./entrypoint.sh"]
CMD ["python3", "app.py"]
