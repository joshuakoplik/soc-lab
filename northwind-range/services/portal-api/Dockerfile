FROM python:3.12-slim
WORKDIR /app
COPY app.py .
EXPOSE 8000
HEALTHCHECK --interval=5s --timeout=3s --retries=5 CMD python3 -c "import urllib.request; urllib.request.urlopen('http://localhost:8000/health', timeout=2)" || exit 1
CMD ["python3", "app.py"]
