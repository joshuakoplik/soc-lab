# Tiny internal web app. Everything it needs is installed at build time; it
# never reaches the internet at runtime (the flock networks are lab-internal).
FROM python:3.12-slim

RUN pip install --no-cache-dir flask==3.0.3 psycopg[binary]==3.2.1 redis==5.0.7

WORKDIR /app
COPY app.py /app/app.py

EXPOSE 80
# gunicorn would be more production-ish, but flask's built-in server keeps the
# image minimal and logs a combined-format access line per request, which is
# exactly the telemetry we want. Threaded so backend calls don't serialize.
CMD ["python", "app.py"]
