#!/usr/bin/env python3
"""A shallow JSON REST stub backed by PostgreSQL.

Each request runs a real query (east-west traffic to its DB NPC) and returns
JSON. Access lines go to stdout in combined format for Wazuh's web decoder.
"""
import datetime
import json
import os
import sys

from flask import Flask, request, Response

try:
    import psycopg
except Exception:  # pragma: no cover
    psycopg = None

APP_NAME = os.environ.get("APP_NAME", "API")
DB_HOST = os.environ.get("DB_HOST")
DB_USER = os.environ.get("DB_USER", "reporting")
DB_PASSWORD = os.environ.get("DB_PASSWORD", "r3port-only")
DB_NAME = os.environ.get("DB_NAME", "appdb")

app = Flask(__name__)


def _query(sql):
    if not (psycopg and DB_HOST):
        return None
    try:
        with psycopg.connect(host=DB_HOST, user=DB_USER, password=DB_PASSWORD,
                             dbname=DB_NAME, connect_timeout=3) as conn:
            with conn.cursor() as cur:
                cur.execute(sql)
                return cur.fetchone()
    except Exception:
        return None


@app.route("/health")
def health():
    return Response(json.dumps({"status": "ok"}), mimetype="application/json")


@app.route("/v1/orders")
def orders():
    row = _query("SELECT count(*) FROM invoices")
    return Response(json.dumps({"orders": row[0] if row else None}),
                    mimetype="application/json")


@app.route("/v1/config")
def config():
    return Response(json.dumps({"app": APP_NAME, "version": "1.4.2"}),
                    mimetype="application/json")


@app.route("/")
def index():
    return Response(json.dumps({"service": APP_NAME, "endpoints": ["/health", "/v1/orders", "/v1/config"]}),
                    mimetype="application/json")


@app.after_request
def _access_log(resp):
    env = request.environ
    ts = datetime.datetime.now().strftime("%d/%b/%Y:%H:%M:%S +0000")
    line = (env.get("REQUEST_METHOD", "-") + " " + env.get("PATH_INFO", "-") +
            " " + env.get("SERVER_PROTOCOL", "HTTP/1.1"))
    try:
        length = resp.calculate_content_length() or 0
    except Exception:
        length = 0
    print(f'{env.get("REMOTE_ADDR","-")} - - [{ts}] "{line}" {resp.status_code} {length} '
          f'"{env.get("HTTP_REFERER","-")}" "{env.get("HTTP_USER_AGENT","-")}"', flush=True)
    return resp


if __name__ == "__main__":
    import logging
    logging.getLogger("werkzeug").setLevel(logging.ERROR)
    print(f"[api-svc] {APP_NAME} starting; db={DB_HOST}", file=sys.stderr, flush=True)
    app.run(host="0.0.0.0", port=80, threaded=True)
