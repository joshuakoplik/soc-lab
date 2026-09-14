#!/usr/bin/env python3
"""A shallow internal web app.

Each request touches the backends the flock wired us to: a SELECT against
PostgreSQL and a GET/INCR against Redis. That produces realistic east-west
traffic (app<->db, app<->cache) on the lab bridge, on top of the north-south
client traffic. Responses are deliberately boring.

Access lines are emitted to stdout in Apache/nginx *combined* format so Wazuh's
web-accesslog decoder parses them once npc-range's tailer syslog-wraps them.
The stub is defensive: if a backend is briefly unavailable it still returns a
page (degraded), because a crash-looping app would look nothing like a real one.
"""
import datetime
import os
import sys

from flask import Flask, request, Response

try:
    import psycopg
except Exception:  # pragma: no cover - image always has it
    psycopg = None
try:
    import redis as redis_lib
except Exception:  # pragma: no cover
    redis_lib = None

APP_NAME = os.environ.get("APP_NAME", "Internal App")
DB_HOST = os.environ.get("DB_HOST")
DB_USER = os.environ.get("DB_USER", "reporting")
DB_PASSWORD = os.environ.get("DB_PASSWORD", "r3port-only")
DB_NAME = os.environ.get("DB_NAME", "appdb")
REDIS_HOST = os.environ.get("REDIS_HOST")

app = Flask(__name__)


def _db_headcount():
    if not (psycopg and DB_HOST):
        return None
    try:
        with psycopg.connect(host=DB_HOST, user=DB_USER, password=DB_PASSWORD,
                             dbname=DB_NAME, connect_timeout=3) as conn:
            with conn.cursor() as cur:
                cur.execute("SELECT count(*) FROM employees")
                return cur.fetchone()[0]
    except Exception:
        return None


def _cache_hit():
    if not (redis_lib and REDIS_HOST):
        return None
    try:
        r = redis_lib.Redis(host=REDIS_HOST, socket_connect_timeout=3)
        return r.incr("app:page_views")
    except Exception:
        return None


@app.route("/")
def index():
    heads = _db_headcount()
    views = _cache_hit()
    body = (f"<!doctype html><title>{APP_NAME}</title>"
            f"<h1>{APP_NAME}</h1>"
            f"<p>Directory: {heads if heads is not None else 'n/a'} staff on file.</p>"
            f"<p>Session store online: {'yes' if views is not None else 'no'}.</p>")
    return Response(body, mimetype="text/html")


@app.route("/health")
def health():
    return Response("ok\n", mimetype="text/plain")


@app.route("/directory/")
def directory():
    heads = _db_headcount()
    return Response(f"<title>Staff Directory</title><p>{heads or 0} records.</p>",
                    mimetype="text/html")


def _log_combined(env, resp_status, length):
    """Emit one Apache/nginx combined-format line to stdout."""
    ip = env.get("REMOTE_ADDR", "-")
    ident = "-"
    user = "-"
    ts = datetime.datetime.now().strftime("%d/%b/%Y:%H:%M:%S %z") or \
        datetime.datetime.now().strftime("%d/%b/%Y:%H:%M:%S +0000")
    line = env.get("REQUEST_METHOD", "-") + " " + env.get("PATH_INFO", "-")
    q = env.get("QUERY_STRING", "")
    if q:
        line += "?" + q
    line += " " + env.get("SERVER_PROTOCOL", "HTTP/1.1")
    ref = env.get("HTTP_REFERER", "-")
    ua = env.get("HTTP_USER_AGENT", "-")
    print(f'{ip} {ident} {user} [{ts}] "{line}" {resp_status} {length} "{ref}" "{ua}"',
          flush=True)


@app.after_request
def _access_log(resp):
    try:
        length = resp.calculate_content_length()
    except Exception:
        length = 0
    _log_combined(request.environ, resp.status_code, length if length is not None else 0)
    return resp


if __name__ == "__main__":
    # Werkzeug's own request log goes to stderr; our combined line goes to
    # stdout. The tailer picks up stdout, so keep the real telemetry there.
    import logging
    logging.getLogger("werkzeug").setLevel(logging.ERROR)
    print(f"[intranet-app] {APP_NAME} starting; db={DB_HOST} redis={REDIS_HOST}",
          file=sys.stderr, flush=True)
    app.run(host="0.0.0.0", port=80, threaded=True)
