"""Benign PostgreSQL queries against a db-postgres NPC.

Connects as the seeded read-only 'reporting' role and runs a harmless SELECT --
exactly what a reporting job or app healthcheck would do. Occasionally a wrong
password (a fat-fingered cron, an expired rotation) to produce the auth-failure
lines a real DB logs, but rarely.
"""
import os
import subprocess

RO_USER = "reporting"
RO_PASS = "r3port-only"
DB = "appdb"

QUERIES = [
    "SELECT count(*) FROM employees;",
    "SELECT department, count(*) FROM employees GROUP BY department;",
    "SELECT status, count(*) FROM invoices GROUP BY status;",
    "SELECT 1;",
]


def run(hostname, rng):
    wrong = rng.random() < 0.05
    env = dict(os.environ)
    env["PGPASSWORD"] = "hunter2" if wrong else RO_PASS
    env["PGCONNECT_TIMEOUT"] = "6"
    subprocess.run(
        ["psql", "-h", hostname, "-U", RO_USER, "-d", DB, "-tAc", rng.choice(QUERIES)],
        capture_output=True, timeout=15, env=env)
