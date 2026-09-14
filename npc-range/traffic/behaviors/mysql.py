"""Benign MariaDB/MySQL queries against a db-mysql NPC (read-only reporting)."""
import subprocess

USER, PASS, DB = "reporting", "r3port-only", "appdb"
QUERIES = [
    "SELECT COUNT(*) FROM customers;",
    "SELECT tier, COUNT(*) FROM customers GROUP BY tier;",
    "SELECT status, COUNT(*) FROM orders GROUP BY status;",
    "SELECT 1;",
]


def run(hostname, rng):
    pw = "hunter2" if rng.random() < 0.05 else PASS
    subprocess.run(
        ["mysql", "-h", hostname, "-u", USER, f"-p{pw}", DB, "--connect-timeout=6",
         "-e", rng.choice(QUERIES)],
        capture_output=True, timeout=15)
