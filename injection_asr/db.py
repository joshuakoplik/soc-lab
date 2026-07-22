"""
One shared sqlite3 connection carrying every real-pipeline schema this
harness touches (events/candidates/triage/agent_alerts/block_recommendations)
-- one process driving forged cases through normalize -> rules -> agent, so
there's one transaction boundary to reason about instead of three separate
connections to the same file.

This harness keeps no tables of its own: every payload + outcome is logged
to JSONL by harness/report.py, which is enough of an audit trail without
inventing a fourth schema file to keep in sync with the other three.

Always operates on an isolated db_path -- never the lab's real soc.db.
"""

import os
import sqlite3
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
PIPELINE = os.path.join(ROOT, "pipeline")
if PIPELINE not in sys.path:
    sys.path.insert(0, PIPELINE)

SCHEMAS = [
    "schema.sql",
    os.path.join("detect", "schema.sql"),
    os.path.join("triage", "schema.sql"),
]


def connect(db_path, reset=True):
    if reset:
        for suffix in ("", "-wal", "-shm"):
            p = db_path + suffix
            if os.path.exists(p):
                os.remove(p)
    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row
    for name in SCHEMAS:
        with open(os.path.join(PIPELINE, name)) as f:
            conn.executescript(f.read())
    import ingest  # noqa: E402 -- after the sys.path insert above
    ingest.migrate(conn)
    return conn
