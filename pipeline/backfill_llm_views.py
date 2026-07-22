#!/usr/bin/env python3
"""
One-time (or as-needed, it's idempotent) backfill: computes llm_view for
every existing events row that doesn't have one yet -- rows ingested before
the llm_view column existed. Safe to re-run: only touches rows where
llm_view IS NULL, and commits in batches so a large backlog doesn't hold one
giant transaction open.

    python3 pipeline/backfill_llm_views.py
"""

import json
import os
import sqlite3
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from ingest import migrate  # noqa: E402 -- reuse the same ALTER-TABLE migration, don't duplicate it
from llm_view import check_llm_view_size, compute_llm_view, print_strip_summary  # noqa: E402

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
DB_PATH = os.path.join(ROOT, "soc.db")
BATCH_SIZE = 500


def main():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    migrate(conn)  # ensure the llm_view column exists even if ingest.py hasn't run since the upgrade

    total = conn.execute("SELECT COUNT(*) n FROM events WHERE llm_view IS NULL").fetchone()["n"]
    print(f"[*] db: {DB_PATH}")
    print(f"[*] {total} row(s) missing llm_view")
    if not total:
        return

    done = 0
    while True:
        rows = conn.execute(
            "SELECT id, raw FROM events WHERE llm_view IS NULL LIMIT ?", (BATCH_SIZE,)
        ).fetchall()
        if not rows:
            break
        for row in rows:
            obj = json.loads(row["raw"])  # always valid JSON -- rows that failed to parse never made it into events
            llm_view_json = json.dumps(compute_llm_view(obj))
            check_llm_view_size(row["id"], llm_view_json)
            conn.execute("UPDATE events SET llm_view=? WHERE id=?", (llm_view_json, row["id"]))
        conn.commit()
        done += len(rows)
        print(f"  backfilled {done}/{total}")

    print_strip_summary()
    print(f"[*] done, {done} row(s) backfilled")


if __name__ == "__main__":
    main()
