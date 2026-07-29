#!/usr/bin/env python3
"""
Replay an export_session.py dump back through the real normalize -> SQLite
path, into an isolated database -- so a red-team session that actually
succeeded can be used for repeatable defender testing without re-running
(and re-paying for) the live attacker.

    python3 pipeline/redteam/export_session.py --session 7
    python3 pipeline/redteam/replay_session.py \\
        --in-dir attacker/loot/replays/session-7 --db-path /tmp/replay.db
    python3 pipeline/detect/rules.py   --db-path /tmp/replay.db --all
    python3 pipeline/triage/agent.py   --db-path /tmp/replay.db --mode single --provider local

Deliberately requires --db-path and refuses to default to the lab's real
soc.db: replaying old events back into the live DB would silently recreate
the exact "backlog mixed with live telemetry" mess this was built to avoid.
If you really want them in soc.db (e.g. to hand-craft a fixture), pass it
explicitly -- this only warns, it doesn't block.

Reuses ingest.ingest_line() unchanged (the same function harness/injector.py
uses to feed forged lines through the real path) so a replayed event is
normalized/inserted exactly as it would have been the first time, not by a
second parallel implementation that could drift from it.
"""

import argparse
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
PIPELINE = os.path.dirname(HERE)
ROOT = os.path.dirname(PIPELINE)
sys.path.insert(0, PIPELINE)

import ingest  # noqa: E402

SOURCES = ("cowrie", "nginx", "suricata", "wazuh")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--in-dir", required=True, help="directory produced by export_session.py")
    ap.add_argument("--db-path", required=True,
                     help="target sqlite file -- created fresh with the real schema if it "
                          "doesn't exist yet; never defaults to soc.db")
    ap.add_argument("--reset", action="store_true", help="wipe --db-path first if it exists")
    args = ap.parse_args()

    if os.path.abspath(args.db_path) == os.path.abspath(ingest.DB_PATH):
        print("[!] --db-path resolves to the lab's live soc.db -- this will mix replayed "
              "events into production telemetry. Proceeding anyway since you asked for it.")

    conn = ingest.connect(reset=args.reset, db_path=args.db_path)

    total = 0
    for source in SOURCES:
        path = os.path.join(args.in_dir, f"{source}.ndjson")
        if not os.path.exists(path):
            continue
        n = 0
        with open(path) as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                if ingest.ingest_line(conn, source, f"replay:{path}", line):
                    n += 1
        total += n
        print(f"[*] {source:<8} +{n}")

    conn.commit()
    print(f"\n[*] {total} event(s) replayed into {args.db_path}")
    print("    run pipeline/detect/rules.py --db-path <that path> --all, then "
          "pipeline/triage/agent.py --db-path <that path> --mode single to triage them")


if __name__ == "__main__":
    main()
