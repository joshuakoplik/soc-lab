#!/usr/bin/env python3
"""
DB + event-queue half of reset.sh (the bash wrapper handles network reset
and killing running pipeline processes, since those are docker/process
concerns, not sqlite ones).

    python3 pipeline/reset_lab.py --db              # wipe soc.db + recreate schema + reposition ingest to EOF
    python3 pipeline/reset_lab.py --queue           # reseed tail_state to each log's current EOF (no wipe)
    python3 pipeline/reset_lab.py --db --queue      # both (--queue is redundant after --db, but harmless)
    python3 pipeline/reset_lab.py --status          # report table counts / tail_state staleness

"--queue" means: don't touch the raw log files on disk, but tell
ingest.py's tail_state that everything currently sitting in
logs/{cowrie,nginx,suricata,wazuh}/*.json (plus the northwind telemetry)
has already been read, so the next `ingest.py --follow` only picks up new
activity. A wipe leaves tail_state empty too, so WITHOUT repositioning the
very next ingest run replays the entire on-disk log history back in as a
fresh "backlog" -- the 155k-event/4925-candidate flood this was built to
avoid (and worse now: the accumulated suricata eve.json is multi-GB, so
the replay also holds the WAL write lock long enough to crash the hunter/
analyst/detect on their first write). To make that impossible to trip over,
"--db" now does this repositioning itself (reset_db calls
_seed_tail_state_eof after the wipe) -- so a --db reset is self-contained
and order-independent, and "--queue" stays available on its own for
skipping a backlog without wiping events.

Schema init applies each module's own schema.sql directly (rather than
importing ingest.py/rules.py/agent.py as libraries) because those modules
are written as standalone scripts -- they rely on Python auto-adding their
own directory to sys.path when run directly (`python3 pipeline/x/agent.py`),
which doesn't happen when imported as `from triage import agent` from
elsewhere, and breaks their own sibling imports (triage/agent.py's bare
`import block_enforcer`, redteam/agent.py's bare `import executor`). Reading
their schema.sql files instead sidesteps that entirely and still can't
drift from what those modules expect, since it's the exact same file.
"""

import argparse
import os
import sqlite3
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
sys.path.insert(0, HERE)

import ingest  # noqa: E402
import llm_call_tracker  # noqa: E402
from hunt import store as hunt_store  # noqa: E402
from analyst import chat_store as analyst_chat_store  # noqa: E402

DB_PATH = ingest.DB_PATH

# The hunt tables (pipeline/hunt/schema.sql) + the additive action-table
# migrations live behind hunt_store.ensure_schema(), not a plain schema.sql in
# SCHEMA_FILES, because the incident_id/hunt_id ALTERs can't be expressed as
# CREATE TABLE IF NOT EXISTS. init_full_schema() calls it after the others so
# candidates + the action tables already exist for those ALTERs to target.
HUNT_TABLES = (
    "incident_handoffs",   # hunter -> analyst queue; child of incidents, so first
    "hunt_checkpoints", "hunt_handoff_notes", "leads", "hunt_notes",
    "incident_evidence", "incidents", "hunt_sessions",
)

SCHEMA_FILES = [
    os.path.join(HERE, "detect", "schema.sql"),
    os.path.join(HERE, "triage", "schema.sql"),
    os.path.join(HERE, "redteam", "schema.sql"),
    # The analyst-chat tables (pipeline/analyst/schema.sql) layer in here for
    # the CREATE TABLE IF NOT EXISTS part; their additive incident_id ALTERs
    # run via analyst_chat_store.ensure_schema() in init_full_schema() below.
    os.path.join(HERE, "analyst", "schema.sql"),
]


def init_full_schema(db_path=None):
    """ingest.connect() applies pipeline/schema.sql (events/tail_state/
    parse_failures) plus its own column migrate(). Layer the other three
    modules' schema.sql on top of that same connection so every table
    exists -- a --status call right after reset shouldn't hit 'no such
    table'.

    llm_call_tracker's schema isn't one of those three modules' own
    schema.sql files -- it's a cross-cutting table triage/agent.py's and
    redteam/agent.py's own connect() each create lazily on first call, not
    something owned by detect/triage/redteam individually -- so it was
    missing here even though this function's whole point is "every table
    exists after a reset." Observed live: dashboard/server.py restarting
    immediately after a --db wipe (see reset.sh) queried llm_calls before
    any agent process had run since the wipe to lazily create it, and hit
    a bare 'no such table: llm_calls' 500."""
    conn = ingest.connect(db_path=db_path)
    for path in SCHEMA_FILES:
        with open(path) as f:
            conn.executescript(f.read())
    llm_call_tracker.ensure_schema(conn)
    hunt_store.ensure_schema(conn)   # hunt tables + additive action-table migrations
    analyst_chat_store.ensure_schema(conn)   # chat_* incident_id migrations
    conn.commit()


def _seed_tail_state_eof(conn):
    """Point ingest's tail_state at each source log's current EOF, so the next
    `ingest.py --follow` picks up only new activity and never replays on-disk
    history. Returns the number of sources seeded.

    SOURCES and TRANSCRIPT_SOURCES are separate lists (ingest.py's own split --
    llm-transcripts.log is nested/transcript-shaped and goes into
    llm_transcripts, not the flat events table), each with their own tail_state
    row keyed by file path -- both need reseeding here, or a wipe leaves
    llm-transcripts.log's queue exactly where it was before. Confirmed live more
    than once: without this a fresh soc.db's first ingest replays the ENTIRE
    on-disk log history back in (the 2.57GB suricata eve.json alone floods the
    hunter and holds the WAL write lock long enough to crash every other agent
    on startup)."""
    seeded = 0
    for source, path in ingest.SOURCES + ingest.TRANSCRIPT_SOURCES:
        if not os.path.exists(path):
            print(f"    {source:<8} {path}  [MISSING] -- nothing to seed")
            continue
        st = os.stat(path)
        ingest.set_state(conn, path, st.st_ino, st.st_size)
        print(f"    {source:<8} {path}  seeded at offset={st.st_size}")
        seeded += 1
    conn.commit()
    return seeded


def reset_db():
    for suffix in ("", "-wal", "-shm"):
        path = DB_PATH + suffix
        if os.path.exists(path):
            os.remove(path)
    init_full_schema()
    print(f"[*] db wiped and re-initialized: {DB_PATH}")
    # A wiped DB has an empty tail_state, so ingest would replay the entire
    # on-disk log backlog. Reposition the ingest pipeline to EOF as part of the
    # wipe, so `reset --db` is self-contained: no separate --queue needed, and
    # the flag order can't matter (a --queue seed before --db used to be erased
    # by the wipe). --queue remains available on its own to skip a backlog
    # without wiping events.
    conn = ingest.connect()
    n = _seed_tail_state_eof(conn)
    conn.close()
    print(f"[*] ingest pipeline repositioned to EOF for {n} source(s) -- no backlog replay")


def reset_queue():
    conn = ingest.connect()
    seeded = _seed_tail_state_eof(conn)
    conn.close()
    print(f"[*] tail_state reseeded for {seeded} source(s) -- ingest.py --follow "
          "will only pick up activity from here on")


def reset_hunt():
    """Clear the standing hunt's own state -- sessions, incidents, notebook,
    leads, handoffs, checkpoints -- and thereby its feed cursor, WITHOUT wiping
    events/candidates/triage. Lets an operator restart the hunter from a clean
    slate against the same telemetry (e.g. to re-measure hunt behavior on a
    fixed candidate set) short of a full --db wipe. Real iptables blocks the
    hunter placed are cleared by reset.sh --network, same as for triage."""
    if not os.path.exists(DB_PATH):
        print(f"[*] {DB_PATH} does not exist -- nothing to clear")
        return
    conn = ingest.connect()
    hunt_store.ensure_schema(conn)   # make sure the tables exist before DELETE
    cleared = 0
    for table in HUNT_TABLES:        # child-before-parent order (FK-safe)
        cleared += conn.execute(f"DELETE FROM {table}").rowcount
    conn.commit()
    print(f"[*] hunt state cleared ({cleared} row(s) across "
          f"{len(HUNT_TABLES)} tables); feed cursor reset")


def status():
    if not os.path.exists(DB_PATH):
        print(f"[*] {DB_PATH} does not exist -- nothing to report")
        return
    conn = ingest.connect()
    print(f"[*] db: {DB_PATH}")
    for table in ("events", "candidates", "triage", "redteam_sessions",
                  "recon_findings", "vuln_findings", "pending_actions", "loot"):
        try:
            n = conn.execute(f"SELECT COUNT(*) FROM {table}").fetchone()[0]
        except sqlite3.OperationalError:
            n = "(no such table yet)"
        print(f"    {table:<18} {n}")

    print("\n[*] tail_state (queue) per source:")
    for source, path in ingest.SOURCES:
        if not os.path.exists(path):
            print(f"    {source:<8} {path}  [MISSING]")
            continue
        st = os.stat(path)
        known_inode, offset = ingest.get_state(conn, path)
        behind = st.st_size - offset if known_inode == st.st_ino else st.st_size
        state = "caught up" if behind == 0 else f"{behind} byte(s) unread"
        print(f"    {source:<8} {path}  {state}")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--db", action="store_true", help="wipe soc.db and recreate empty schema")
    ap.add_argument("--queue", action="store_true",
                     help="reseed tail_state to each log's current EOF")
    ap.add_argument("--hunt", action="store_true",
                     help="clear the standing hunt's sessions/incidents/notebook/leads "
                          "(and its feed cursor), leaving events/candidates/triage intact")
    ap.add_argument("--status", action="store_true",
                     help="report table counts and tail_state staleness, change nothing")
    args = ap.parse_args()

    if args.status:
        status()
        return

    if not args.db and not args.queue and not args.hunt:
        print("[!] nothing to do -- pass --db, --queue, --hunt, --status, or some combination",
              file=sys.stderr)
        sys.exit(1)

    if args.db:
        reset_db()
    if args.queue:
        reset_queue()
    if args.hunt:
        reset_hunt()


if __name__ == "__main__":
    main()
