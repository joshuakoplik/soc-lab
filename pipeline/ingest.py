#!/usr/bin/env python3
"""
Tail Cowrie + nginx logs -> normalize -> SQLite.

    python3 pipeline/ingest.py            # catch up on existing logs, then exit
    python3 pipeline/ingest.py --follow   # stay running, tail forever
    python3 pipeline/ingest.py --reset    # wipe the DB and re-ingest from scratch

No dependencies. Deliberately: you should be able to read every line of the thing
that feeds your detections.
"""

import argparse
import json
import os
import sqlite3
import sys
import time
from datetime import datetime, timezone

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from normalize import NORMALIZERS, COLUMNS  # noqa: E402
from llm_view import compute_llm_view, check_llm_view_size, print_strip_summary  # noqa: E402

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
DB_PATH = os.path.join(ROOT, "soc.db")

def _db_identity(path=None):
    """(dev, ino) of the db file, or None if it's gone. --follow uses this to
    notice a swap: reset.sh's --db wipe UNLINKS and recreates soc.db as a brand
    new inode, and a connection opened before that keeps writing to the old,
    detached inode that nothing will ever read again (confirmed live -- the
    tailer looked healthy, totals climbing, while the new soc.db stayed empty).
    Same guard the dashboard's poll_loop already uses to reconnect."""
    try:
        st = os.stat(path or DB_PATH)
        return (st.st_dev, st.st_ino)
    except OSError:
        return None
NW_TELEMETRY = os.path.join(ROOT, "northwind-range", "telemetry")

SOURCES = [
    ("cowrie",   os.path.join(ROOT, "logs", "cowrie", "cowrie.json")),
    ("nginx",    os.path.join(ROOT, "logs", "nginx", "access.json")),
    ("suricata", os.path.join(ROOT, "logs", "suricata", "eve.json")),
    # Wazuh hardlinks this into a dated tree and rotates it at midnight, so the
    # path stays put while the inode changes. read_new()'s inode check handles
    # it — that branch was written for logrotate and works here unchanged.
    ("wazuh",    os.path.join(ROOT, "logs", "wazuh", "alerts.json")),
    # Northwind range milestone 12 (SPEC.md §10) -- same tail-a-JSON-lines-
    # file mechanism, five more sources. See normalize.py for the
    # corresponding normalizer functions.
    ("northwind-nginx",      os.path.join(NW_TELEMETRY, "edge-nginx-access.json")),
    ("northwind-portal-api", os.path.join(NW_TELEMETRY, "portal-api.log")),
    ("northwind-policy",     os.path.join(NW_TELEMETRY, "policy-decisions.log")),
    ("northwind-ingest",     os.path.join(NW_TELEMETRY, "ingest-events.log")),
    ("northwind-retrieval",  os.path.join(NW_TELEMETRY, "retrieval-events.log")),
]

# Full LLM transcripts don't fit the events table's flat shape (see
# schema.sql's llm_transcripts table) -- handled by read_new_transcripts()
# below, not the SOURCES/read_new()/NORMALIZERS path.
TRANSCRIPT_SOURCES = [
    ("northwind-portal-api", os.path.join(NW_TELEMETRY, "llm-transcripts.log")),
]


def connect(reset=False, db_path=None):
    """db_path lets a caller (e.g. harness/injector.py) point this at an
    isolated database instead of the lab's real soc.db, using the exact same
    schema/migration path. Defaults to DB_PATH, so every existing caller is
    unaffected."""
    path = db_path or DB_PATH
    if reset and os.path.exists(path):
        os.remove(path)
        for suffix in ("-wal", "-shm"):
            if os.path.exists(path + suffix):
                os.remove(path + suffix)
    conn = sqlite3.connect(path)
    conn.row_factory = sqlite3.Row
    with open(os.path.join(HERE, "schema.sql")) as f:
        conn.executescript(f.read())
    migrate(conn)
    return conn


def migrate(conn):
    """CREATE TABLE IF NOT EXISTS won't add columns to a table that already
    exists from an earlier version. Add any missing IDS columns in place so an
    existing soc.db picks up Suricata support without a --reset."""
    have = {r["name"] for r in conn.execute("PRAGMA table_info(events)")}
    for col, decl in (
        ("ids_signature",    "TEXT"),
        ("ids_category",     "TEXT"),
        ("ids_severity",     "INTEGER"),
        ("ids_signature_id", "INTEGER"),
        ("siem_rule_id",     "TEXT"),
        ("siem_level",       "INTEGER"),
        ("siem_description", "TEXT"),
        ("siem_groups",      "TEXT"),
        ("llm_view",         "TEXT"),
        ("host",             "TEXT"),
    ):
        if col not in have:
            conn.execute(f"ALTER TABLE events ADD COLUMN {col} {decl}")
    conn.commit()


def now_iso():
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def record_failure(conn, path, reason, line):
    conn.execute(
        "INSERT INTO parse_failures (ts, path, reason, line) VALUES (?,?,?,?)",
        (now_iso(), path, reason, line[:2000]),
    )


def insert_event(conn, row, obj):
    """obj is the pre-normalization parsed JSON (what compute_llm_view needs
    -- http_request_body etc. only exist there, normalize.py's normalizers
    never carry them into `row`). llm_view is computed and stored here,
    inline with the row insert, rather than as a separate UPDATE pass."""
    llm_view_json = json.dumps(compute_llm_view(obj))
    placeholders = ",".join("?" * len(COLUMNS))
    cur = conn.execute(
        f"INSERT INTO events ({','.join(COLUMNS)}, llm_view) VALUES ({placeholders}, ?)",
        # `host` is optional -- only source=wazuh (fleet) sets it, so default it
        # here rather than making all nine normalizers carry the key. Every
        # other column stays strict (KeyError on a missing key is a real bug).
        tuple(row.get(c) if c == "host" else row[c] for c in COLUMNS) + (llm_view_json,),
    )
    check_llm_view_size(cur.lastrowid, llm_view_json)


def get_state(conn, path):
    r = conn.execute("SELECT inode, offset FROM tail_state WHERE path=?", (path,)).fetchone()
    return (r["inode"], r["offset"]) if r else (None, 0)


def set_state(conn, path, inode, offset):
    conn.execute(
        "INSERT INTO tail_state (path, inode, offset, updated) VALUES (?,?,?,?) "
        "ON CONFLICT(path) DO UPDATE SET inode=excluded.inode, offset=excluded.offset, updated=excluded.updated",
        (path, inode, offset, now_iso()),
    )


def ingest_line(conn, source, path, line):
    """Parse -> normalize -> insert one raw log line. Returns True if an
    event was inserted, False if the line was skipped or failed (recorded to
    parse_failures either way -- see record_failure). Factored out of
    read_new's per-line loop so harness/injector.py can feed forged lines
    through the exact same normalize/insert path a real tailed log line
    takes, without a file or a tail_state row involved. `path` here is just a
    label for parse_failures provenance, not necessarily a real file."""
    normalizer = NORMALIZERS[source]
    try:
        obj = json.loads(line)
    except json.JSONDecodeError as e:
        record_failure(conn, path, f"json: {e}", line)
        return False
    try:
        row = normalizer(obj, line)
        if row is None:      # normalizer chose to skip (e.g. EVE flow/stats)
            return False
        insert_event(conn, row, obj)
        return True
    except Exception as e:  # noqa: BLE001
        record_failure(conn, path, f"normalize: {e}", line)
        return False


def _read_new_lines(conn, path):
    """Shared tail-since-last-offset + rotation-detection logic. Returns
    the list of new, complete, non-empty decoded lines. Queues the
    tail_state update in the same (uncommitted) transaction as whatever
    the caller does next -- read_new() and read_new_transcripts() both
    commit once after processing every returned line, so a crash mid-batch
    rolls back the offset advance along with the inserts, and the next run
    safely re-reads from the old offset rather than silently skipping
    lines that were never actually ingested."""
    if not os.path.exists(path):
        return []

    st = os.stat(path)
    known_inode, offset = get_state(conn, path)

    # Rotation detection. Two signals: the inode changed (log was moved and
    # recreated), or the file got shorter than our offset (truncated in place).
    # Either way our offset is meaningless and we start over at 0.
    if known_inode is not None and st.st_ino != known_inode:
        print(f"  [rotate] {os.path.basename(path)}: inode changed, restarting at 0")
        offset = 0
    elif st.st_size < offset:
        print(f"  [rotate] {os.path.basename(path)}: truncated, restarting at 0")
        offset = 0

    if st.st_size == offset:
        return []

    lines = []
    # Binary mode, deliberately. Two reasons:
    #  1. Offsets must be EXACT byte counts. Reading in text mode and counting
    #     len(line.encode(...)) drifts: errors="replace" turns one invalid byte
    #     into U+FFFD, which re-encodes to THREE bytes. Every bad byte inflates
    #     the offset by 2, the offset overshoots EOF, the st_size < offset
    #     branch below mistakes that for truncation, and --follow re-ingests the
    #     whole file every poll. Attacker-controlled fields (SSH usernames, URIs)
    #     can carry invalid UTF-8, so this is reachable, not theoretical.
    #  2. Python only defines seek() in text mode for values returned by tell().
    #     Feeding it a raw byte offset is undefined behaviour that happens to
    #     work. In binary mode it's simply defined.
    with open(path, "rb") as f:
        f.seek(offset)
        for raw_line in f:
            # Partial final line: writer is mid-write. Stop, leave the offset
            # before it, pick it up whole next pass.
            if not raw_line.endswith(b"\n"):
                break
            offset += len(raw_line)          # exact: these are the bytes we read
            line = raw_line.decode("utf-8", errors="replace").strip()
            if line:
                lines.append(line)

    set_state(conn, path, st.st_ino, offset)
    return lines


def read_new(conn, source, path):
    """Read whatever's new since last time. Returns count ingested."""
    count = 0
    for line in _read_new_lines(conn, path):
        if ingest_line(conn, source, path, line):
            count += 1
    conn.commit()
    return count


def insert_transcript(conn, obj, raw):
    conn.execute(
        "INSERT INTO llm_transcripts "
        "(ts, source, session_id, username, model, system_prompt, user_turn, "
        " retrieved_context, tool_calls, completion, controls, raw) "
        "VALUES (?,?,?,?,?,?,?,?,?,?,?,?)",
        (
            obj.get("ts") or now_iso(), "northwind-portal-api",
            obj.get("session_id"), obj.get("username"), obj.get("model"),
            obj.get("system_prompt"), obj.get("user_turn"),
            json.dumps(obj["retrieved_context"]) if obj.get("retrieved_context") is not None else None,
            json.dumps(obj["tool_calls"]) if obj.get("tool_calls") is not None else None,
            obj.get("completion"),
            json.dumps(obj["controls"]) if obj.get("controls") is not None else None,
            raw,
        ),
    )


def ingest_transcript_line(conn, path, line):
    """llm_transcripts' analogue of ingest_line() -- parses one JSON line
    and inserts it directly, bypassing NORMALIZERS/insert_event since a
    transcript's nested shape (retrieved_context, tool_calls) doesn't fit
    the flat events table."""
    try:
        obj = json.loads(line)
    except json.JSONDecodeError as e:
        record_failure(conn, path, f"json: {e}", line)
        return False
    try:
        insert_transcript(conn, obj, line)
        return True
    except Exception as e:  # noqa: BLE001
        record_failure(conn, path, f"transcript: {e}", line)
        return False


def read_new_transcripts(conn, path):
    count = 0
    for line in _read_new_lines(conn, path):
        if ingest_transcript_line(conn, path, line):
            count += 1
    conn.commit()
    return count


def summarize(conn):
    print("\n=== events by source / type ===")
    for r in conn.execute(
        "SELECT source, event_type, COUNT(*) n FROM events "
        "GROUP BY source, event_type ORDER BY source, n DESC"
    ):
        print(f"  {r['source']:<8} {r['event_type']:<22} {r['n']:>6}")
    total = conn.execute("SELECT COUNT(*) n FROM events").fetchone()["n"]
    fails = conn.execute("SELECT COUNT(*) n FROM parse_failures").fetchone()["n"]
    transcripts = conn.execute("SELECT COUNT(*) n FROM llm_transcripts").fetchone()["n"]
    print(f"\n  total events: {total}   llm_transcripts: {transcripts}   parse failures: {fails}")
    print_strip_summary()
    if fails:
        print("  inspect with: SELECT reason, COUNT(*) FROM parse_failures GROUP BY reason;")
    unmapped = conn.execute(
        "SELECT COUNT(*) n FROM events WHERE event_type='ssh.other'"
    ).fetchone()["n"]
    if unmapped:
        print(f"\n  [!] {unmapped} cowrie events fell through to 'ssh.other'.")
        print("      Your Cowrie version emits eventids I didn't map. See what they are:")
        print("      sqlite3 soc.db \"SELECT DISTINCT json_extract(raw,'$.eventid') FROM events WHERE event_type='ssh.other';\"")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--follow", action="store_true", help="tail continuously")
    ap.add_argument("--reset", action="store_true", help="wipe DB and re-ingest")
    ap.add_argument("--interval", type=float, default=2.0)
    args = ap.parse_args()

    conn = connect(reset=args.reset)
    db_id = _db_identity()
    print(f"[*] db: {DB_PATH}")

    total = 0
    for source, path in SOURCES:
        n = read_new(conn, source, path)
        total += n
        state = "ok" if os.path.exists(path) else "MISSING"
        print(f"[*] {source:<8} {path}  [{state}]  +{n}")
    for source, path in TRANSCRIPT_SOURCES:
        n = read_new_transcripts(conn, path)
        total += n
        state = "ok" if os.path.exists(path) else "MISSING"
        print(f"[*] {source:<8} {path}  [{state}]  +{n} (llm_transcripts)")

    if not args.follow:
        summarize(conn)
        return

    print(f"[*] following (ctrl-c to stop), {args.interval}s interval")
    try:
        while True:
            time.sleep(args.interval)
            cur_id = _db_identity()
            if cur_id is not None and cur_id != db_id:
                # soc.db was swapped out (reset --db). Drop the stale handle on
                # the detached inode and reopen the new file, or every event
                # from here on vanishes into a ghost nothing reads.
                print("[*] soc.db was replaced (reset --db?) -- reconnecting to the new file")
                try:
                    conn.close()
                except Exception:
                    pass
                conn = connect()
                db_id = cur_id
            for source, path in SOURCES:
                n = read_new(conn, source, path)
                if n:
                    total += n
                    print(f"  +{n:<4} {source:<8} (total {total})")
            for source, path in TRANSCRIPT_SOURCES:
                n = read_new_transcripts(conn, path)
                if n:
                    total += n
                    print(f"  +{n:<4} {source:<8} (total {total}, llm_transcripts)")
    except KeyboardInterrupt:
        print("\n[*] stopped")
        summarize(conn)


if __name__ == "__main__":
    main()
