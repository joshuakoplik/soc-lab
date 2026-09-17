#!/usr/bin/env python3
"""
The analyst-chat persistence layer.

Mirror of pipeline/hunt/store.py, but for the human-driven analyst chat. Owns:

  - connect()/ensure_schema(): apply the sibling schemas the analyst reads
    (detect/candidates, triage action tables) and the hunt schema (so the
    shared-memory reads -- incidents/notes/leads -- work against any soc.db),
    then the analyst's own chat_* tables.
  - chat session / transcript / note / action CRUD.
  - the read-shared bridge to the standing hunt: latest_hunt_id() plus thin
    passthroughs to hunt.store for incidents/notebook/leads. The analyst reads
    those; it never writes them (that is the hunter's memory).

Kept separate from agent.py (loop/tools/prompts) so the persistence model can
be exercised without a provider, exactly as hunt/store.py can.
"""

import importlib.util
import json
import os
import sqlite3
import sys
from datetime import datetime, timezone

HERE = os.path.dirname(os.path.abspath(__file__))        # pipeline/analyst
PIPELINE = os.path.dirname(HERE)                          # pipeline
ROOT = os.path.dirname(PIPELINE)                          # soc-lab root

sys.path.insert(0, PIPELINE)
import llm_call_tracker  # noqa: E402  (unique filename -- bare import is unambiguous)


def _load_by_path(mod_name, path):
    """Load a module under an explicit, unique name. Both pipeline/hunt/ and
    pipeline/analyst/ ship a store.py and an agent.py, so a bare `import store`
    / `import agent` would collide in one process (the analyst reuses the
    hunter's code). Loading hunt's store under 'soclab_hunt_store' sidesteps
    that entirely -- same trick dashboard/server.py uses to load dotenv.py."""
    if mod_name in sys.modules:
        return sys.modules[mod_name]
    spec = importlib.util.spec_from_file_location(mod_name, path)
    mod = importlib.util.module_from_spec(spec)
    sys.modules[mod_name] = mod
    spec.loader.exec_module(mod)
    return mod


# The hunter's store, reused for the read-shared bridge (incidents/notes/leads).
hunt_store = _load_by_path("soclab_hunt_store", os.path.join(PIPELINE, "hunt", "store.py"))

DB_PATH = os.path.join(ROOT, "soc.db")

# Sibling schemas applied on connect so the analyst is self-sufficient against
# any soc.db, exactly as hunt/store.connect() does. All CREATE ... IF NOT
# EXISTS, so this is a no-op when reset_lab.py already built the full schema.
# The hunt schema is included because the analyst READS incidents/notes/leads.
_SIBLING_SCHEMAS = (
    os.path.join(PIPELINE, "detect", "schema.sql"),   # candidates, rule_state
    os.path.join(PIPELINE, "triage", "schema.sql"),   # triage + action tables (assets, etc.)
    os.path.join(PIPELINE, "hunt", "schema.sql"),     # hunt_sessions/incidents/hunt_notes/leads
)

# Cap on tool-result text stored in the transcript. The full result was already
# shown to the model in-context; chat_turns is for humans and replay, so a
# preview is enough and keeps the DB small under a chatty session.
TOOL_RESULT_PREVIEW_CAP = 4000


def now_iso():
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


# ---------------------------------------------------------------------------
# connect / schema
# ---------------------------------------------------------------------------

def connect(db_path=None):
    """Open soc.db (or an isolated db_path for testing), apply the sibling +
    analyst schema, and set a busy_timeout so this writer waits on the WAL
    write lock instead of raising 'database is locked' next to ingest.py,
    detect/rules.py and a running hunter."""
    conn = sqlite3.connect(db_path or DB_PATH)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA busy_timeout=30000")
    for path in _SIBLING_SCHEMAS:
        with open(path) as f:
            conn.executescript(f.read())
    hunt_store.ensure_schema(conn)   # runs the hunt additive migrations too
    ensure_schema(conn)
    llm_call_tracker.ensure_schema(conn)
    return conn


def ensure_schema(conn):
    """Create the analyst chat_* tables and run the additive migrations. Safe
    to call on any connection; all CREATE ... IF NOT EXISTS plus PRAGMA-guarded
    ALTERs. Called by connect() and by reset_lab.init_full_schema()."""
    with open(os.path.join(HERE, "schema.sql")) as f:
        conn.executescript(f.read())
    migrate(conn)
    conn.commit()


def _table_columns(conn, table):
    return {r["name"] for r in conn.execute(f"PRAGMA table_info({table})")}


def migrate(conn):
    """Additive, idempotent -- same pattern as hunt/store.migrate(). Adds the
    responder's incident_id attribution column to chat_sessions and
    chat_actions on databases that predate it."""
    for table in ("chat_sessions", "chat_actions"):
        have = _table_columns(conn, table)
        if have and "incident_id" not in have:
            conn.execute(f"ALTER TABLE {table} ADD COLUMN incident_id INTEGER")
    conn.commit()


# ---------------------------------------------------------------------------
# chat sessions
# ---------------------------------------------------------------------------

def start_session(conn, provider, model, lab_mode=None, hunt_id=None, title=None,
                  incident_id=None):
    ts = now_iso()
    cur = conn.execute(
        "INSERT INTO chat_sessions (started, provider, model, lab_mode, status, title, "
        "hunt_id, incident_id, created, updated) VALUES (?,?,?,?, 'active', ?,?,?,?,?)",
        (ts, provider, model, lab_mode, title, hunt_id, incident_id, ts, ts),
    )
    conn.commit()
    return cur.lastrowid


def get_session(conn, session_id):
    return conn.execute("SELECT * FROM chat_sessions WHERE id=?", (session_id,)).fetchone()


def latest_active_session(conn):
    return conn.execute(
        "SELECT * FROM chat_sessions WHERE status='active' ORDER BY id DESC LIMIT 1"
    ).fetchone()


def close_session(conn, session_id):
    conn.execute(
        "UPDATE chat_sessions SET status='closed', ended=?, updated=? WHERE id=?",
        (now_iso(), now_iso(), session_id),
    )
    conn.commit()


def set_title(conn, session_id, title):
    conn.execute(
        "UPDATE chat_sessions SET title=?, updated=? WHERE id=?",
        (title, now_iso(), session_id),
    )
    conn.commit()


def _touch(conn, session_id):
    conn.execute("UPDATE chat_sessions SET updated=? WHERE id=?", (now_iso(), session_id))


# ---------------------------------------------------------------------------
# transcript
# ---------------------------------------------------------------------------

def _next_seq(conn, session_id):
    r = conn.execute(
        "SELECT COALESCE(MAX(seq), 0) AS m FROM chat_turns WHERE session_id=?", (session_id,)
    ).fetchone()
    return r["m"] + 1


def add_turn(conn, session_id, role, content=None, tool_name=None, tool_input=None,
             tool_result_preview=None, is_error=False):
    """Append one transcript row. tool_input is JSON-encoded here if a dict is
    passed; tool_result_preview is truncated to the cap."""
    if isinstance(tool_input, (dict, list)):
        tool_input = json.dumps(tool_input, default=str)
    if tool_result_preview and len(tool_result_preview) > TOOL_RESULT_PREVIEW_CAP:
        tool_result_preview = tool_result_preview[:TOOL_RESULT_PREVIEW_CAP] + "\n...[truncated]"
    cur = conn.execute(
        "INSERT INTO chat_turns (session_id, seq, role, content, tool_name, tool_input, "
        "tool_result_preview, is_error, created) VALUES (?,?,?,?,?,?,?,?,?)",
        (session_id, _next_seq(conn, session_id), role, content, tool_name, tool_input,
         tool_result_preview, int(bool(is_error)), now_iso()),
    )
    _touch(conn, session_id)
    conn.commit()
    return cur.lastrowid


def turn_in_flight(conn, session_id, stale_after_s=900):
    """True if a turn appears to be running on this session in SOME process:
    the last transcript row is not the assistant's reply (a user message or a
    tool row) and is younger than stale_after_s. run_turn() and
    dashboard/chat._do_turn() always append an assistant row on every handled
    failure path, so only a hard kill can leave a dangling non-assistant row --
    the staleness cutoff keeps that from 409-ing the session forever. This is
    the cross-process check the dashboard's in-process per-session lock can't
    provide once the responder (--serve) is also writing turns."""
    row = conn.execute(
        "SELECT role, created FROM chat_turns WHERE session_id=? ORDER BY seq DESC LIMIT 1",
        (session_id,),
    ).fetchone()
    if not row or row["role"] == "assistant":
        return False
    try:
        age = (datetime.now(timezone.utc)
               - datetime.fromisoformat(row["created"].replace("Z", "+00:00"))).total_seconds()
    except (ValueError, AttributeError):
        return False
    return age < stale_after_s


def transcript(conn, session_id):
    return conn.execute(
        "SELECT * FROM chat_turns WHERE session_id=? ORDER BY seq", (session_id,)
    ).fetchall()


# ---------------------------------------------------------------------------
# write-own notebook
# ---------------------------------------------------------------------------

def add_note(conn, session_id, body, note_type="finding", refs=None):
    cur = conn.execute(
        "INSERT INTO chat_notes (session_id, note_type, body, refs, created) VALUES (?,?,?,?,?)",
        (session_id, note_type, body, json.dumps(refs) if refs else None, now_iso()),
    )
    _touch(conn, session_id)
    conn.commit()
    return cur.lastrowid


def notes(conn, session_id):
    return conn.execute(
        "SELECT * FROM chat_notes WHERE session_id=? ORDER BY id", (session_id,)
    ).fetchall()


# ---------------------------------------------------------------------------
# response actions (audit record; real enforcement is in the backends)
# ---------------------------------------------------------------------------

def add_action(conn, session_id, kind, src_ip=None, target_ref=None, reason=None,
               executed=False, result=None, incident_id=None):
    cur = conn.execute(
        "INSERT INTO chat_actions (session_id, incident_id, kind, src_ip, target_ref, reason, "
        "executed, result_json, created) VALUES (?,?,?,?,?,?,?,?,?)",
        (session_id, incident_id, kind, src_ip, target_ref, reason, int(bool(executed)),
         json.dumps(result, default=str) if result is not None else None, now_iso()),
    )
    _touch(conn, session_id)
    conn.commit()
    return cur.lastrowid


# ---------------------------------------------------------------------------
# read-shared bridge to the standing hunt
# ---------------------------------------------------------------------------

def latest_hunt_id(conn):
    """The standing hunt whose shared memory the analyst reads. Prefers a
    running/idle hunt (the live one); falls back to the most recent hunt of any
    status so a chat opened after a hunt was stopped still sees its incidents."""
    row = hunt_store.latest_resumable_hunt(conn)
    if row:
        return row["id"]
    row = conn.execute("SELECT id FROM hunt_sessions ORDER BY id DESC LIMIT 1").fetchone()
    return row["id"] if row else None
