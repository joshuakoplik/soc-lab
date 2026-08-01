"""
Tracks LLM calls that are currently in flight, so the dashboard can show
what's blocking a run instead of going dark for however long a slow
provider takes to respond (observed: 10+ minutes on some local/GMI calls).
One row per provider.complete()/run_stage_turn() invocation: inserted with
status='running' immediately before the blocking call, flipped to
'completed'/'error' immediately after.

Both triage/agent.py and redteam/agent.py write here independently, each
over its own connection -- this module has no opinion on which; it only
owns the table shape and the two operations (start/finish). Each write
commits immediately, on purpose: the whole point is for the dashboard's
separate read-only connection to see a call the moment it starts, well
before the blocking provider call it represents returns.

Deliberately NOT imported by pipeline/providers/*.py -- those stay
DB-agnostic and vendor-neutral (see providers/base.py's docstring); this is
called from the agent loops one level up, at exactly the granularity where
"how long has this been running, and on what prompt" is meaningful (one
triage candidate, one redteam stage chunk).
"""
from datetime import datetime, timezone

SCHEMA = """
CREATE TABLE IF NOT EXISTS llm_calls (
    id             INTEGER PRIMARY KEY AUTOINCREMENT,
    component      TEXT    NOT NULL,   -- 'triage' | 'redteam-recon' | 'redteam-assess'
    context_label  TEXT    NOT NULL,   -- human-readable: "candidate #42 (ssh_bruteforce)", "session #7 -- recon chunk 1/10"
    provider       TEXT    NOT NULL,
    model          TEXT    NOT NULL,
    system_prompt  TEXT    NOT NULL,
    user_prompt    TEXT    NOT NULL,
    status         TEXT    NOT NULL DEFAULT 'running',  -- running | completed | error
    started        TEXT    NOT NULL,
    finished       TEXT,
    elapsed_s      REAL,
    error          TEXT
);
CREATE INDEX IF NOT EXISTS idx_llm_calls_status ON llm_calls(status);
"""

# New columns on a table that already existed before this set of changes --
# CREATE TABLE IF NOT EXISTS above only helps a table that doesn't exist
# yet. session_id (redteam only; NULL for triage rows, which have no
# session concept) is what lets redteam/agent.py's --loop sum a session's
# TRUE cumulative token spend across every chunk of every round, including
# past --continue-assess invocations -- before this, usage only ever lived
# in an in-memory dict inside one process's own _run_chained_stage call,
# printed once and gone. prompt/completion/total_tokens mirror
# AgenticResult.usage's own shape (real API-reported numbers where the
# provider has them, NULL otherwise -- never estimated, same convention as
# everywhere else usage is threaded through this codebase).
_MIGRATIONS = {
    "session_id": "INTEGER",
    "prompt_tokens": "INTEGER",
    "completion_tokens": "INTEGER",
    "total_tokens": "INTEGER",
}


def _now_iso():
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def _migrate_schema(conn):
    existing = {row[1] for row in conn.execute("PRAGMA table_info(llm_calls)").fetchall()}
    for column, col_type in _MIGRATIONS.items():
        if column not in existing:
            conn.execute(f"ALTER TABLE llm_calls ADD COLUMN {column} {col_type}")
    conn.commit()


def ensure_schema(conn):
    conn.executescript(SCHEMA)
    _migrate_schema(conn)
    conn.commit()


def start_call(conn, component, context_label, provider, model, system_prompt, user_prompt, session_id=None):
    ts = _now_iso()
    cur = conn.execute(
        "INSERT INTO llm_calls (component, context_label, provider, model, "
        "system_prompt, user_prompt, status, started, session_id) VALUES (?,?,?,?,?,?,'running',?,?)",
        (component, context_label, provider, model, system_prompt, user_prompt, ts, session_id),
    )
    conn.commit()
    return cur.lastrowid


def finish_call(conn, call_id, status, error=None, usage=None):
    """status is 'completed' or 'error'. Always called from a try/except
    around the same call start_call() was paired with -- see triage/agent.py's
    triage_one() and redteam/agent.py's _run_chained_stage() for the two
    call sites.

    usage, when given, is THIS call's own {prompt_tokens, completion_tokens,
    total_tokens} (not a running cumulative total -- redteam/agent.py's
    session_token_total() sums across rows itself, so storing a per-row
    cumulative here would double-count). None for providers that don't
    report real usage (local/claude) or when the call errored before any
    usage was returned -- left NULL, not zero, so a SUM() over a session
    doesn't silently under-report by treating "unknown" as "none spent"."""
    ts = _now_iso()
    usage = usage or {}
    conn.execute(
        "UPDATE llm_calls SET status=?, finished=?, error=?, "
        "elapsed_s=(julianday(?) - julianday(started)) * 86400.0, "
        "prompt_tokens=?, completion_tokens=?, total_tokens=? WHERE id=?",
        (status, ts, error, ts,
         usage.get("prompt_tokens"), usage.get("completion_tokens"), usage.get("total_tokens"),
         call_id),
    )
    conn.commit()
