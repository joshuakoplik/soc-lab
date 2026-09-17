#!/usr/bin/env python3
"""
The hunter's persistence layer -- "the DB is the memory, not the conversation."

Everything the threat-hunter agent knows lives in soc.db (pipeline/hunt/
schema.sql) and is rebuilt into each fresh chunk's prompt from these rows, the
same way pipeline/redteam/agent.py externalizes its state. This module owns:

  - connect()/ensure_schema()/migrate(): the schema, including the additive
    incident_id/hunt_id columns on the existing action tables and the
    candidates(updated) index the feed cursor needs.
  - the non-consuming feed cursor over `candidates` (read the stream by
    id/updated high-water mark, never by flipping candidates.status).
  - session, incident, notebook, lead, chunk-handoff-note and checkpoint CRUD.
  - the incident_handoffs queue (hunter -> analyst responder): the hunter
    inserts, the responder claims atomically and records the verdict.

Deliberately separate from agent.py (loop/tools/prompts) and context.py
(prompt rendering) so the memory model can be unit-tested without a provider.

The hunter NEVER writes candidates.status. That column belonged to the old
triage queue; the hunter treats candidates as a growing intel feed and tracks
what it has looked at via its own cursor + notebook, not a queue flag.
"""

import json
import os
import sqlite3
import sys
from datetime import datetime, timezone

HERE = os.path.dirname(os.path.abspath(__file__))        # pipeline/hunt
PIPELINE = os.path.dirname(HERE)                          # pipeline
ROOT = os.path.dirname(PIPELINE)                          # soc-lab root

sys.path.insert(0, PIPELINE)
import llm_call_tracker  # noqa: E402

DB_PATH = os.path.join(ROOT, "soc.db")

# Sibling schemas the hunter reads (candidates) or writes (action tables). We
# apply them on connect so the hunter is self-sufficient against any soc.db,
# exactly as triage/agent.py applies its own schema.sql. All CREATE ... IF NOT
# EXISTS, so this is a no-op when reset_lab.py already built the full schema.
_SIBLING_SCHEMAS = (
    os.path.join(PIPELINE, "detect", "schema.sql"),   # candidates, rule_state
    os.path.join(PIPELINE, "triage", "schema.sql"),   # triage + action tables
)

# The action tables the hunter attributes to an incident + hunt. candidate_id
# stays NOT NULL (an incident is always seeded from candidates, so there is
# always a representative candidate to attribute to); incident_id/hunt_id are
# added nullable so the legacy triage path (injection_asr) is untouched -- it
# keeps writing candidate_id and leaves these NULL.
_ACTION_TABLES = (
    "agent_alerts", "block_recommendations", "block_ip_calls", "human_pages",
    "northwind_control_calls", "northwind_quarantine_calls",
)

# severity ladder shared with detect/rules.py; used to rank the feed so the
# hunter sees "what's burning brightest" first.
SEVERITY_ORDER = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}
SEVERITY_RANK_SQL = (
    "CASE severity WHEN 'critical' THEN 4 WHEN 'high' THEN 3 "
    "WHEN 'medium' THEN 2 WHEN 'low' THEN 1 ELSE 0 END"
)

FEED_DELTA_DEFAULT_CAP = 40


def now_iso():
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


# ---------------------------------------------------------------------------
# connect / schema
# ---------------------------------------------------------------------------

def connect(db_path=None):
    """Open soc.db (or an isolated db_path for testing), apply the sibling +
    hunt schema, run migrations, and set a busy_timeout so the standing hunter
    -- a long-lived writer running next to ingest.py and detect/rules.py --
    waits on the WAL write lock instead of raising 'database is locked'."""
    conn = sqlite3.connect(db_path or DB_PATH)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA busy_timeout=30000")
    for path in _SIBLING_SCHEMAS:
        with open(path) as f:
            conn.executescript(f.read())
    ensure_schema(conn)
    llm_call_tracker.ensure_schema(conn)
    return conn


def ensure_schema(conn):
    """Create the hunt tables and run the additive migrations. Safe to call on
    any connection that already has the detect/triage schema applied (the
    migrations guard on table existence). Called by connect() and by
    reset_lab.init_full_schema()."""
    with open(os.path.join(HERE, "schema.sql")) as f:
        conn.executescript(f.read())
    migrate(conn)
    conn.commit()


def _table_columns(conn, table):
    return {r["name"] for r in conn.execute(f"PRAGMA table_info({table})")}


def migrate(conn):
    """Additive, idempotent. Adds incident_id/hunt_id to the action tables
    (CREATE TABLE IF NOT EXISTS in triage/schema.sql can't add columns to a
    table that already exists) and the candidates(updated) index the feed
    cursor's `updated > ?` scan needs. Each ALTER is guarded on the table
    existing, so a db missing the triage schema entirely just skips it rather
    than erroring -- mirrors the PRAGMA-guarded pattern in triage/agent.py's
    migrate() and llm_call_tracker._migrate_schema()."""
    for table in _ACTION_TABLES:
        have = _table_columns(conn, table)
        if not have:
            continue  # table not present in this db yet; nothing to migrate
        for col, decl in (("incident_id", "INTEGER"), ("hunt_id", "INTEGER")):
            if col not in have:
                conn.execute(f"ALTER TABLE {table} ADD COLUMN {col} {decl}")
    if _table_columns(conn, "candidates"):
        conn.execute("CREATE INDEX IF NOT EXISTS idx_cand_updated ON candidates(updated)")
    # The events table is owned by pipeline/schema.sql (applied by ingest.py),
    # which connect() does NOT re-run -- so, exactly like idx_cand_updated above,
    # create the hunter-board's signature index here too, guarded on events
    # existing, so a hunter running against a db that predates the schema change
    # still gets it. Partial predicate keeps it tiny (NULL on every non-alert row).
    if _table_columns(conn, "events"):
        conn.execute("CREATE INDEX IF NOT EXISTS idx_events_ids_sig "
                     "ON events(ids_signature) WHERE ids_signature IS NOT NULL")
    conn.commit()


# ---------------------------------------------------------------------------
# hunt sessions
# ---------------------------------------------------------------------------

def start_hunt(conn, provider, model, lab_mode=None):
    ts = now_iso()
    cur = conn.execute(
        "INSERT INTO hunt_sessions (started, provider, model, lab_mode, status, "
        "chunk_count, feed_cursor_id, feed_cursor_ts, created, updated) "
        "VALUES (?,?,?,?, 'running', 0, 0, '', ?, ?)",
        (ts, provider, model, lab_mode, ts, ts),
    )
    conn.commit()
    return cur.lastrowid


def latest_resumable_hunt(conn):
    """The most recent hunt not cleanly stopped -- what --continue with no id,
    or a bare restart, picks up. A 'stopped' hunt is done; running/idle ones
    were interrupted (crash, kill without clean shutdown, or just still going)."""
    return conn.execute(
        "SELECT * FROM hunt_sessions WHERE status IN ('running','idle') "
        "ORDER BY id DESC LIMIT 1"
    ).fetchone()


def get_hunt(conn, hunt_id):
    return conn.execute("SELECT * FROM hunt_sessions WHERE id=?", (hunt_id,)).fetchone()


def set_hunt_status(conn, hunt_id, status):
    ended = now_iso() if status == "stopped" else None
    conn.execute(
        "UPDATE hunt_sessions SET status=?, ended=COALESCE(?, ended), updated=? WHERE id=?",
        (status, ended, now_iso(), hunt_id),
    )
    conn.commit()


def advance_cursor(conn, hunt_id, cursor_id, cursor_ts):
    """Move the feed high-water mark forward. Only ever advances (guards
    against a smaller value) so a re-render can't rewind the cursor and replay
    the backlog."""
    conn.execute(
        "UPDATE hunt_sessions SET feed_cursor_id=MAX(feed_cursor_id, ?), "
        "feed_cursor_ts=MAX(feed_cursor_ts, ?), updated=? WHERE id=?",
        (cursor_id, cursor_ts or "", now_iso(), hunt_id),
    )
    conn.commit()


def bump_chunk(conn, hunt_id):
    conn.execute(
        "UPDATE hunt_sessions SET chunk_count=chunk_count+1, updated=? WHERE id=?",
        (now_iso(), hunt_id),
    )
    conn.commit()
    return conn.execute(
        "SELECT chunk_count FROM hunt_sessions WHERE id=?", (hunt_id,)
    ).fetchone()["chunk_count"]


# ---------------------------------------------------------------------------
# the feed: non-consuming cursor over candidates
# ---------------------------------------------------------------------------

def feed_high_water(conn):
    """(max candidates.id, max candidates.updated) right now -- what the cursor
    is advanced to at a chunk boundary. Everything past this at read time is,
    by definition, new/changed since the hunter last looked."""
    r = conn.execute("SELECT MAX(id) AS mi, MAX(updated) AS mt FROM candidates").fetchone()
    return (r["mi"] or 0, r["mt"] or "")


def read_feed_delta(conn, cursor_id, cursor_ts, min_severity=None, limit=FEED_DELTA_DEFAULT_CAP):
    """New OR changed candidates since the cursor, brightest first.

    Returns (rows, total_matching). `total_matching` lets the caller render a
    "+N more" overflow line so a burst never silently drops off the radar --
    the hunter can then poll_feed() for the rest before the cursor rolls past
    them. `updated > ?` catches candidates whose bucket grew (rules.py upserts
    bump `updated`), not just brand-new ids -- both are "something changed
    since I last looked." status is never referenced or written."""
    where = "(id > ? OR updated > ?)"
    params = [cursor_id, cursor_ts or ""]
    if min_severity:
        where += f" AND {SEVERITY_RANK_SQL} >= ?"
        params.append(SEVERITY_ORDER.get(min_severity, 0))
    total = conn.execute(
        f"SELECT COUNT(*) AS n FROM candidates WHERE {where}", params
    ).fetchone()["n"]
    rows = conn.execute(
        f"SELECT * FROM candidates WHERE {where} "
        f"ORDER BY {SEVERITY_RANK_SQL} DESC, updated DESC LIMIT ?",
        params + [limit],
    ).fetchall()
    return rows, total


def get_candidate(conn, candidate_id):
    return conn.execute("SELECT * FROM candidates WHERE id=?", (candidate_id,)).fetchone()


# ---------------------------------------------------------------------------
# incidents + evidence
# ---------------------------------------------------------------------------

def open_incident(conn, hunt_id, title, severity="medium", entity=None, hypothesis=None):
    ts = now_iso()
    cur = conn.execute(
        "INSERT INTO incidents (hunt_id, title, status, severity, entity, hypothesis, "
        "opened_at, updated_at) VALUES (?,?, 'open', ?,?,?,?,?)",
        (hunt_id, title, severity, entity, hypothesis, ts, ts),
    )
    conn.commit()
    return cur.lastrowid


def update_incident(conn, incident_id, status=None, severity=None, hypothesis=None, summary=None):
    sets, params = [], []
    for col, val in (("status", status), ("severity", severity),
                     ("hypothesis", hypothesis), ("summary", summary)):
        if val is not None:
            sets.append(f"{col}=?")
            params.append(val)
    if not sets:
        return
    if status in ("closed", "false_positive"):
        sets.append("closed_at=?")
        params.append(now_iso())
    sets.append("updated_at=?")
    params.append(now_iso())
    params.append(incident_id)
    conn.execute(f"UPDATE incidents SET {', '.join(sets)} WHERE id=?", params)
    conn.commit()


def get_incident(conn, incident_id):
    return conn.execute("SELECT * FROM incidents WHERE id=?", (incident_id,)).fetchone()


def list_incidents(conn, hunt_id, open_only=True, exclude_handed_off=False):
    """exclude_handed_off drops every incident that has ANY handoff row -- used
    only by the hunter's own OPEN INCIDENTS block (a handed-off incident is the
    analyst's, rendered separately under HANDED OFF). The analyst's
    list_hunt_incidents keeps the default so it still sees them."""
    sql = "SELECT * FROM incidents WHERE hunt_id=?"
    if open_only:
        sql += " AND status NOT IN ('closed','false_positive')"
    if exclude_handed_off:
        sql += " AND id NOT IN (SELECT incident_id FROM incident_handoffs)"
    sql += f" ORDER BY {SEVERITY_RANK_SQL} DESC, updated_at DESC"
    return conn.execute(sql, (hunt_id,)).fetchall()


def link_evidence(conn, incident_id, kind, ref_id, note=None):
    """Idempotent (UNIQUE(incident_id, kind, ref_id)); a re-link is a no-op
    that updates the note. Touches the incident's updated_at."""
    conn.execute(
        "INSERT INTO incident_evidence (incident_id, kind, ref_id, note, added_at) "
        "VALUES (?,?,?,?,?) ON CONFLICT(incident_id, kind, ref_id) DO UPDATE SET "
        "note=COALESCE(excluded.note, incident_evidence.note)",
        (incident_id, kind, ref_id, note, now_iso()),
    )
    conn.execute("UPDATE incidents SET updated_at=? WHERE id=?", (now_iso(), incident_id))
    conn.commit()


def incident_evidence(conn, incident_id):
    return conn.execute(
        "SELECT * FROM incident_evidence WHERE incident_id=? ORDER BY id", (incident_id,)
    ).fetchall()


def incident_evidence_count(conn, incident_id):
    return conn.execute(
        "SELECT COUNT(*) AS n FROM incident_evidence WHERE incident_id=?", (incident_id,)
    ).fetchone()["n"]


# ---------------------------------------------------------------------------
# incident handoffs (hunter -> analyst queue)
# ---------------------------------------------------------------------------
# The hunter side INSERTs (add_handoff_request); the analyst responder side
# claims/requeues/resolves. See schema.sql for the column ownership split.

HANDOFF_VERDICTS = ("false_positive", "confirmed", "inconclusive")


def add_handoff_request(conn, incident_id, hunt_id, severity, brief):
    """Queue an incident for the analyst. Returns the new handoff id, or None
    if the incident already has a live (queued/in_progress) handoff -- the
    partial unique index idx_handoffs_live enforces that, so this never races."""
    ts = now_iso()
    try:
        cur = conn.execute(
            "INSERT INTO incident_handoffs (incident_id, hunt_id, severity, brief, status, "
            "handed_at, updated_at) VALUES (?,?,?,?, 'queued', ?,?)",
            (incident_id, hunt_id, severity, brief, ts, ts),
        )
    except sqlite3.IntegrityError:
        conn.rollback()
        return None
    conn.execute("UPDATE incidents SET updated_at=? WHERE id=?", (ts, incident_id))
    conn.commit()
    return cur.lastrowid


def get_handoff(conn, handoff_id):
    return conn.execute("SELECT * FROM incident_handoffs WHERE id=?", (handoff_id,)).fetchone()


def live_handoff(conn, incident_id):
    """The queued/in_progress handoff for an incident, or None."""
    return conn.execute(
        "SELECT * FROM incident_handoffs WHERE incident_id=? AND status IN ('queued','in_progress') "
        "ORDER BY id DESC LIMIT 1", (incident_id,)
    ).fetchone()


def latest_handoff_for_incident(conn, incident_id):
    """Most recent handoff of ANY status for an incident, or None."""
    return conn.execute(
        "SELECT * FROM incident_handoffs WHERE incident_id=? ORDER BY id DESC LIMIT 1",
        (incident_id,)
    ).fetchone()


def list_handoffs(conn, hunt_id, limit=12):
    """One row per handed-off incident (its latest handoff), joined to the
    incident for title/entity/current status. Feeds the hunter's HANDED OFF
    context block. Live ones first, then most recently updated."""
    return conn.execute(
        "SELECT h.*, i.title AS inc_title, i.entity AS inc_entity, i.status AS inc_status, "
        "i.severity AS inc_severity "
        "FROM incident_handoffs h JOIN incidents i ON i.id = h.incident_id "
        "WHERE h.hunt_id=? AND h.id IN (SELECT MAX(id) FROM incident_handoffs GROUP BY incident_id) "
        "ORDER BY (h.status IN ('queued','in_progress')) DESC, h.updated_at DESC LIMIT ?",
        (hunt_id, limit),
    ).fetchall()


def false_positive_handoff_for_entity(conn, hunt_id, entity):
    """The latest resolved-as-false_positive handoff for an entity in this
    hunt, or None -- lets open_incident warn the hunter before it re-opens a
    thread the analyst already explained away."""
    if not entity:
        return None
    return conn.execute(
        "SELECT h.*, i.title AS inc_title FROM incident_handoffs h "
        "JOIN incidents i ON i.id = h.incident_id "
        "WHERE h.hunt_id=? AND i.entity=? AND h.verdict='false_positive' "
        "ORDER BY h.id DESC LIMIT 1", (hunt_id, entity)
    ).fetchone()


def claim_next_handoff(conn):
    """Atomically claim the brightest queued handoff (severity DESC, id ASC).
    Returns the claimed row or None if the queue is empty. The UPDATE is
    guarded on claimed_at IS NULL so two responders can never both win."""
    row = conn.execute(
        f"SELECT id FROM incident_handoffs WHERE status='queued' "
        f"ORDER BY {SEVERITY_RANK_SQL} DESC, id ASC LIMIT 1"
    ).fetchone()
    if not row:
        return None
    ts = now_iso()
    cur = conn.execute(
        "UPDATE incident_handoffs SET status='in_progress', claimed_at=?, "
        "attempts=attempts+1, updated_at=? WHERE id=? AND claimed_at IS NULL",
        (ts, ts, row["id"]),
    )
    conn.commit()
    return get_handoff(conn, row["id"]) if cur.rowcount == 1 else None


def set_handoff_session(conn, handoff_id, session_id):
    conn.execute("UPDATE incident_handoffs SET session_id=?, updated_at=? WHERE id=?",
                 (session_id, now_iso(), handoff_id))
    conn.commit()


def requeue_handoff(conn, handoff_id):
    """Give a claimed handoff back to the queue (transient provider failure).
    attempts is kept so the responder can cap retries."""
    conn.execute(
        "UPDATE incident_handoffs SET status='queued', claimed_at=NULL, updated_at=? WHERE id=?",
        (now_iso(), handoff_id),
    )
    conn.commit()


def resolve_handoff(conn, handoff_id, verdict, confidence, rationale, session_id=None):
    ts = now_iso()
    conn.execute(
        "UPDATE incident_handoffs SET status='resolved', verdict=?, confidence=?, rationale=?, "
        "resolved_at=?, session_id=COALESCE(?, session_id), updated_at=? WHERE id=?",
        (verdict, confidence, rationale, ts, session_id, ts, handoff_id),
    )
    conn.commit()


def mark_handoff_unresolved(conn, handoff_id):
    """The responder spent its turn budget (or failed hard) without a verdict.
    Terminal for this row; the hunter may re-hand off with a sharper brief."""
    conn.execute(
        "UPDATE incident_handoffs SET status='unresolved', updated_at=? WHERE id=?",
        (now_iso(), handoff_id),
    )
    conn.commit()


def requeue_stale_in_progress(conn):
    """Startup recovery: a previous responder instance died mid-turn. Only one
    responder runs (labctl), so anything still in_progress at startup is ours."""
    cur = conn.execute(
        "UPDATE incident_handoffs SET status='queued', claimed_at=NULL, updated_at=? "
        "WHERE status='in_progress'", (now_iso(),)
    )
    conn.commit()
    return cur.rowcount


# ---------------------------------------------------------------------------
# notebook
# ---------------------------------------------------------------------------

def add_note(conn, hunt_id, chunk, note_type, body, refs=None, incident_id=None):
    cur = conn.execute(
        "INSERT INTO hunt_notes (hunt_id, incident_id, chunk, note_type, body, refs, created) "
        "VALUES (?,?,?,?,?,?,?)",
        (hunt_id, incident_id, chunk, note_type, body,
         json.dumps(refs) if refs else None, now_iso()),
    )
    conn.commit()
    return cur.lastrowid


def recent_notes(conn, hunt_id, limit=12, note_types=None):
    sql = "SELECT * FROM hunt_notes WHERE hunt_id=?"
    params = [hunt_id]
    if note_types:
        sql += " AND note_type IN (%s)" % ",".join("?" * len(note_types))
        params += list(note_types)
    sql += " ORDER BY id DESC LIMIT ?"
    params.append(limit)
    return list(reversed(conn.execute(sql, params).fetchall()))


def search_notes(conn, hunt_id, query=None, incident_id=None, ids=None, limit=25):
    if ids:
        q = "SELECT * FROM hunt_notes WHERE hunt_id=? AND id IN (%s) ORDER BY id" % \
            ",".join("?" * len(ids))
        return conn.execute(q, [hunt_id] + list(ids)).fetchall()
    sql = "SELECT * FROM hunt_notes WHERE hunt_id=?"
    params = [hunt_id]
    if incident_id is not None:
        sql += " AND incident_id=?"
        params.append(incident_id)
    if query:
        sql += " AND body LIKE ?"
        params.append(f"%{query}%")
    sql += " ORDER BY id DESC LIMIT ?"
    params.append(limit)
    return conn.execute(sql, params).fetchall()


# ---------------------------------------------------------------------------
# leads (anti-perseveration)
# ---------------------------------------------------------------------------

def add_lead(conn, hunt_id, description, incident_id=None):
    ts = now_iso()
    cur = conn.execute(
        "INSERT INTO leads (hunt_id, incident_id, description, status, fail_count, "
        "created, updated) VALUES (?,?,?, 'open', 0, ?,?)",
        (hunt_id, incident_id, description, ts, ts),
    )
    conn.commit()
    return cur.lastrowid


def update_lead(conn, lead_id, status=None, resolution=None, bump_fail=False):
    sets, params = [], []
    if status is not None:
        sets.append("status=?")
        params.append(status)
    if resolution is not None:
        sets.append("resolution=?")
        params.append(resolution)
    if bump_fail:
        sets.append("fail_count=fail_count+1")
    sets.append("updated=?")
    params.append(now_iso())
    params.append(lead_id)
    conn.execute(f"UPDATE leads SET {', '.join(sets)} WHERE id=?", params)
    conn.commit()


def active_leads(conn, hunt_id):
    """open/pursuing leads only -- dead/resolved ones drop out of the standing
    context so the hunter stops circling them."""
    return conn.execute(
        "SELECT * FROM leads WHERE hunt_id=? AND status IN ('open','pursuing') "
        "ORDER BY id", (hunt_id,)
    ).fetchall()


def get_lead(conn, lead_id):
    return conn.execute("SELECT * FROM leads WHERE id=?", (lead_id,)).fetchone()


# ---------------------------------------------------------------------------
# handoff notes + checkpoints (chunk-boundary compaction)
# ---------------------------------------------------------------------------

def add_handoff(conn, hunt_id, chunk, note, next_step=None):
    conn.execute(
        "INSERT INTO hunt_handoff_notes (hunt_id, chunk, note, next_step, created) "
        "VALUES (?,?,?,?,?)",
        (hunt_id, chunk, note, next_step, now_iso()),
    )
    conn.commit()


def latest_handoff(conn, hunt_id):
    return conn.execute(
        "SELECT * FROM hunt_handoff_notes WHERE hunt_id=? ORDER BY id DESC LIMIT 1",
        (hunt_id,),
    ).fetchone()


def add_checkpoint(conn, hunt_id, chunk, note):
    conn.execute(
        "INSERT INTO hunt_checkpoints (hunt_id, chunk, note, created) VALUES (?,?,?,?)",
        (hunt_id, chunk, note, now_iso()),
    )
    conn.commit()


def latest_checkpoint_since(conn, hunt_id, since_ts):
    """A checkpoint the model wrote during the current chunk (created >
    chunk-start ts) -- preferred over an after-the-fact handoff call, mirroring
    redteam's _latest_checkpoint_since."""
    return conn.execute(
        "SELECT * FROM hunt_checkpoints WHERE hunt_id=? AND created > ? "
        "ORDER BY id DESC LIMIT 1",
        (hunt_id, since_ts or ""),
    ).fetchone()


def next_step_stagnation_streak(conn, hunt_id):
    """How many consecutive handoff notes named the same next_step, most-recent
    first -- the signal that the hunter is stuck repeating an action. Mirrors
    redteam's _next_step_stagnation_streak; drives the escalating wording in
    context.mandatory_first_action_block()."""
    rows = conn.execute(
        "SELECT next_step FROM hunt_handoff_notes WHERE hunt_id=? AND next_step IS NOT NULL "
        "ORDER BY id DESC LIMIT 10",
        (hunt_id,),
    ).fetchall()
    if not rows:
        return 0
    latest = (rows[0]["next_step"] or "").strip().lower()
    if not latest:
        return 0
    streak = 0
    for r in rows:
        if (r["next_step"] or "").strip().lower() == latest:
            streak += 1
        else:
            break
    return streak
