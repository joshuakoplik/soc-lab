"""Read-only soc.db queries for the signals the supervisor acts on.

Everything here opens the DB read-only (mode=ro, like dashboard/server.py:112) --
labctl never writes to the agents' tables. These functions read state the hunter
and attacker ALREADY persist for their own reasons; the hunter has no idea labctl
is watching, and no idea what an "attack run" is. That separation is the whole
point of the lab manager.

A note on `finished`: redteam/schema.sql documents redteam_sessions.status as
running|completed|error, but agent.py also writes 'incomplete' on a failed stage.
So "finished" here is simply status != 'running' -- covering completed, error,
incomplete, and any future terminal value without a brittle allowlist.
"""

import sqlite3

from . import config


def _connect(db_path=None):
    path = db_path or config.SOC_DB
    conn = sqlite3.connect(f"file:{path}?mode=ro", uri=True, check_same_thread=False)
    conn.row_factory = sqlite3.Row
    return conn


def _table_exists(conn, name):
    row = conn.execute(
        "SELECT 1 FROM sqlite_master WHERE type='table' AND name=?", (name,)
    ).fetchone()
    return row is not None


def hunter_state(db_path=None):
    """The current standing hunt's lifecycle signal, or None if no hunt row exists.

    Returns {hunt_id, status, chunk_count, feed_cursor_id, provider, model,
    started, updated}. status is running|idle|stopped (hunt/schema.sql). The
    supervisor uses (status, chunk_count) to decide idleness -- NOT the `updated`
    timestamp, since the hunter re-touches that row on every idle poll.
    """
    try:
        conn = _connect(db_path)
    except sqlite3.Error:
        return None
    try:
        if not _table_exists(conn, "hunt_sessions"):
            return None
        # The latest non-stopped hunt is the standing one (mirrors
        # store.latest_resumable_hunt); fall back to the newest row otherwise so
        # `status` can still report a just-stopped hunt.
        row = conn.execute(
            "SELECT * FROM hunt_sessions WHERE status IN ('running','idle') "
            "ORDER BY id DESC LIMIT 1"
        ).fetchone()
        if row is None:
            row = conn.execute(
                "SELECT * FROM hunt_sessions ORDER BY id DESC LIMIT 1"
            ).fetchone()
        if row is None:
            return None
        return {
            "hunt_id": row["id"],
            "status": row["status"],
            "chunk_count": row["chunk_count"],
            "feed_cursor_id": row["feed_cursor_id"],
            "provider": row["provider"],
            "model": row["model"],
            "started": row["started"],
            "updated": row["updated"],
        }
    except sqlite3.Error:
        return None
    finally:
        conn.close()


def active_attack_runs(db_path=None):
    """Red-team sessions still running (status='running'). List of row dicts."""
    try:
        conn = _connect(db_path)
    except sqlite3.Error:
        return []
    try:
        if not _table_exists(conn, "redteam_sessions"):
            return []
        rows = conn.execute(
            "SELECT id, stage, status, started, provider, model FROM redteam_sessions "
            "WHERE status='running' ORDER BY id DESC"
        ).fetchall()
        return [dict(r) for r in rows]
    except sqlite3.Error:
        return []
    finally:
        conn.close()


def max_redteam_id(db_path=None):
    """Highest redteam_sessions.id, or 0. The supervisor baselines its
    `last_seen_redteam_id` from this so it only reacts to runs that finish AFTER
    it started watching (it never retro-fires on old completed campaigns)."""
    try:
        conn = _connect(db_path)
    except sqlite3.Error:
        return 0
    try:
        if not _table_exists(conn, "redteam_sessions"):
            return 0
        row = conn.execute("SELECT MAX(id) AS m FROM redteam_sessions").fetchone()
        return (row["m"] or 0) if row else 0
    except sqlite3.Error:
        return 0
    finally:
        conn.close()


def newly_finished_runs(since_id, db_path=None):
    """Red-team runs with id > since_id that are no longer running (finished).

    Returns (rows, new_high_water). new_high_water is the max id seen among ALL
    runs > since_id (finished or not) so the caller advances past runs it has
    accounted for without missing a still-running one that finishes later.
    """
    try:
        conn = _connect(db_path)
    except sqlite3.Error:
        return [], since_id
    try:
        if not _table_exists(conn, "redteam_sessions"):
            return [], since_id
        finished = conn.execute(
            "SELECT id, stage, status, ended FROM redteam_sessions "
            "WHERE id > ? AND status != 'running' ORDER BY id",
            (since_id,),
        ).fetchall()
        hw_row = conn.execute(
            "SELECT MAX(id) AS m FROM redteam_sessions WHERE id > ? AND status != 'running'",
            (since_id,),
        ).fetchone()
        high = (hw_row["m"] or since_id) if hw_row else since_id
        return [dict(r) for r in finished], high
    except sqlite3.Error:
        return [], since_id
    finally:
        conn.close()


def pending_feed_count(cursor_id, db_path=None):
    """How many candidates sit beyond the hunter's feed cursor -- i.e. work it
    hasn't acknowledged yet. 0 with the hunter idle is a firm 'nothing to do'
    signal, guarding the idle decision against a just-arrived-but-unpolled race."""
    if cursor_id is None:
        cursor_id = 0
    try:
        conn = _connect(db_path)
    except sqlite3.Error:
        return 0
    try:
        if not _table_exists(conn, "candidates"):
            return 0
        row = conn.execute(
            "SELECT COUNT(*) AS c FROM candidates WHERE id > ?", (cursor_id,)
        ).fetchone()
        return (row["c"] or 0) if row else 0
    except sqlite3.Error:
        return 0
    finally:
        conn.close()


def handoff_state(db_path=None):
    """The hunter -> analyst handoff queue (incident_handoffs) as counts, or
    None if the table doesn't exist yet. Read-only; the responder's progress
    signal, the way hunt_sessions is the hunter's."""
    try:
        conn = _connect(db_path)
    except sqlite3.Error:
        return None
    try:
        if not _table_exists(conn, "incident_handoffs"):
            return None
        out = {"queued": 0, "in_progress": 0, "resolved": 0, "unresolved": 0}
        for r in conn.execute("SELECT status, COUNT(*) AS n FROM incident_handoffs GROUP BY status"):
            if r["status"] in out:
                out[r["status"]] = r["n"]
        return out
    except sqlite3.Error:
        return None
    finally:
        conn.close()


def summary(db_path=None):
    """Compact dict for `labctl status` / the dashboard: hunter + handoffs + attack runs."""
    return {
        "hunter": hunter_state(db_path),
        "handoffs": handoff_state(db_path),
        "active_attack_runs": active_attack_runs(db_path),
    }
