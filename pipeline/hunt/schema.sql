-- The threat-hunter agent's tables. Same soc.db as pipeline/schema.sql,
-- pipeline/detect/schema.sql, pipeline/triage/schema.sql,
-- pipeline/redteam/schema.sql -- one lab, one database, so "did the hunter
-- catch what red team did" stays a plain SQL join.
--
-- These tables are the blue-team mirror of the red-team agent's externalized
-- memory (redteam/schema.sql: redteam_sessions/wins/handoff_notes/
-- checkpoints/branches). The load-bearing idea is identical: the DB is the
-- agent's memory, not the model's conversation. The hunter discards its
-- conversation at every chunk boundary and rebuilds an evolving picture from
-- these rows -- so nothing depends on the model choosing to persist, and a
-- kill -TERM (or a crash, or a --continue days later) loses no context.
--
-- The unit here is a HUNT SESSION (a standing investigation that never
-- "completes"), inside which the hunter promotes candidates into INCIDENTS
-- and keeps a freeform NOTEBOOK. Unlike the old triage tier, the hunter does
-- NOT treat candidates as a work queue and never writes candidates.status --
-- it reads candidates as a growing intel stream via a non-consuming cursor
-- (hunt_sessions.feed_cursor_*). See pipeline/hunt/store.py.

-- One row per standing hunt. hunt_id threads every child table below, exactly
-- as redteam_sessions.id threads the red-team tables. A hunt is resumable
-- across processes (pipeline/hunt/agent.py --continue <id>): status flips
-- running <-> idle as the feed goes busy/quiet, and to 'stopped' on a clean
-- SIGINT/SIGTERM. feed_cursor_id / feed_cursor_ts are the non-consuming
-- watermark into the candidates feed -- advanced to the feed's high-water
-- mark at each chunk boundary, never by flipping candidates.status (that
-- column is now vestigial; the hunter's memory of "what I've looked at" is
-- the notebook + incidents, not a queue flag).
CREATE TABLE IF NOT EXISTS hunt_sessions (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    started         TEXT    NOT NULL,
    ended           TEXT,
    provider        TEXT    NOT NULL,
    model           TEXT    NOT NULL,
    lab_mode        TEXT,                          -- active lab mode at start (best-effort)
    status          TEXT    NOT NULL DEFAULT 'running',  -- running | idle | stopped
    chunk_count     INTEGER NOT NULL DEFAULT 0,
    feed_cursor_id  INTEGER NOT NULL DEFAULT 0,    -- last candidates.id acknowledged
    feed_cursor_ts  TEXT    NOT NULL DEFAULT '',   -- last candidates.updated acknowledged
    created         TEXT    NOT NULL,
    updated         TEXT    NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_hunt_sessions_status ON hunt_sessions(status);

-- The investigation grouping unit -- all-new on the blue side (no "incident"
-- existed before; candidate was the only unit). The hunter opens one when a
-- thread looks worth pursuing and hangs its notebook + actions off it. entity
-- is the primary pivot (usually a src_ip). severity is the hunter's judgment,
-- not the max of member candidates -- a hunter can rate an incident above or
-- below the deterministic severity of the candidates that seeded it.
CREATE TABLE IF NOT EXISTS incidents (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    hunt_id       INTEGER NOT NULL REFERENCES hunt_sessions(id),
    title         TEXT    NOT NULL,
    status        TEXT    NOT NULL DEFAULT 'open',    -- open | monitoring | contained | closed | false_positive
    severity      TEXT    NOT NULL DEFAULT 'medium',  -- info | low | medium | high | critical
    entity        TEXT,                                -- primary pivot: src_ip or other entity key
    hypothesis    TEXT,
    summary       TEXT,
    opened_at     TEXT    NOT NULL,
    updated_at    TEXT    NOT NULL,
    closed_at     TEXT
);
CREATE INDEX IF NOT EXISTS idx_incidents_hunt   ON incidents(hunt_id);
CREATE INDEX IF NOT EXISTS idx_incidents_status ON incidents(status);
CREATE INDEX IF NOT EXISTS idx_incidents_entity ON incidents(entity);

-- Links an incident to the candidates / raw events that are its evidence
-- ("tied to events it creates along the way"). Many-to-one: one candidate can
-- inform several incidents. UNIQUE keeps link_evidence idempotent.
CREATE TABLE IF NOT EXISTS incident_evidence (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    incident_id   INTEGER NOT NULL REFERENCES incidents(id),
    kind          TEXT    NOT NULL,   -- 'candidate' | 'event'
    ref_id        INTEGER NOT NULL,   -- candidates.id or events.id
    note          TEXT,
    added_at      TEXT    NOT NULL,
    UNIQUE(incident_id, kind, ref_id)
);
CREATE INDEX IF NOT EXISTS idx_incident_evidence_inc ON incident_evidence(incident_id);

-- The hunter's notebook -- the blue-team mirror of redteam `wins` +
-- `vuln_findings`, but keyed to a hunt (and optionally an incident) instead
-- of a red-team session. Freeform, timestamped, linkable: refs is an optional
-- JSON array [{"kind":"candidate"|"event"|"incident","id":N}] so a note can
-- point at the evidence it's about the same way red-team wins reference "see
-- recon finding #47" in prose. note_type lets the context renderer surface
-- findings/decisions prominently and keep routine observations terse.
CREATE TABLE IF NOT EXISTS hunt_notes (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    hunt_id       INTEGER NOT NULL REFERENCES hunt_sessions(id),
    incident_id   INTEGER REFERENCES incidents(id),   -- nullable: a note need not belong to an incident
    chunk         INTEGER NOT NULL,
    note_type     TEXT    NOT NULL,   -- observation | hypothesis | lead | decision | finding
    body          TEXT    NOT NULL,
    refs          TEXT,               -- JSON array of {kind, id}; NULL if none
    created       TEXT    NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_hunt_notes_hunt ON hunt_notes(hunt_id);
CREATE INDEX IF NOT EXISTS idx_hunt_notes_inc  ON hunt_notes(incident_id);

-- Anti-perseveration -- the blue-team mirror of redteam `branches`. One row
-- per thread the hunter decides to pursue. fail_count climbs when the hunter
-- reports a lead going nowhere; a lead marked 'dead' is dropped from the
-- standing context block so the hunter stops circling it. Distinct from a
-- hunt_note of type 'lead': a note is a timestamped observation, a lead is a
-- tracked, status-bearing thread of work.
CREATE TABLE IF NOT EXISTS leads (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    hunt_id       INTEGER NOT NULL REFERENCES hunt_sessions(id),
    incident_id   INTEGER REFERENCES incidents(id),
    description   TEXT    NOT NULL,
    status        TEXT    NOT NULL DEFAULT 'open',  -- open | pursuing | dead | resolved
    fail_count    INTEGER NOT NULL DEFAULT 0,
    resolution    TEXT,
    created       TEXT    NOT NULL,
    updated       TEXT    NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_leads_hunt   ON leads(hunt_id);
CREATE INDEX IF NOT EXISTS idx_leads_status ON leads(status);

-- Chunk-boundary compaction -- mirror of redteam handoff_notes. Written by a
-- cheap no-tools model call when a chunk is cut off (IterationsExhausted /
-- ContextBudgetExceeded), distilling "where the hunt stands" so the next
-- fresh chunk can reorient. next_step is the parsed "NEXT STEP:" line, hoisted
-- into the next chunk's MANDATORY FIRST ACTION block (see context.py).
CREATE TABLE IF NOT EXISTS hunt_handoff_notes (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    hunt_id       INTEGER NOT NULL REFERENCES hunt_sessions(id),
    chunk         INTEGER NOT NULL,
    note          TEXT    NOT NULL,
    next_step     TEXT,
    created       TEXT    NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_hunt_handoff_hunt ON hunt_handoff_notes(hunt_id);

-- Model-initiated mid-turn state save -- mirror of redteam checkpoints. When
-- the hunter calls checkpoint(note) during a chunk, the boundary compaction
-- prefers that over an after-the-fact handoff call (the model's own words,
-- and one fewer completion). Distinct table from hunt_handoff_notes so we can
-- always tell which restarts the hunter saw coming.
CREATE TABLE IF NOT EXISTS hunt_checkpoints (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    hunt_id       INTEGER NOT NULL REFERENCES hunt_sessions(id),
    chunk         INTEGER NOT NULL,
    note          TEXT    NOT NULL,
    created       TEXT    NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_hunt_checkpoints_hunt ON hunt_checkpoints(hunt_id);
