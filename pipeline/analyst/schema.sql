-- The interactive analyst-chat agent's tables. Same soc.db as
-- pipeline/schema.sql, pipeline/detect/schema.sql, pipeline/triage/schema.sql,
-- pipeline/redteam/schema.sql, pipeline/hunt/schema.sql -- one lab, one
-- database, so "what did the analyst do about what red team did / what the
-- hunter flagged" stays a plain SQL join.
--
-- This is the human-in-the-loop counterpart to the standing hunter
-- (pipeline/hunt/). The hunter runs unattended and compacts its conversation
-- away at every chunk boundary; the analyst chat is DRIVEN by a human typing
-- questions, and its conversation IS the artifact -- so unlike the hunter, the
-- transcript itself is persisted (chat_turns) rather than discarded.
--
-- MEMORY POSTURE (deliberate, see the feature plan): the analyst READS the
-- live hunt's shared memory (incidents / hunt_notes / leads, via
-- pipeline/hunt/store.py) for context, but WRITES only to its own tables here
-- -- so two agents never contend on the same rows and the frozen injection_asr
-- compatibility surface (candidates.status, the triage action tables'
-- NOT NULL candidate_id) is never touched. That is why analyst actions land in
-- chat_actions below, NOT in the hunter/triage action tables: a chat action is
-- often taken on a bare IP the operator named, with no representative
-- candidate_id to satisfy those tables' constraint.
--
-- RESPONDER MODE (pipeline/analyst/agent.py --serve): the same agent also
-- runs unattended as the analyst RESPONDER, claiming incidents the hunter
-- handed off (pipeline/hunt/schema.sql: incident_handoffs) and working each
-- in a chat session of its own. chat_sessions.incident_id / chat_actions.
-- incident_id tie that session and its actions back to the incident. Those
-- two columns are ALTER-migrated in chat_store.migrate() for pre-existing
-- databases (CREATE TABLE IF NOT EXISTS can't add a column).

-- One row per interactive chat session. A session is opened when an operator
-- starts a conversation and stays 'active' until closed; it can be resumed
-- across processes (pipeline/analyst/agent.py --session <id>) because the
-- whole transcript lives in chat_turns, not in memory. hunt_id records which
-- standing hunt this session was opened against, so the shared-memory reads
-- (incidents/notes/leads) resolve to the right hunt even if a newer one starts
-- later; nullable because a chat can be opened with no hunt running.
CREATE TABLE IF NOT EXISTS chat_sessions (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    started     TEXT    NOT NULL,
    ended       TEXT,
    provider    TEXT    NOT NULL,
    model       TEXT    NOT NULL,
    lab_mode    TEXT,                              -- active lab mode at start (best-effort)
    status      TEXT    NOT NULL DEFAULT 'active', -- active | closed
    title       TEXT,                              -- short human label (first question, or set later)
    hunt_id     INTEGER,                           -- the standing hunt this chat reads shared memory from
    incident_id INTEGER,                           -- set on responder-opened sessions ("Incident #N"); see incident_handoffs
    created     TEXT    NOT NULL,
    updated     TEXT    NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_chat_sessions_status ON chat_sessions(status);

-- The full transcript, one row per turn, in order (seq is monotonic within a
-- session). role tells the renderer what a row is:
--   user        -- the operator's typed message (the TRUSTED instruction channel)
--   assistant   -- the model's natural-language reply
--   tool_call   -- the model invoked a tool (tool_name + tool_input JSON)
--   tool_result -- the result handed back (tool_result_preview; is_error=1 on failure)
-- tool_result content is size-capped to a preview here (the full result was
-- already fenced as <untrusted-evidence> when the tool built it, and the model
-- saw it in-context) -- the transcript is for humans and replay, not forensics.
CREATE TABLE IF NOT EXISTS chat_turns (
    id                  INTEGER PRIMARY KEY AUTOINCREMENT,
    session_id          INTEGER NOT NULL REFERENCES chat_sessions(id),
    seq                 INTEGER NOT NULL,
    role                TEXT    NOT NULL,   -- user | assistant | tool_call | tool_result
    content             TEXT,               -- user/assistant text, or NULL for tool rows
    tool_name           TEXT,               -- set on tool_call / tool_result rows
    tool_input          TEXT,               -- JSON, set on tool_call rows
    tool_result_preview TEXT,               -- preview of the tool result, set on tool_result rows
    is_error            INTEGER NOT NULL DEFAULT 0,
    created             TEXT    NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_chat_turns_session ON chat_turns(session_id, seq);

-- The analyst's write-own notebook: findings the operator/model want kept with
-- the session (distinct from the shared hunt notebook, which the analyst only
-- reads). refs is an optional JSON array [{"kind":..,"id":N}] pointing at the
-- candidates/events/incidents a note is about, same shape as hunt_notes.refs.
CREATE TABLE IF NOT EXISTS chat_notes (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    session_id  INTEGER NOT NULL REFERENCES chat_sessions(id),
    note_type   TEXT    NOT NULL DEFAULT 'finding',  -- observation | hypothesis | finding | decision
    body        TEXT    NOT NULL,
    refs        TEXT,                                 -- JSON array of {kind, id}; NULL if none
    created     TEXT    NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_chat_notes_session ON chat_notes(session_id);

-- Every response action the analyst takes, attributed to the chat session.
-- REAL actions (block_ip, harden/quarantine) go through the exact same
-- backends the hunter uses (pipeline/triage/block_enforcer.py,
-- northwind_enforcer.py) with the identical hard fences -- this table is the
-- audit record, not the safety boundary. executed distinguishes a fence
-- rejection (executed=0, error in result_json) from a real enforcement
-- (executed=1). kind covers the full parity set the operator chose:
-- alert | recommend_block | block_ip | page_oncall | harden_northwind |
-- quarantine_northwind.
CREATE TABLE IF NOT EXISTS chat_actions (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    session_id  INTEGER NOT NULL REFERENCES chat_sessions(id),
    incident_id INTEGER,                 -- the hunter incident this action was taken for (nullable)
    kind        TEXT    NOT NULL,
    src_ip      TEXT,                -- the IP acted on, for block/recommend
    target_ref  TEXT,                -- free-form target (document id, toggle set, candidate id, ...)
    reason      TEXT,
    executed    INTEGER NOT NULL DEFAULT 0,
    result_json TEXT,
    created     TEXT    NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_chat_actions_session ON chat_actions(session_id);
