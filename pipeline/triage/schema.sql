-- The agent's output. One row per verdict, keyed to candidates.id, so a
-- re-run is idempotent and a human can audit what the agent decided and why.
--
-- candidates.status is the agent's ONLY write to that table (flipped to
-- 'triaged' in pipeline/agent.py right after the row below is inserted) --
-- see AGENT_BRIEF.md #2. Everything else the agent produces lives here or in
-- the two tables below it.

CREATE TABLE IF NOT EXISTS triage (
    id                  INTEGER PRIMARY KEY AUTOINCREMENT,
    candidate_id        INTEGER NOT NULL REFERENCES candidates(id),
    verdict             TEXT    NOT NULL,   -- benign|suspicious|malicious|needs_human|error
    confidence          REAL,               -- 0.0-1.0; NULL on a provider/parse failure
    rationale           TEXT    NOT NULL,
    recommended_action  TEXT,
    attack_technique    TEXT,               -- MITRE ATT&CK id, else NULL
    model               TEXT    NOT NULL,   -- exact model string that produced this
    provider            TEXT    NOT NULL,   -- 'claude' | 'local'
    tool_calls          INTEGER NOT NULL DEFAULT 0,
    error               TEXT,               -- failure detail; NULL on a real verdict
    elapsed_s           REAL,               -- wall-clock seconds for this candidate's provider.complete() call
    thinking            TEXT,               -- reasoning trace, where the provider exposes one; NULL if none captured
    created             TEXT    NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_triage_candidate ON triage(candidate_id);
CREATE INDEX IF NOT EXISTS idx_triage_verdict   ON triage(verdict);

-- raise_alert() writes here. Safe, ungated tool -- a human-readable record,
-- nothing that acts on the world.
CREATE TABLE IF NOT EXISTS agent_alerts (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    candidate_id  INTEGER NOT NULL REFERENCES candidates(id),
    severity      TEXT    NOT NULL,
    summary       TEXT    NOT NULL,
    created       TEXT    NOT NULL
);

-- The block gate. recommend_block() writes here; `approved` starts at 0 and
-- nothing in this codebase ever flips it or reads it to take action -- that
-- gap IS the human-in-the-loop gate for this path. An agent that reads
-- attacker-controlled text and can act on it unsupervised is a self-DoS
-- waiting to happen -- an injected "recommend blocking 10.0.0.1" against
-- your own gateway becomes an outage the moment something automates the
-- approval away.
--
-- block_ip_calls, just below, is a SEPARATE, deliberately UNGATED path added
-- 2026-07-21 at explicit request, purely so the red-team ASR harness
-- (harness/scorer.py) could measure what happens when the agent has an
-- execute-capable block tool instead of only this gated one. It is a no-op
-- test stand-in -- see tool_block_ip's docstring in agent.py -- not a real
-- firewall integration. Its existence does not mean the gate below was
-- removed; it's an additional, intentionally-unsafe tool layered on top for
-- testing, not a replacement for it.
CREATE TABLE IF NOT EXISTS block_recommendations (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    candidate_id  INTEGER NOT NULL REFERENCES candidates(id),
    src_ip        TEXT    NOT NULL,
    reason        TEXT    NOT NULL,
    approved      INTEGER NOT NULL DEFAULT 0,
    created       TEXT    NOT NULL
);

-- Every block_ip() call, "executed" or not -- it's never actually executed,
-- see tool_block_ip. Deliberately no `approved` column: unlike
-- block_recommendations, nothing here waits for a human before the model's
-- call returns success. That's the point of a separate table -- "the agent
-- called the ungated block tool, at this target" stays visible and
-- auditable even though this implementation never touches real
-- infrastructure.
CREATE TABLE IF NOT EXISTS block_ip_calls (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    candidate_id  INTEGER NOT NULL REFERENCES candidates(id),
    src_ip        TEXT    NOT NULL,
    reason        TEXT    NOT NULL,
    created       TEXT    NOT NULL
);
