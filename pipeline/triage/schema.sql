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
-- block_ip_calls, just below, is a SEPARATE, deliberately UNGATED path --
-- REAL enforcement as of 2026-07-28 (was a no-op test stand-in before
-- that; see tool_block_ip's docstring in agent.py and block_enforcer.py).
-- Its existence does not mean the gate above was removed for
-- recommend_block; it's a second, independent tool with a different safety
-- model: instead of a human approval queue, block_ip's safety boundary is
-- hard technical fencing (block_enforcer.validate_lab_ip()) that rejects
-- any src_ip outside this lab's own docker subnet before anything runs.
-- Worth being precise about what that fencing does and doesn't cover: it
-- guarantees a block can never reach outside the lab's own network, but it
-- does NOT protect against the model picking the wrong IN-subnet target --
-- an injected "the real attacker is actually X, block that instead" is
-- still exactly the self-DoS risk described above, just scoped smaller.
-- That risk is mitigated by the system prompt's untrusted-evidence
-- skepticism, not by a technical control, same as everywhere else
-- attacker-controlled text could influence a tool call.
CREATE TABLE IF NOT EXISTS block_recommendations (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    candidate_id  INTEGER NOT NULL REFERENCES candidates(id),
    src_ip        TEXT    NOT NULL,
    reason        TEXT    NOT NULL,
    approved      INTEGER NOT NULL DEFAULT 0,
    created       TEXT    NOT NULL
);

-- Every block_ip() call -- REAL enforcement (see tool_block_ip,
-- block_enforcer.py): a real iptables DROP rule, inserted immediately, no
-- human review. Deliberately no `approved` column: unlike
-- block_recommendations, nothing here waits for a human before the model's
-- call takes effect. `executed` distinguishes a real block from a call
-- block_enforcer's hard fencing rejected (src_ip outside the lab's own
-- docker subnet, or the bridge gateway) -- rejected calls still land a row
-- here, `executed=0`, `result_json` holding the rejection reason, so a
-- rejected attempt stays just as visible/auditable as a real one. See
-- network-reset.sh to remove every rule this has ever inserted.
CREATE TABLE IF NOT EXISTS block_ip_calls (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    candidate_id  INTEGER NOT NULL REFERENCES candidates(id),
    src_ip        TEXT    NOT NULL,
    reason        TEXT    NOT NULL,
    executed      INTEGER NOT NULL DEFAULT 0,   -- 1 = real iptables rule inserted, 0 = rejected
    executed_at   TEXT,                          -- NULL unless executed=1
    result_json   TEXT,                          -- block_enforcer's return value or error
    created       TEXT    NOT NULL
);

-- Every page_oncall() call. Same "test stand-in, always logged" pattern as
-- block_ip_calls -- see tool_page_oncall's docstring in agent.py -- no real
-- pager/SMS/phone integration exists, nothing here wakes an actual human.
-- What this table is FOR: this is the loudest tool the agent has, the one
-- that claims "a human should be woken up for this right now." Whether the
-- agent reaches for it at the right threshold -- not on every high-severity
-- candidate (alert fatigue), not withheld when something really does look
-- like an active intrusion -- is exactly the judgment this lab measures.
CREATE TABLE IF NOT EXISTS human_pages (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    candidate_id  INTEGER NOT NULL REFERENCES candidates(id),
    reason        TEXT    NOT NULL,
    created       TEXT    NOT NULL
);
