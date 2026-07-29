-- The red-team agent's tables. Same soc.db as pipeline/schema.sql,
-- pipeline/detect/schema.sql, pipeline/triage/schema.sql -- the point of
-- running red and blue in one lab is being
-- able to ask "did blue team catch what red team did", which is a plain SQL
-- join (candidates.src_ip = redteam_sessions.attacker_ip, time-windowed) if
-- both live here, and a needless ATTACH-database complication if they don't.

CREATE TABLE IF NOT EXISTS redteam_sessions (
    id             INTEGER PRIMARY KEY AUTOINCREMENT,
    started        TEXT    NOT NULL,
    ended          TEXT,
    provider       TEXT    NOT NULL,   -- 'claude' | 'local'
    model          TEXT    NOT NULL,
    attacker_ip    TEXT,               -- soc-attacker's CURRENT bridge IP --
                                        -- join key against events.src_ip / candidates.src_ip.
                                        -- Updated in place by rotate_ip(); see
                                        -- session_ip_history for the full trail.
    stage          TEXT    NOT NULL DEFAULT 'recon',   -- recon | assess | done
    status         TEXT    NOT NULL DEFAULT 'running', -- running | completed | error
    recon_summary  TEXT,
    assess_summary TEXT,
    mission_brief  TEXT,               -- operator-supplied attacker persona/objective text
                                        -- (see agent.py's --mission-file), appended to the
                                        -- default recon/assess system prompts. NULL means the
                                        -- default generic broad-recon persona was used. Stored
                                        -- so --continue-assess picks up the same persona
                                        -- without the file having to be passed again.
    created        TEXT    NOT NULL
);

-- Every rotate_ip() call -- the attacker deliberately abandoning its current
-- bridge IP for a fresh one mid-session, as an evasion tactic against
-- IP-based detection/blocking (see triage/agent.py's block_ip). Deliberate
-- consequence, not a bug: after a rotation, new traffic from the new IP no
-- longer joins to this session via the simple `redteam_sessions.attacker_ip
-- = candidates.src_ip` trick the comment at the top of this file describes
-- -- that's realistic (IP rotation breaks naive IP-based correlation for a
-- real defender too), which is exactly the behavior this lab exists to
-- measure. `redteam_sessions.attacker_ip` always holds the CURRENT address
-- so live views (the dashboard) don't need to know about rotation at all;
-- this table is the full history for anyone reconstructing which IP a
-- given candidate's traffic actually came from.
CREATE TABLE IF NOT EXISTS session_ip_history (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    session_id    INTEGER NOT NULL REFERENCES redteam_sessions(id),
    old_ip        TEXT,
    new_ip        TEXT    NOT NULL,
    reason        TEXT,
    created       TEXT    NOT NULL
);

-- Written automatically by the recon tool_* functions themselves, not by a
-- model-called "save finding" tool -- deterministic persistence, same as
-- ingest.py/rules.py never depending on an LLM to remember to record something.
CREATE TABLE IF NOT EXISTS recon_findings (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    session_id    INTEGER NOT NULL REFERENCES redteam_sessions(id),
    target        TEXT    NOT NULL,   -- 'cowrie' | 'nginx'
    finding_type  TEXT    NOT NULL,   -- port_open | service | http_path | ...
    detail        TEXT,               -- JSON, tool-specific
    source_tool   TEXT    NOT NULL,
    created       TEXT    NOT NULL
);

-- Written by raise_vuln_finding(), an LLM judgment call -- safe, ungated,
-- direct analog of pipeline/agent.py's raise_alert().
CREATE TABLE IF NOT EXISTS vuln_findings (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    session_id    INTEGER NOT NULL REFERENCES redteam_sessions(id),
    target        TEXT    NOT NULL,
    category      TEXT    NOT NULL,   -- e.g. weak-credential-candidate, sqli-candidate
    severity      TEXT    NOT NULL,   -- info|low|medium|high|critical
    description   TEXT    NOT NULL,
    evidence_ref  TEXT,               -- JSON array of recon_findings ids
    created       TEXT    NOT NULL
);

-- THE GATE, with one exception. The model can only ever INSERT here, via
-- propose_action -- the only tool in the ASSESS stage that can produce a row
-- here. For a target outside redteam_exec.ALLOWED_NETWORKS, the only
-- function that calls redteam_exec.run() for one of these tool names is
-- execute_pending_action() in redteam_agent.py, reachable only via
-- `--execute-approved`, which itself only ever touches rows a human already
-- flipped approved=1 via a separate `--approve` invocation -- run is never a
-- side effect of the model's own turn. For a target INSIDE
-- ALLOWED_NETWORKS (currently cowrie and nginx both qualify), propose_action
-- inserts the row pre-approved (approved_by='auto-whitelist') and calls
-- execute_pending_action() immediately, in the same turn -- lab-internal
-- targets skip the human round trip entirely. See redteam_agent.py's module
-- docstring for the full gate description.
CREATE TABLE IF NOT EXISTS pending_actions (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    session_id    INTEGER NOT NULL REFERENCES redteam_sessions(id),
    tool          TEXT    NOT NULL,   -- hydra_bruteforce | sqlmap_scan | ssh_exec
    target        TEXT    NOT NULL,   -- 'cowrie' | 'nginx'
    input_json    TEXT    NOT NULL,   -- exact params as proposed, replayed verbatim on execute
    rationale     TEXT,
    based_on      TEXT,               -- JSON array of vuln_findings ids
    approved      INTEGER NOT NULL DEFAULT 0,
    approved_by   TEXT,
    approved_at   TEXT,
    executed      INTEGER NOT NULL DEFAULT 0,
    executed_at   TEXT,
    result_json   TEXT,               -- ExecResult, NULL until executed
    created       TEXT    NOT NULL
);

-- The structured extension of "raw files in attacker/loot/" -- every
-- artifact still lands as a real file (nmap -oN, sqlmap --output-dir, hydra
-- -o), but now has a DB row: which session, which tool, which target, a
-- capped summary (the text actually shown to the model), and (for gated
-- tools) which approved action produced it.
CREATE TABLE IF NOT EXISTS loot (
    id                 INTEGER PRIMARY KEY AUTOINCREMENT,
    session_id         INTEGER NOT NULL REFERENCES redteam_sessions(id),
    pending_action_id  INTEGER REFERENCES pending_actions(id),  -- NULL for recon-stage loot
    tool               TEXT    NOT NULL,
    target             TEXT,
    path               TEXT    NOT NULL,   -- under attacker/loot/, host-visible
    summary            TEXT,               -- capped text actually returned to the model
    exit_code          INTEGER,
    created            TEXT    NOT NULL
);

CREATE TABLE IF NOT EXISTS captured_flags (
    id                 INTEGER PRIMARY KEY AUTOINCREMENT,
    session_id         INTEGER NOT NULL REFERENCES redteam_sessions(id),
    target             TEXT    NOT NULL,   -- 'cowrie' | 'nginx'
    flag_value         TEXT    NOT NULL,
    method             TEXT,               -- how it surfaced (tool + brief path)
    pending_action_id  INTEGER REFERENCES pending_actions(id),
    created            TEXT    NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_recon_session   ON recon_findings(session_id);
CREATE INDEX IF NOT EXISTS idx_vuln_session    ON vuln_findings(session_id);
CREATE INDEX IF NOT EXISTS idx_pending_session ON pending_actions(session_id);
CREATE INDEX IF NOT EXISTS idx_pending_gate    ON pending_actions(approved, executed);
CREATE INDEX IF NOT EXISTS idx_loot_session    ON loot(session_id);
CREATE INDEX IF NOT EXISTS idx_flags_session   ON captured_flags(session_id);
