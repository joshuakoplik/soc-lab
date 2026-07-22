-- The rules tier's output. This is the ONLY table the agent reads in step 4.
--
-- The unit here is a candidate, not an event: one row per (rule, src_ip, time
-- bucket), with the underlying events referenced as evidence. 200 failed logins
-- from one IP is ONE candidate, not 200. That aggregation is most of the volume
-- cut, and it's also what lets the model see an attack instead of a fragment.

CREATE TABLE IF NOT EXISTS candidates (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    dedupe_key    TEXT    NOT NULL UNIQUE,
    rule          TEXT    NOT NULL,
    severity      TEXT    NOT NULL,
    src_ip        TEXT,
    first_seen    TEXT    NOT NULL,
    last_seen     TEXT    NOT NULL,
    event_count   INTEGER NOT NULL,
    evidence      TEXT    NOT NULL,
    detail        TEXT,
    status        TEXT    NOT NULL DEFAULT 'new',
    created       TEXT    NOT NULL,
    updated       TEXT    NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_cand_status   ON candidates(status);
CREATE INDEX IF NOT EXISTS idx_cand_severity ON candidates(severity);
CREATE INDEX IF NOT EXISTS idx_cand_ip       ON candidates(src_ip);

CREATE TABLE IF NOT EXISTS rule_state (
    k       TEXT PRIMARY KEY,
    v       TEXT NOT NULL,
    updated TEXT NOT NULL
);
