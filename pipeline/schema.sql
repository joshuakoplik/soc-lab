-- One table, one event shape, both sources. The agent only ever sees this.
--
-- Design note that matters later: columns are split by TRUST, not just by type.
-- Everything under "attacker-controlled" is free text that a hostile party wrote
-- and we merely transported. When the LLM lands in step 4, that distinction is
-- the difference between a triage analyst and a confused deputy.

PRAGMA journal_mode = WAL;

CREATE TABLE IF NOT EXISTS events (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,

    -- ---- infrastructure-asserted: we observed this, nobody could forge it ----
    ts            TEXT    NOT NULL,   -- ISO8601 UTC, normalized from both sources
    source        TEXT    NOT NULL,   -- 'cowrie' | 'nginx'
    host          TEXT,               -- emitting host: which NPC/sensor produced the line.
                                      -- Set for Wazuh fleet alerts (from the log location /
                                      -- predecoder hostname); NULL for sources that don't
                                      -- attribute a host. Infrastructure-asserted.
    event_type    TEXT    NOT NULL,   -- canonical taxonomy, see normalize.py
    src_ip        TEXT,
    src_port      INTEGER,
    dst_port      INTEGER,
    session_id    TEXT,               -- cowrie session; NULL for nginx
    http_status   INTEGER,
    bytes_sent    INTEGER,

    -- ---- attacker-controlled: free text, hostile until proven otherwise ----
    username      TEXT,
    password      TEXT,
    command       TEXT,               -- typed shell input
    http_method   TEXT,
    url_path      TEXT,
    url_query     TEXT,
    user_agent    TEXT,
    referer       TEXT,
    request_body  TEXT,
    client_version TEXT,              -- SSH client banner

    -- ---- IDS-asserted (Suricata): a rule fired. Trustworthy AS A DETECTION,
    --      but the payload it carries is still attacker-controlled text. ----
    ids_signature    TEXT,            -- human-readable rule name
    ids_category     TEXT,            -- ET classification
    ids_severity     INTEGER,         -- 1=high .. 3=low (Suricata convention)
    ids_signature_id INTEGER,         -- numeric SID, for tuning/suppression

    -- ---- SIEM-asserted (Wazuh): a log-based rule fired. Same trust status as
    --      the IDS tier: the detection is real, the fields it carries are not. ----
    siem_rule_id     TEXT,            -- Wazuh SID (string in the alert JSON)
    siem_level       INTEGER,         -- 0-15, Wazuh's own severity scale
    siem_description TEXT,            -- rendered rule description
    siem_groups      TEXT,            -- JSON array: cowrie, attack, web, ...

    -- ---- provenance ----
    message       TEXT,               -- cowrie's human-readable summary
    raw           TEXT NOT NULL,      -- the original line, verbatim, always
    -- Same event as raw, with oversized/blob fields (Suricata HTTP bodies
    -- etc.) replaced by a preview+hash -- see pipeline/llm_view.py. This is
    -- what the agent tools hand the LLM; raw is untouched and still always
    -- present for forensics. NULL for rows ingested before this column
    -- existed, backfilled by pipeline/backfill_llm_views.py.
    llm_view      TEXT
);

CREATE INDEX IF NOT EXISTS idx_events_ts        ON events(ts);
CREATE INDEX IF NOT EXISTS idx_events_src_ip    ON events(src_ip);
CREATE INDEX IF NOT EXISTS idx_events_type      ON events(event_type);
CREATE INDEX IF NOT EXISTS idx_events_ip_ts     ON events(src_ip, ts);
CREATE INDEX IF NOT EXISTS idx_events_session   ON events(session_id);

-- Tail offsets, so restarting the ingester doesn't re-import the world.
-- Keyed on inode as well as path: when a log rotates, the path is the same but
-- the inode changes, and that's how we notice.
CREATE TABLE IF NOT EXISTS tail_state (
    path      TEXT PRIMARY KEY,
    inode     INTEGER NOT NULL,
    offset    INTEGER NOT NULL,
    updated   TEXT    NOT NULL
);

-- Anything we couldn't parse. Never silently drop telemetry: a gap in a SOC
-- feed is indistinguishable from an attacker who cleaned up after themselves.
CREATE TABLE IF NOT EXISTS parse_failures (
    id      INTEGER PRIMARY KEY AUTOINCREMENT,
    ts      TEXT NOT NULL,
    path    TEXT NOT NULL,
    reason  TEXT NOT NULL,
    line    TEXT NOT NULL
);

-- Northwind range milestone 12 (SPEC.md §10): full LLM transcripts don't
-- fit the single-row events shape above (retrieved_context and tool_calls
-- are nested structures, not flat columns) -- a deliberate, minimal
-- extension of the one-table pattern rather than a lossy flattening.
-- Populated by pipeline/ingest.py's read_new_transcripts(), tailing
-- northwind-range/telemetry/llm-transcripts.log the same way every other
-- source here is tailed.
CREATE TABLE IF NOT EXISTS llm_transcripts (
    id                INTEGER PRIMARY KEY AUTOINCREMENT,
    ts                TEXT NOT NULL,
    source            TEXT NOT NULL,
    session_id        TEXT,
    username          TEXT,
    model             TEXT,
    system_prompt     TEXT,
    user_turn         TEXT,
    retrieved_context TEXT,           -- JSON array
    tool_calls        TEXT,           -- JSON array
    completion        TEXT,
    controls          TEXT,           -- JSON: the control vector active for this call
    raw               TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_llm_transcripts_ts      ON llm_transcripts(ts);
CREATE INDEX IF NOT EXISTS idx_llm_transcripts_session ON llm_transcripts(session_id);
