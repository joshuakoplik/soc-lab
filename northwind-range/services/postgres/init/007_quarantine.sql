-- Defender-invoked quarantine (SOC-lab's northwind_enforcer.py /
-- quarantine_northwind_document triage tool) -- render a document
-- flagged as malicious inert without deleting it, so the row (and its
-- content, for forensics) survives. NULL = not quarantined, the default
-- for every existing and new row. A real timestamp means retrieval-svc's
-- PREFILTER_SQL/POSTFILTER_SQL now exclude it unconditionally, in every
-- retrieval mode -- not a toggle-gated behavior like RET_SOURCE_ALLOWLIST,
-- always enforced once set.
ALTER TABLE app.documents ADD COLUMN quarantined_at TIMESTAMPTZ;
