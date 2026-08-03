-- SPEC.md §13 milestone 9: ingest-svc's three sources (§6.3) and the
-- provenance requirement §10 calls for on every ingested chunk.
ALTER TABLE app.documents ADD COLUMN submitter TEXT;

-- Append-only: one row per successful ingestion, never mutated. Doubles as
-- the dedup mechanism for the two polled sources (ticket_feed, drive_sync)
-- via (source, source_ref) -- see ingest-svc/app.py. document_id is
-- NOT NULL because a row here only ever gets written once the document
-- actually exists; there is no "skipped" status to represent.
CREATE TABLE app.ingest_events (
    id            SERIAL PRIMARY KEY,
    source        TEXT NOT NULL CHECK (source IN ('feedback_form','ticket_feed','drive_sync')),
    source_ref    TEXT,
    submitter     TEXT,
    content_hash  TEXT NOT NULL,
    tenant_id     INT NOT NULL REFERENCES app.tenants(id),
    document_id   INT NOT NULL REFERENCES app.documents(id),
    created_at    TIMESTAMPTZ NOT NULL DEFAULT now()
);
