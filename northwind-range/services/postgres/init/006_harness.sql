-- SPEC.md §13 milestone 11: the harness's own results schema, deliberately
-- a separate `harness` schema from `app` -- `app.*` gets wiped by `make
-- reset`'s `docker compose down -v` (the developer/cold-start command),
-- but harness.* must survive across runs for cross-run comparison and
-- resumability (SPEC.md §9.1). Between-attempt state cleanup is a
-- targeted DELETE the runner issues itself (see harness/runner.py's
-- reset_app_state()), not a volume wipe.
CREATE SCHEMA IF NOT EXISTS harness;

CREATE TABLE harness.corpus_items (
    id         SERIAL PRIMARY KEY,
    kind       TEXT NOT NULL CHECK (kind IN ('attack', 'benign')),
    category   TEXT,                    -- one of SPEC.md §9.2's 8 categories, NULL for benign
    item_key   TEXT NOT NULL,            -- stable id from the source YAML filename/id field
    definition JSONB NOT NULL,           -- full parsed item (actor/setup/steps/target/expected)
    UNIQUE (kind, item_key)
);

CREATE TABLE harness.runs (
    id              SERIAL PRIMARY KEY,
    model           TEXT NOT NULL,
    controls_name   TEXT NOT NULL,
    controls        JSONB NOT NULL,
    corpus_version  TEXT NOT NULL,
    harness_version TEXT NOT NULL,
    started_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    finished_at     TIMESTAMPTZ
);

CREATE TABLE harness.results (
    id              SERIAL PRIMARY KEY,
    run_id          INT NOT NULL REFERENCES harness.runs(id),
    corpus_item_id  INT NOT NULL REFERENCES harness.corpus_items(id),
    attempted_at    TIMESTAMPTZ NOT NULL DEFAULT now(),
    requested       JSONB NOT NULL,
    policy_expected JSONB,
    retrieved       JSONB,
    emitted         TEXT,
    leaked          BOOLEAN NOT NULL,
    refused         BOOLEAN NOT NULL,
    over_refusal    BOOLEAN NOT NULL,
    latency_ms      INT,
    raw_response    JSONB,
    UNIQUE (run_id, corpus_item_id)
);
