-- SPEC.md §13 build order step 2. app.documents.embedding is intentionally
-- absent -- pgvector's vector(N) needs a fixed dimension, and no embedding
-- model is chosen until milestone 6 (retrieval-svc). This migration only
-- proves the extension itself is installed and usable.
CREATE EXTENSION IF NOT EXISTS vector;
CREATE EXTENSION IF NOT EXISTS pgcrypto;

CREATE SCHEMA IF NOT EXISTS app;

CREATE TABLE app.tenants (
    id   SERIAL PRIMARY KEY,
    slug TEXT UNIQUE NOT NULL,
    name TEXT NOT NULL
);

-- Serves two roles per SPEC.md §6.1: a user's "role" and a document's
-- "owning department" are the same five organizational units in this
-- scenario, so one lookup table covers both rather than two parallel
-- five-row tables for the same concept.
CREATE TABLE app.departments (
    id   SERIAL PRIMARY KEY,
    name TEXT UNIQUE NOT NULL
);

CREATE TABLE app.users (
    id            SERIAL PRIMARY KEY,
    tenant_id     INT NOT NULL REFERENCES app.tenants(id),
    department_id INT NOT NULL REFERENCES app.departments(id),
    username      TEXT NOT NULL,
    password_hash TEXT NOT NULL,
    display_name  TEXT NOT NULL,
    is_active     BOOLEAN NOT NULL DEFAULT true,
    created_at    TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (tenant_id, username)
);

-- A cross-department grant on top of a user's home department. "Active" is
-- computed, not stored: revoked_at IS NULL AND (expires_at IS NULL OR
-- expires_at > now()).
CREATE TABLE app.grants (
    id            SERIAL PRIMARY KEY,
    user_id       INT NOT NULL REFERENCES app.users(id),
    department_id INT NOT NULL REFERENCES app.departments(id),
    granted_at    TIMESTAMPTZ NOT NULL DEFAULT now(),
    expires_at    TIMESTAMPTZ,
    revoked_at    TIMESTAMPTZ
);

-- Rows land here in milestone 3 (corpus generation) -- schema only for now.
CREATE TABLE app.documents (
    id                    SERIAL PRIMARY KEY,
    tenant_id             INT NOT NULL REFERENCES app.tenants(id),
    label                 TEXT NOT NULL CHECK (label IN ('public', 'internal', 'confidential', 'restricted')),
    owning_department_id  INT NOT NULL REFERENCES app.departments(id),
    title                 TEXT NOT NULL,
    source                TEXT,
    content               TEXT,
    created_at            TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE app.document_shares (
    document_id   INT NOT NULL REFERENCES app.documents(id),
    department_id INT NOT NULL REFERENCES app.departments(id),
    PRIMARY KEY (document_id, department_id)
);
