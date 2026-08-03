-- SPEC.md §13 build order step 8. Deferred from milestone 2 -- see that
-- migration's own comment: "Records... are deferred to milestone 8...
-- milestone 8 adds it alongside the tools that need it."

CREATE TABLE app.customers (
    id         SERIAL PRIMARY KEY,
    tenant_id  INT NOT NULL REFERENCES app.tenants(id),
    name       TEXT NOT NULL,
    email      TEXT NOT NULL,
    phone      TEXT NOT NULL,
    plan       TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE app.tickets (
    id          SERIAL PRIMARY KEY,
    tenant_id   INT NOT NULL REFERENCES app.tenants(id),
    customer_id INT NOT NULL REFERENCES app.customers(id),
    subject     TEXT NOT NULL,
    body        TEXT NOT NULL,
    status      TEXT NOT NULL CHECK (status IN ('open', 'pending', 'closed')),
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
    closed_at   TIMESTAMPTZ
);

CREATE TABLE app.invoices (
    id           SERIAL PRIMARY KEY,
    tenant_id    INT NOT NULL REFERENCES app.tenants(id),
    customer_id  INT NOT NULL REFERENCES app.customers(id),
    amount_cents INT NOT NULL,
    status       TEXT NOT NULL CHECK (status IN ('paid', 'due', 'overdue')),
    issued_at    TIMESTAMPTZ NOT NULL DEFAULT now(),
    due_at       TIMESTAMPTZ NOT NULL
);

CREATE TABLE app.usage_records (
    id          SERIAL PRIMARY KEY,
    tenant_id   INT NOT NULL REFERENCES app.tenants(id),
    customer_id INT NOT NULL REFERENCES app.customers(id),
    period      TEXT NOT NULL,
    metric      TEXT NOT NULL,
    value       NUMERIC NOT NULL
);

-- Generalize the decision log for a second object type (documents were the
-- only one through milestone 5-7). No FK on object_id -- a single column
-- can't reference two different tables, and a polymorphic-association
-- pattern would be over-engineering for exactly two object types.
ALTER TABLE app.policy_decisions RENAME COLUMN object_document_id TO object_id;
ALTER TABLE app.policy_decisions DROP CONSTRAINT policy_decisions_object_document_id_fkey;
ALTER TABLE app.policy_decisions ADD COLUMN object_type TEXT NOT NULL DEFAULT 'document';
ALTER TABLE app.policy_decisions ALTER COLUMN object_type DROP DEFAULT;
