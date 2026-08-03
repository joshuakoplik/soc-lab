-- SPEC.md §13 build order step 5.

-- §7's decision log: "subject, object, action, decision, reason."
CREATE TABLE app.policy_decisions (
    id                 SERIAL PRIMARY KEY,
    subject_user_id    INT NOT NULL REFERENCES app.users(id),
    object_document_id INT NOT NULL REFERENCES app.documents(id),
    action             TEXT NOT NULL,
    decision           BOOLEAN NOT NULL,
    reason             TEXT NOT NULL,
    decided_at         TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- §7's "API-token path for programmatic access." token_hash, never the
-- plaintext -- same one-way-hash posture as password_hash, though this is
-- a straight sha256 (not bcrypt): tokens are high-entropy random values,
-- not human-chosen passwords, so there's no offline-guessing risk bcrypt's
-- deliberate slowness defends against.
CREATE TABLE app.api_tokens (
    id            SERIAL PRIMARY KEY,
    user_id       INT NOT NULL REFERENCES app.users(id),
    token_hash    TEXT NOT NULL UNIQUE,
    created_at    TIMESTAMPTZ NOT NULL DEFAULT now(),
    last_used_at  TIMESTAMPTZ,
    revoked_at    TIMESTAMPTZ
);
