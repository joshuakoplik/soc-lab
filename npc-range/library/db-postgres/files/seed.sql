-- Shallow but plausible application schema. Enough that a SELECT returns rows
-- and a curious attacker finds something that looks like a real app DB.
CREATE TABLE IF NOT EXISTS employees (
    id          SERIAL PRIMARY KEY,
    full_name   TEXT NOT NULL,
    email       TEXT NOT NULL,
    department  TEXT,
    title       TEXT,
    hired_on    DATE
);

INSERT INTO employees (full_name, email, department, title, hired_on) VALUES
    ('Dana Ellsworth', 'dana.ellsworth@corp.internal', 'Finance', 'Controller', '2019-03-11'),
    ('Marcus Vint',    'marcus.vint@corp.internal',    'Engineering', 'Staff Engineer', '2021-07-02'),
    ('Priya Ramanan',  'priya.ramanan@corp.internal',  'HR', 'People Partner', '2020-01-20'),
    ('Owen Bradley',   'owen.bradley@corp.internal',   'Sales', 'Account Executive', '2022-11-14'),
    ('Sofia Marchetti','sofia.marchetti@corp.internal','IT', 'Systems Administrator', '2018-05-30');

CREATE TABLE IF NOT EXISTS invoices (
    id          SERIAL PRIMARY KEY,
    customer    TEXT NOT NULL,
    amount_cents BIGINT NOT NULL,
    status      TEXT DEFAULT 'open',
    issued_on   DATE DEFAULT CURRENT_DATE
);

INSERT INTO invoices (customer, amount_cents, status) VALUES
    ('Northwind Traders', 1849900, 'paid'),
    ('Contoso Ltd',        992500, 'open'),
    ('Fabrikam Inc',      3120000, 'open');

-- A config table an app would legitimately read at startup. Any planted flag is
-- injected here as an extra row by npcctl (kind: pg_row) -- not committed.
CREATE TABLE IF NOT EXISTS config_secrets (
    key    TEXT PRIMARY KEY,
    value  TEXT NOT NULL
);

INSERT INTO config_secrets (key, value) VALUES
    ('smtp_relay', 'mail-01.corp.internal:25'),
    ('session_ttl_minutes', '30');

-- A read-only-ish app role, so the traffic generator can authenticate.
DO $$
BEGIN
    IF NOT EXISTS (SELECT FROM pg_roles WHERE rolname = 'reporting') THEN
        CREATE ROLE reporting LOGIN PASSWORD 'r3port-only';
        GRANT CONNECT ON DATABASE appdb TO reporting;
        GRANT SELECT ON ALL TABLES IN SCHEMA public TO reporting;
    END IF;
END $$;
