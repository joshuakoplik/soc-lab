#!/usr/bin/env python3
"""Load fake customer/ticket/invoice/usage data (SPEC.md §13 milestone 8).

Unlike the real document corpus (expensive LLM prose, worth committing and
versioning), this is simple structured fake data -- generated fresh on
every `make reset` from a deterministic Random(.seed) rather than needing
a separate generate/commit/load pipeline. Same .seed-driven reproducibility
convention scripts/seed_entitlements.py already established.
"""
import random
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
SEED_FILE = ROOT / ".seed"

TENANTS = ["riverside", "bluepeak", "fenwick"]
PLANS = ["starter", "pro", "enterprise"]

FIRST_NAMES = [
    "Jordan", "Casey", "Morgan", "Taylor", "Riley", "Avery", "Quinn", "Dakota",
    "Reese", "Skyler", "Hayden", "Rowan", "Emerson", "Finley", "Kendall", "Peyton",
    "Sawyer", "Blake",
]
LAST_NAMES = [
    "Whitfield", "Marsh", "Delgado", "Ibsen", "Prescott", "Castellanos", "Overby",
    "Tran", "Kowalski", "Ashworth", "Baptiste", "Simmons", "Reyes", "Nakamura",
    "Ferreira", "Novak", "Okoro", "Lindqvist",
]

TICKET_SUBJECTS = [
    ("Billing question about last invoice", "Customer noticed a discrepancy on their most recent invoice and wants a line-item breakdown."),
    ("API rate limit increase request", "Customer is hitting rate limits during peak hours and would like a higher tier applied."),
    ("Login issues after password reset", "Customer reset their password but is still getting an invalid-credentials error."),
    ("Feature request: bulk export", "Customer would like the ability to export their full account history as a CSV."),
    ("Integration webhook failing intermittently", "Customer's webhook endpoint is receiving duplicate and occasionally malformed payloads."),
    ("Account upgrade inquiry", "Customer wants to know what changes when moving from their current plan to the next tier up."),
    ("Data export request", "Customer is requesting a full export of their account data ahead of an internal audit."),
    ("Unexpected downtime report", "Customer reported a short outage window and is asking for a root-cause summary."),
]

USAGE_METRICS = ["api_calls", "storage_gb"]
USAGE_PERIODS = ["2026-05", "2026-06", "2026-07"]


def get_seed() -> str:
    if not SEED_FILE.exists():
        sys.exit("seed_records: .seed missing -- run 'make seed' first")
    return SEED_FILE.read_text().strip()


def sql_str(value) -> str:
    return "'" + str(value).replace("'", "''") + "'"


def main() -> None:
    seed = get_seed()
    rng = random.Random(seed)

    statements = [
        "BEGIN;",
        "TRUNCATE app.usage_records, app.invoices, app.tickets, app.customers RESTART IDENTITY CASCADE;",
    ]

    for tenant in TENANTS:
        for _ in range(6):
            first = rng.choice(FIRST_NAMES)
            last = rng.choice(LAST_NAMES)
            name = f"{first} {last}"
            email = f"{first.lower()}.{last.lower()}@{tenant}-customer.example"
            phone = f"+1-555-{rng.randint(200, 999)}-{rng.randint(1000, 9999)}"
            plan = rng.choice(PLANS)

            ticket_rows = []
            for _ in range(rng.randint(2, 4)):
                subject, body = rng.choice(TICKET_SUBJECTS)
                status = rng.choices(["open", "pending", "closed"], weights=[2, 1, 3])[0]
                closed_at = "now()" if status == "closed" else "NULL::timestamptz"
                ticket_rows.append(
                    f"({sql_str(subject)}, {sql_str(body)}, {sql_str(status)}, {closed_at})"
                )

            invoice_rows = []
            for _ in range(rng.randint(1, 3)):
                amount = rng.randint(5000, 500000)
                status = rng.choices(["paid", "due", "overdue"], weights=[5, 2, 1])[0]
                invoice_rows.append(
                    f"({amount}, {sql_str(status)}, now(), now() + interval '30 days')"
                )

            usage_rows = []
            for metric in USAGE_METRICS:
                base = rng.randint(1000, 50000) if metric == "api_calls" else rng.randint(5, 500)
                for period in USAGE_PERIODS:
                    value = max(0, base + rng.randint(-base // 4, base // 4))
                    usage_rows.append(f"({sql_str(period)}, {sql_str(metric)}, {value})")

            statements.append(f"""
WITH cust AS (
    INSERT INTO app.customers (tenant_id, name, email, phone, plan)
    SELECT t.id, {sql_str(name)}, {sql_str(email)}, {sql_str(phone)}, {sql_str(plan)}
    FROM app.tenants t WHERE t.slug = {sql_str(tenant)}
    RETURNING id, tenant_id
),
ins_tickets AS (
    INSERT INTO app.tickets (tenant_id, customer_id, subject, body, status, closed_at)
    SELECT cust.tenant_id, cust.id, v.subject, v.body, v.status, v.closed_at
    FROM cust, (VALUES {", ".join(ticket_rows)}) AS v(subject, body, status, closed_at)
),
ins_invoices AS (
    INSERT INTO app.invoices (tenant_id, customer_id, amount_cents, status, issued_at, due_at)
    SELECT cust.tenant_id, cust.id, v.amount_cents, v.status, v.issued_at, v.due_at
    FROM cust, (VALUES {", ".join(invoice_rows)}) AS v(amount_cents, status, issued_at, due_at)
)
INSERT INTO app.usage_records (tenant_id, customer_id, period, metric, value)
SELECT cust.tenant_id, cust.id, v.period, v.metric, v.value
FROM cust, (VALUES {", ".join(usage_rows)}) AS v(period, metric, value);
""")

    statements.append("COMMIT;")
    sql = "\n".join(statements)

    result = subprocess.run(
        ["docker", "compose", "exec", "-T", "postgres", "psql", "-v", "ON_ERROR_STOP=1",
         "-U", "northwind", "-d", "northwind"],
        input=sql, capture_output=True, text=True, cwd=str(ROOT),
    )
    if result.returncode != 0:
        sys.exit(f"seed_records: psql failed:\n{result.stdout}\n{result.stderr}")

    print("Seeded 18 customers with tickets, invoices, and usage records.")


if __name__ == "__main__":
    main()
