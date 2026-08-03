"""Single source of truth for entitlement decisions (SPEC.md §7).

Imported directly by portal-api (milestone 5), retrieval-svc (milestone 6),
and tool-svc (milestone 8) -- "a single policy module... not duplicated
logic." Every call is logged to app.policy_decisions (subject, object type
+ id, action, decision, reason), independent of whatever the caller does
with the answer.

Two decision functions, not one generic dispatcher -- documents and
records don't share a shape (labels/departments/grants/shares vs. plain
tenant ownership), so forcing both through one signature would mean fake
fields on one side or the other:

decide() -- documents. Decision algorithm (SPEC.md doesn't specify one
explicitly -- this is the rule this codebase settled on, documented here
since it's load-bearing):

1. Cross-tenant -> deny, no exceptions (SPEC.md §6.1: "No document or
   record crosses tenants").
2. label == 'public' -> allow, regardless of department.
3. Otherwise: allow if the user's home department matches the document's
   owning department, OR the user holds a currently-active grant for that
   department, OR the document is explicitly shared with that department.
   Deny otherwise. All four labels share this same rule -- 'restricted'
   isn't specially gated beyond it; that distinction belongs to the
   control-matrix toggles (SPEC.md §5.2), not a second access-control axis.

decide_record() -- customers/tickets/invoices (SPEC.md §8, milestone 8).
Tenant-only: no department-ownership axis for customer records the way
documents have one (the scenario has both support *and* operations staff
plausibly needing customer lookups). This is what makes tool-svc's
ENT_TOOL toggle sharp -- with it on, decide_record() is the enforcement;
with it off, tool-svc skips calling it entirely (the "service credential"
confused-deputy mode SPEC.md §8 describes).
"""
import os
from dataclasses import dataclass

import psycopg2

import telemetry_writer

DATABASE_URL = os.environ.get(
    "DATABASE_URL", "postgresql://northwind:northwind-placeholder@postgres:5432/northwind"
)


@dataclass
class Decision:
    allowed: bool
    reason: str


def _connect():
    return psycopg2.connect(DATABASE_URL)


def decide(user_id: int, document_id: int, action: str = "read", conn=None) -> Decision:
    own_conn = conn is None
    conn = conn or _connect()
    try:
        with conn.cursor() as cur:
            cur.execute(
                "SELECT tenant_id, department_id FROM app.users WHERE id = %s", (user_id,)
            )
            user_row = cur.fetchone()
            if user_row is None:
                # Nothing valid to log a decision_log row against (subject_user_id
                # is a real FK) -- just deny.
                return Decision(allowed=False, reason="unknown-user")
            user_tenant_id, user_department_id = user_row

            cur.execute(
                "SELECT tenant_id, label, owning_department_id FROM app.documents WHERE id = %s",
                (document_id,),
            )
            doc_row = cur.fetchone()
            if doc_row is None:
                return Decision(allowed=False, reason="unknown-document")
            doc_tenant_id, label, owning_department_id = doc_row

            if user_tenant_id != doc_tenant_id:
                return _log(conn, user_id, "document", document_id, action, False, "cross-tenant")

            if label == "public":
                return _log(conn, user_id, "document", document_id, action, True, "public")

            if user_department_id == owning_department_id:
                return _log(conn, user_id, "document", document_id, action, True, "same-department")

            cur.execute(
                """
                SELECT 1 FROM app.grants
                WHERE user_id = %s AND department_id = %s
                  AND revoked_at IS NULL
                  AND (expires_at IS NULL OR expires_at > now())
                """,
                (user_id, owning_department_id),
            )
            if cur.fetchone() is not None:
                return _log(conn, user_id, "document", document_id, action, True, "active-grant")

            # user_department_id, not owning_department_id -- a share row
            # names the department being granted access, which is never the
            # document's own owning department (that'd be a no-op share).
            cur.execute(
                "SELECT 1 FROM app.document_shares WHERE document_id = %s AND department_id = %s",
                (document_id, user_department_id),
            )
            if cur.fetchone() is not None:
                return _log(conn, user_id, "document", document_id, action, True, "explicit-share")

            return _log(conn, user_id, "document", document_id, action, False, "no-entitlement")
    finally:
        if own_conn:
            conn.close()


# SPEC.md §8: customer records/tickets/invoices have no department-ownership
# axis the way documents do (the scenario has both support *and* operations
# staff plausibly needing customer lookups) -- the rule here is tenant-only.
RECORD_TABLES = ("customers", "tickets", "invoices")


def decide_record(user_id: int, table: str, record_id: int, action: str = "read", conn=None) -> Decision:
    if table not in RECORD_TABLES:
        raise ValueError(f"unknown record table: {table!r}")

    own_conn = conn is None
    conn = conn or _connect()
    try:
        with conn.cursor() as cur:
            cur.execute("SELECT tenant_id FROM app.users WHERE id = %s", (user_id,))
            user_row = cur.fetchone()
            if user_row is None:
                return Decision(allowed=False, reason="unknown-user")
            (user_tenant_id,) = user_row

            # table is allow-listed above, not string-interpolated from caller input.
            cur.execute(f"SELECT tenant_id FROM app.{table} WHERE id = %s", (record_id,))
            record_row = cur.fetchone()
            if record_row is None:
                return Decision(allowed=False, reason=f"unknown-{table[:-1]}")
            (record_tenant_id,) = record_row

            if user_tenant_id != record_tenant_id:
                return _log(conn, user_id, table, record_id, action, False, "cross-tenant")
            return _log(conn, user_id, table, record_id, action, True, "same-tenant")
    finally:
        if own_conn:
            conn.close()


def _log(conn, user_id: int, object_type: str, object_id: int, action: str, allowed: bool, reason: str) -> Decision:
    with conn.cursor() as cur:
        cur.execute(
            """
            INSERT INTO app.policy_decisions
                (subject_user_id, object_type, object_id, action, decision, reason)
            VALUES (%s, %s, %s, %s, %s, %s)
            """,
            (user_id, object_type, object_id, action, allowed, reason),
        )
    conn.commit()
    # SPEC.md §7/§10 milestone 12 -- every caller (portal-api, retrieval-svc,
    # tool-svc, harness's scoring) ships its decisions automatically, no
    # per-caller wiring. Best-effort: telemetry_writer.emit() never raises.
    try:
        telemetry_writer.emit("policy-decisions", {
            "user_id": user_id, "object_type": object_type, "object_id": object_id,
            "action": action, "decision": allowed, "reason": reason,
        })
    except Exception:
        pass
    return Decision(allowed=allowed, reason=reason)
