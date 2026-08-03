"""Single source of truth for entitlement decisions (SPEC.md §7).

Imported directly by portal-api (milestone 5) and, later, retrieval-svc and
tool-svc (milestones 6/8) -- "a single policy module... not duplicated
logic." Every call is logged to app.policy_decisions (subject, object,
action, decision, reason), independent of whatever the caller does with
the answer.

Decision algorithm (SPEC.md doesn't specify one explicitly -- this is the
rule this codebase settled on, documented here since it's load-bearing):

1. Cross-tenant -> deny, no exceptions (SPEC.md §6.1: "No document or
   record crosses tenants").
2. label == 'public' -> allow, regardless of department.
3. Otherwise: allow if the user's home department matches the document's
   owning department, OR the user holds a currently-active grant for that
   department, OR the document is explicitly shared with that department.
   Deny otherwise. All four labels share this same rule -- 'restricted'
   isn't specially gated beyond it; that distinction belongs to the
   control-matrix toggles (SPEC.md §5.2), not a second access-control axis.
"""
import os
from dataclasses import dataclass

import psycopg2

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
                return _log(conn, user_id, document_id, action, False, "cross-tenant")

            if label == "public":
                return _log(conn, user_id, document_id, action, True, "public")

            if user_department_id == owning_department_id:
                return _log(conn, user_id, document_id, action, True, "same-department")

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
                return _log(conn, user_id, document_id, action, True, "active-grant")

            # user_department_id, not owning_department_id -- a share row
            # names the department being granted access, which is never the
            # document's own owning department (that'd be a no-op share).
            cur.execute(
                "SELECT 1 FROM app.document_shares WHERE document_id = %s AND department_id = %s",
                (document_id, user_department_id),
            )
            if cur.fetchone() is not None:
                return _log(conn, user_id, document_id, action, True, "explicit-share")

            return _log(conn, user_id, document_id, action, False, "no-entitlement")
    finally:
        if own_conn:
            conn.close()


def _log(conn, user_id: int, document_id: int, action: str, allowed: bool, reason: str) -> Decision:
    with conn.cursor() as cur:
        cur.execute(
            """
            INSERT INTO app.policy_decisions
                (subject_user_id, object_document_id, action, decision, reason)
            VALUES (%s, %s, %s, %s, %s)
            """,
            (user_id, document_id, action, allowed, reason),
        )
    conn.commit()
    return Decision(allowed=allowed, reason=reason)
