"""retrieval-svc: pre-filter and post-filter semantic search (SPEC.md §6.2,
milestone 6).

prefilter puts the ACL predicate inside the vector query itself -- a
third, independent expression of the same rule as policy/policy.py and
verify-entitlements.sh's reimplementation (necessarily so: pre-filter's
whole point is excluding forbidden rows *inside* the query, which can't be
done by calling the Python function per candidate without defeating the
purpose). Keep this predicate in sync with policy.decide() by hand;
scripts/verify-retrieval.sh tests its output against policy.decide() on
real data rather than trusting they match by construction.

postfilter deliberately has NO predicate at all -- not even a tenant
scope. That's the honest shape of what SPEC.md §6.2 describes ("retrieve
top-k, then drop what the user cannot see"): the candidate pool is
whatever ranks highest across the *entire* corpus, filtered only after
the fact via the real policy.decide() check. Scoping postfilter's SQL to
the caller's own tenant would understate the leak this mode exists to
demonstrate.
"""
import os

import psycopg2
import psycopg2.extras
from fastapi import FastAPI, HTTPException
from pgvector.psycopg2 import register_vector
from pydantic import BaseModel

from embeddings import as_vector_literal, embed
from policy import policy

DATABASE_URL = os.environ.get(
    "DATABASE_URL", "postgresql://northwind:northwind-placeholder@postgres:5432/northwind"
)

app = FastAPI()

PREFILTER_SQL = """
    SELECT d.id, d.title, d.content, d.tenant_id, d.owning_department_id, d.label,
           1 - (d.embedding <=> %(qvec)s::vector) AS score
    FROM app.documents d
    WHERE d.tenant_id = %(tenant_id)s
      AND (
        d.label = 'public'
        OR d.owning_department_id = %(department_id)s
        OR EXISTS (
            SELECT 1 FROM app.grants g
            WHERE g.user_id = %(user_id)s AND g.department_id = d.owning_department_id
              AND g.revoked_at IS NULL AND (g.expires_at IS NULL OR g.expires_at > now())
        )
        OR EXISTS (
            SELECT 1 FROM app.document_shares s
            WHERE s.document_id = d.id AND s.department_id = %(department_id)s
        )
      )
    ORDER BY d.embedding <=> %(qvec)s::vector
    LIMIT %(k)s
"""

POSTFILTER_SQL = """
    SELECT d.id, d.title, d.content, d.tenant_id, d.owning_department_id, d.label,
           1 - (d.embedding <=> %(qvec)s::vector) AS score
    FROM app.documents d
    ORDER BY d.embedding <=> %(qvec)s::vector
    LIMIT %(k)s
"""


def db():
    conn = psycopg2.connect(DATABASE_URL)
    register_vector(conn)
    with conn.cursor() as cur:
        # HNSW ORDER BY + LIMIT + a selective WHERE filter (the ACL
        # predicate) is a real, confirmed pgvector gotcha, not a
        # hypothetical: the index scan only examines hnsw.ef_search
        # candidates *before* the filter is applied, and at the default
        # value it can return fewer rows than requested -- or zero -- even
        # when plenty of entitled documents exist further down the actual
        # ranking. At this corpus's size (~180 rows), a value comfortably
        # above the row count makes the search exhaustive, trading a
        # little speed for correctness that matters a lot more here.
        cur.execute("SET hnsw.ef_search = 200")
    return conn


class SearchRequest(BaseModel):
    user_id: int
    query: str
    k: int = 5
    mode: str = "prefilter"


@app.get("/health")
def health():
    return {"status": "ok"}


@app.post("/search")
def search(body: SearchRequest):
    if body.mode not in ("prefilter", "postfilter"):
        raise HTTPException(status_code=400, detail="mode must be 'prefilter' or 'postfilter'")

    qvec = as_vector_literal(embed(body.query))
    conn = db()
    try:
        with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
            cur.execute("SELECT tenant_id, department_id FROM app.users WHERE id = %s", (body.user_id,))
            user_row = cur.fetchone()
            if not user_row:
                raise HTTPException(status_code=404, detail="unknown user")

            if body.mode == "prefilter":
                cur.execute(
                    PREFILTER_SQL,
                    {
                        "qvec": qvec,
                        "tenant_id": user_row["tenant_id"],
                        "department_id": user_row["department_id"],
                        "user_id": body.user_id,
                        "k": body.k,
                    },
                )
                rows = cur.fetchall()
                # Prefilter's SQL predicate already excluded forbidden rows --
                # this call is a cross-check logged to the same decision log
                # everything else writes to, not a second filtering pass.
                for row in rows:
                    policy.decide(body.user_id, row["id"], "read", conn=conn)
                results = rows
            else:
                cur.execute(POSTFILTER_SQL, {"qvec": qvec, "k": body.k})
                candidates = cur.fetchall()
                results = []
                for row in candidates:
                    decision = policy.decide(body.user_id, row["id"], "read", conn=conn)
                    if decision.allowed:
                        results.append(row)
    finally:
        conn.close()

    return {
        "mode": body.mode,
        "count": len(results),
        "results": [
            {
                "document_id": r["id"],
                "title": r["title"],
                "content": r["content"],
                "label": r["label"],
                "score": float(r["score"]),
            }
            for r in results
        ],
    }
