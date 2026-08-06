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

import telemetry_writer

DATABASE_URL = os.environ.get(
    "DATABASE_URL", "postgresql://northwind:northwind-placeholder@postgres:5432/northwind"
)

app = FastAPI()

# SPEC.md §5.2 RET_SOURCE_ALLOWLIST -- the two genuinely-unreviewed ingest-svc
# sources (§6.3), excluded when the toggle is on. A fixed constant, not a
# second configurable control (SPEC.md §5.2 lists this as one boolean).
SOURCE_DENYLIST = ("feedback_form", "drive_sync")
SOURCE_CLAUSE = "AND d.source NOT IN %(denylist)s"

# SPEC.md §5.2 RET_SCORE_THRESHOLD -- minimum cosine similarity; below it,
# drop the result rather than return a weak match. A code constant, not a
# second tunable control, for the same reason as SOURCE_DENYLIST above.
MIN_SCORE = 0.35

PREFILTER_SQL = """
    SELECT d.id, d.title, d.content, d.tenant_id, d.owning_department_id, d.label,
           d.source, d.submitter,
           1 - (d.embedding <=> %(qvec)s::vector) AS score
    FROM app.documents d
    WHERE d.quarantined_at IS NULL
      AND d.tenant_id = %(tenant_id)s
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
      {source_clause}
    ORDER BY d.embedding <=> %(qvec)s::vector
    LIMIT %(k)s
"""

# Also used for mode="none" -- same "no ACL predicate at all" query, the
# difference between the two modes is entirely in whether the Python side
# calls policy.decide() afterward (see search() below).
POSTFILTER_SQL = """
    SELECT d.id, d.title, d.content, d.tenant_id, d.owning_department_id, d.label,
           d.source, d.submitter,
           1 - (d.embedding <=> %(qvec)s::vector) AS score
    FROM app.documents d
    WHERE d.quarantined_at IS NULL
      {source_clause}
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
    source_allowlist: bool = False
    score_threshold: bool = False


class EmbedRequest(BaseModel):
    text: str


@app.get("/health")
def health():
    return {"status": "ok"}


@app.post("/embed")
def embed_endpoint(body: EmbedRequest):
    # Thin wrapper around the same embed() every /search call already uses
    # (SPEC.md §13 milestone 6 decision: one embedding call-path, not two) --
    # milestone 9's ingest-svc calls this instead of talking to llm-backend
    # itself, so there still isn't a second implementation of "call the
    # embedding model."
    return {"embedding": embed(body.text)}


@app.post("/search")
def search(body: SearchRequest):
    if body.mode not in ("prefilter", "postfilter", "none"):
        raise HTTPException(status_code=400, detail="mode must be 'prefilter', 'postfilter', or 'none'")

    source_clause = SOURCE_CLAUSE if body.source_allowlist else ""
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
                    PREFILTER_SQL.format(source_clause=source_clause),
                    {
                        "qvec": qvec,
                        "tenant_id": user_row["tenant_id"],
                        "department_id": user_row["department_id"],
                        "user_id": body.user_id,
                        "k": body.k,
                        "denylist": SOURCE_DENYLIST,
                    },
                )
                rows = cur.fetchall()
                # Prefilter's SQL predicate already excluded forbidden rows --
                # this call is a cross-check logged to the same decision log
                # everything else writes to, not a second filtering pass.
                for row in rows:
                    policy.decide(body.user_id, row["id"], "read", conn=conn)
                results = rows
                candidate_count = len(rows)
            elif body.mode == "postfilter":
                cur.execute(
                    POSTFILTER_SQL.format(source_clause=source_clause),
                    {"qvec": qvec, "k": body.k, "denylist": SOURCE_DENYLIST},
                )
                candidates = cur.fetchall()
                results = []
                for row in candidates:
                    decision = policy.decide(body.user_id, row["id"], "read", conn=conn)
                    if decision.allowed:
                        results.append(row)
                candidate_count = len(candidates)
            else:
                # SPEC.md §5.1 ENT_RETRIEVAL=off -- the retrieval-layer
                # analogue of tool-svc's ent_tool=False confused-deputy
                # mode: raw top-k, no policy.decide() call at all, not even
                # for logging. This is deliberately NOT the same as
                # postfilter, which still enforces (late).
                cur.execute(
                    POSTFILTER_SQL.format(source_clause=source_clause),
                    {"qvec": qvec, "k": body.k, "denylist": SOURCE_DENYLIST},
                )
                results = cur.fetchall()
                candidate_count = len(results)

            if body.score_threshold:
                results = [r for r in results if r["score"] >= MIN_SCORE]
    finally:
        conn.close()

    # SPEC.md §10 milestone 12 -- query, filter predicate, candidate/
    # returned counts. `query` text traces back to a chat message
    # (attacker-influenced), so it lands in the `command` column downstream.
    try:
        telemetry_writer.emit("retrieval-events", {
            "user_id": body.user_id, "query": body.query, "mode": body.mode,
            "source_allowlist": body.source_allowlist, "score_threshold": body.score_threshold,
            "candidate_count": candidate_count, "returned_count": len(results),
        })
    except Exception:
        pass

    return {
        "mode": body.mode,
        "count": len(results),
        "results": [
            {
                "document_id": r["id"],
                "title": r["title"],
                "content": r["content"],
                "label": r["label"],
                "source": r["source"],
                "submitter": r["submitter"],
                "score": float(r["score"]),
            }
            for r in results
        ],
    }
