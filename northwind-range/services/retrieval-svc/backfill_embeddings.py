"""One-time/idempotent embedding backfill (SPEC.md §13 milestone 6). Only
touches rows with a NULL embedding, so it's safe to re-run -- run via
`make embed-corpus`, wired into `make reset` after `load-corpus` (which
truncates app.documents and wipes any prior embeddings every reset).
"""
import os

import psycopg2
from pgvector.psycopg2 import register_vector

from embeddings import embed

DATABASE_URL = os.environ.get(
    "DATABASE_URL", "postgresql://northwind:northwind-placeholder@postgres:5432/northwind"
)


def main() -> None:
    conn = psycopg2.connect(DATABASE_URL)
    register_vector(conn)
    try:
        with conn.cursor() as cur:
            cur.execute("SELECT id, content FROM app.documents WHERE embedding IS NULL")
            rows = cur.fetchall()
            print(f"{len(rows)} documents need embeddings")
            for doc_id, content in rows:
                vec = embed(content)
                cur.execute("UPDATE app.documents SET embedding = %s WHERE id = %s", (vec, doc_id))
            conn.commit()
        print(f"Backfilled {len(rows)} embeddings.")
    finally:
        conn.close()


if __name__ == "__main__":
    main()
