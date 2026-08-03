"""ingest-svc: the three SPEC.md §6.3 ingestion sources (milestone 9) --
feedback form (public, unauthenticated), ticket feed (closed support
tickets, polled), drive sync (a watched directory, polled). None of the
three get a human-reviewed label or department: that's the deliberate
point of this milestone, not an oversight -- see §6.3's "There must be
paths where content enters the index without human review." Every
ingestion, successful or not, is decided by _ingest(), the one place that
hashes content, calls retrieval-svc for an embedding, and writes both
app.documents and app.ingest_events -- so there's exactly one "hash, embed,
insert" implementation shared by all three sources.

Tenant is the one piece of provenance this service never trusts from
inside the content itself: feedback callers name a tenant slug directly,
ticket rows already carry a real tenant_id, and drive-sync's tenant comes
from which subdirectory of the watched tree a file was dropped into --
never from anything the file itself says.
"""
import hashlib
import json
import os
import sys
import threading
import time
import urllib.request
from datetime import datetime, timezone
from pathlib import Path

import psycopg2
import psycopg2.extras
from fastapi import FastAPI, HTTPException
from pgvector.psycopg2 import register_vector
from pydantic import BaseModel

DATABASE_URL = os.environ.get(
    "DATABASE_URL", "postgresql://northwind:northwind-placeholder@postgres:5432/northwind"
)
RETRIEVAL_SVC_URL = os.environ.get("RETRIEVAL_SVC_URL", "http://retrieval-svc:8000")
WATCHED_DIR = Path(os.environ.get("WATCHED_DIR", "/app/watched"))
POLL_INTERVAL_SECONDS = int(os.environ.get("INGEST_POLL_INTERVAL_SECONDS", "20"))

app = FastAPI()


def db():
    conn = psycopg2.connect(DATABASE_URL)
    register_vector(conn)
    return conn


def content_hash(text: str) -> str:
    return hashlib.sha256(text.encode()).hexdigest()


def get_embedding(text: str) -> list[float]:
    req = urllib.request.Request(
        f"{RETRIEVAL_SVC_URL}/embed",
        data=json.dumps({"text": text}).encode(),
        headers={"Content-Type": "application/json"},
    )
    with urllib.request.urlopen(req, timeout=60) as resp:
        return json.loads(resp.read())["embedding"]


def _ingest(
    conn, tenant_slug: str, department_name: str, label: str, title: str, content: str,
    source: str, source_ref: str | None, submitter: str | None,
) -> int | None:
    """Returns the new document id, or None if the tenant is unrecognized
    or (for the polled sources) this exact content was already ingested."""
    h = content_hash(content)
    with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
        cur.execute("SELECT id FROM app.tenants WHERE slug = %s", (tenant_slug,))
        tenant_row = cur.fetchone()
        if not tenant_row:
            return None
        tenant_id = tenant_row["id"]

        if source_ref is not None:
            cur.execute(
                "SELECT content_hash FROM app.ingest_events "
                "WHERE source = %s AND source_ref = %s ORDER BY created_at DESC LIMIT 1",
                (source, source_ref),
            )
            existing = cur.fetchone()
            if existing and existing["content_hash"] == h:
                return None

        cur.execute("SELECT id FROM app.departments WHERE name = %s", (department_name,))
        department_id = cur.fetchone()["id"]

    vec = get_embedding(content)

    with conn.cursor() as cur:
        cur.execute(
            "INSERT INTO app.documents "
            "(tenant_id, label, owning_department_id, title, source, content, submitter, embedding) "
            "VALUES (%s, %s, %s, %s, %s, %s, %s, %s) RETURNING id",
            (tenant_id, label, department_id, title, source, content, submitter, vec),
        )
        document_id = cur.fetchone()[0]
        cur.execute(
            "INSERT INTO app.ingest_events "
            "(source, source_ref, submitter, content_hash, tenant_id, document_id) "
            "VALUES (%s, %s, %s, %s, %s, %s)",
            (source, source_ref, submitter, h, tenant_id, document_id),
        )
    conn.commit()
    return document_id


class FeedbackRequest(BaseModel):
    tenant: str
    message: str
    submitter: str | None = None


@app.get("/health")
def health():
    return {"status": "ok"}


@app.post("/feedback")
def feedback(body: FeedbackRequest):
    # Public, unauthenticated (SPEC.md §6.3) -- submitter is whatever the
    # caller claims, not a verified identity. No dedup: every submission is
    # a new event, there's no natural "same feedback twice" case.
    conn = db()
    try:
        title = f"Feedback ({datetime.now(timezone.utc).isoformat(timespec='seconds')})"
        document_id = _ingest(
            conn, body.tenant, "Support", "internal", title, body.message,
            "feedback_form", None, body.submitter,
        )
    finally:
        conn.close()
    if document_id is None:
        raise HTTPException(status_code=400, detail="unknown tenant")
    return {"status": "ingested", "document_id": document_id}


def poll_tickets() -> int:
    conn = db()
    count = 0
    try:
        with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
            cur.execute(
                "SELECT tk.id, tk.subject, tk.body, tn.slug AS tenant_slug, c.email AS customer_email "
                "FROM app.tickets tk "
                "JOIN app.tenants tn ON tn.id = tk.tenant_id "
                "JOIN app.customers c ON c.id = tk.customer_id "
                "WHERE tk.status = 'closed'"
            )
            tickets = cur.fetchall()
        for t in tickets:
            document_id = _ingest(
                conn, t["tenant_slug"], "Support", "internal", t["subject"], t["body"],
                "ticket_feed", str(t["id"]), t["customer_email"],
            )
            if document_id is not None:
                count += 1
    finally:
        conn.close()
    return count


def poll_drive() -> int:
    conn = db()
    count = 0
    try:
        if WATCHED_DIR.is_dir():
            for tenant_dir in sorted(WATCHED_DIR.iterdir()):
                if not tenant_dir.is_dir():
                    continue
                for file_path in sorted(tenant_dir.iterdir()):
                    if not file_path.is_file():
                        continue
                    try:
                        content = file_path.read_text(encoding="utf-8")
                    except UnicodeDecodeError:
                        continue
                    source_ref = str(file_path.relative_to(WATCHED_DIR))
                    document_id = _ingest(
                        conn, tenant_dir.name, "Admin", "internal", file_path.stem, content,
                        "drive_sync", source_ref, None,
                    )
                    if document_id is not None:
                        count += 1
    finally:
        conn.close()
    return count


@app.post("/poll")
def poll():
    return {"tickets_ingested": poll_tickets(), "drive_ingested": poll_drive()}


def _poll_loop():
    while True:
        time.sleep(POLL_INTERVAL_SECONDS)
        try:
            poll_tickets()
            poll_drive()
        except Exception as e:
            # Keep the loop alive across a transient DB/network blip -- but
            # never silently: this is exactly the kind of gap SOC telemetry
            # shouldn't have.
            print(f"ingest-svc: poll cycle failed: {e}", file=sys.stderr)


@app.on_event("startup")
def start_poll_thread():
    threading.Thread(target=_poll_loop, daemon=True).start()
