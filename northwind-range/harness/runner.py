"""harness/runner.py: SPEC.md §9.1's run model -- one model x one control
vector x one corpus version x the full attack+benign corpus, unattended
and resumable. execute_run() is the one core function, called two ways:
this file's own CLI entrypoint (matching SPEC's literal example shape,
`harness run --model qwen3-8b --controls configs/ablation-07.yaml
--corpus v3`) and api.py's `POST /runs` (same function, backgrounded).

The runner talks to the running stack exactly the way verify-controls.sh
already does: direct HTTP to portal-api (the only thing harness has a
route to besides postgres -- see docker-compose.yml's network comment),
never edge-nginx (already covered structurally by verify-chat.sh) and
never retrieval-svc/tool-svc/ingest-svc directly (nw_app-only, no route).
Each attempt logs in for real via /auth/login, deriving the actor's
password the same way scripts/seed_entitlements.py does from the
bind-mounted .seed file -- no Redis access needed for session forging.
"""
import argparse
import base64
import hashlib
import hmac
import http.cookiejar
import json
import os
import time
import urllib.error
import urllib.request
from pathlib import Path

import psycopg2
import psycopg2.extras
import yaml

from policy import policy
from scoring import score_attempt

DATABASE_URL = os.environ.get(
    "DATABASE_URL", "postgresql://northwind:northwind-placeholder@postgres:5432/northwind"
)
PORTAL_API_URL = os.environ.get("PORTAL_API_URL", "http://portal-api:8000")
SEED_FILE = Path(os.environ.get("SEED_FILE", "/app/.seed"))
PROMPTS_DIR = Path("/app/prompts")
HARNESS_VERSION = "0.1.0"

PROMPT_VARIANTS = ("minimal", "baseline", "hardened", "hardened_with_examples")


def db():
    return psycopg2.connect(DATABASE_URL)


# ---------------------------------------------------------------------------
# portal-api HTTP helpers
# ---------------------------------------------------------------------------

def put_controls(payload: dict) -> None:
    req = urllib.request.Request(
        f"{PORTAL_API_URL}/controls", data=json.dumps(payload).encode(),
        headers={"Content-Type": "application/json"}, method="PUT",
    )
    urllib.request.urlopen(req, timeout=15)


def get_controls() -> dict:
    resp = urllib.request.urlopen(f"{PORTAL_API_URL}/controls", timeout=15)
    return json.loads(resp.read())


def reset_controls() -> None:
    req = urllib.request.Request(
        f"{PORTAL_API_URL}/controls/reset", data=b"{}",
        headers={"Content-Type": "application/json"}, method="POST",
    )
    urllib.request.urlopen(req, timeout=15)


def derive_password(seed: str, username: str) -> str:
    # Identical derivation to scripts/seed_entitlements.py's own -- must
    # stay in lockstep, since this is what lets the runner log in for real
    # without a copy of .seed-credentials.json's plaintext.
    digest = hmac.new(seed.encode(), username.encode(), hashlib.sha256).digest()
    return base64.b32encode(digest).decode().rstrip("=").lower()[:20]


def login(username: str, tenant_slug: str, seed: str) -> urllib.request.OpenerDirector:
    password = derive_password(seed, username)
    cj = http.cookiejar.CookieJar()
    opener = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(cj))
    body = json.dumps({"tenant": tenant_slug, "username": username, "password": password}).encode()
    req = urllib.request.Request(
        f"{PORTAL_API_URL}/auth/login", data=body, headers={"Content-Type": "application/json"}
    )
    opener.open(req, timeout=15)
    return opener


# ---------------------------------------------------------------------------
# Actor + target resolution -- against live data, not hardcoded ids (see
# the milestone 11 plan's decision 3)
# ---------------------------------------------------------------------------

def resolve_actor(actor_spec: dict, conn) -> dict:
    with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
        if actor_spec.get("username"):
            cur.execute(
                "SELECT u.id, u.username, t.slug AS tenant_slug FROM app.users u "
                "JOIN app.tenants t ON t.id = u.tenant_id WHERE u.username = %s",
                (actor_spec["username"],),
            )
        else:
            cur.execute(
                "SELECT u.id, u.username, t.slug AS tenant_slug FROM app.users u "
                "JOIN app.tenants t ON t.id = u.tenant_id "
                "JOIN app.departments d ON d.id = u.department_id "
                "WHERE t.slug = %s AND d.name = %s ORDER BY u.id LIMIT 1",
                (actor_spec["tenant"], actor_spec["department"]),
            )
        row = cur.fetchone()
        if not row:
            raise ValueError(f"no user matches actor spec {actor_spec!r}")
        return dict(row)


def resolve_target(target_spec: dict | None, actor: dict, conn) -> dict | None:
    if not target_spec or target_spec.get("type") in (None, "none"):
        return None
    ttype = target_spec["type"]
    # cross_department and any_denied resolve identically for documents --
    # both mean "not public, not the actor's own department" -- so they're
    # not given separate query paths.
    cross_tenant = target_spec.get("scope") == "cross_tenant"

    with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
        cur.execute("SELECT tenant_id, department_id FROM app.users WHERE id = %s", (actor["id"],))
        actor_row = cur.fetchone()

        if ttype == "document":
            if cross_tenant:
                cur.execute("SELECT id FROM app.documents WHERE tenant_id != %s ORDER BY id", (actor_row["tenant_id"],))
            else:
                cur.execute(
                    "SELECT id FROM app.documents WHERE tenant_id = %s AND label != 'public' "
                    "AND owning_department_id != %s ORDER BY id",
                    (actor_row["tenant_id"], actor_row["department_id"]),
                )
            for row in cur.fetchall():
                if not policy.decide(actor["id"], row["id"], "read", conn=conn).allowed:
                    return {"type": "document", "document_id": row["id"]}
            return None

        if ttype == "customer_record":
            tenant_filter = "!=" if cross_tenant else "="
            cur.execute(
                f"SELECT id, name, email, phone FROM app.customers WHERE tenant_id {tenant_filter} %s ORDER BY id LIMIT 1",
                (actor_row["tenant_id"],),
            )
            row = cur.fetchone()
            if not row:
                return None
            return {
                "type": "customer_record", "customer_id": row["id"],
                "fields": {"name": row["name"], "email": row["email"], "phone": row["phone"]},
            }

        if ttype == "ticket":
            tenant_filter = "!=" if cross_tenant else "="
            cur.execute(
                f"SELECT id, subject FROM app.tickets WHERE tenant_id {tenant_filter} %s ORDER BY id LIMIT 1",
                (actor_row["tenant_id"],),
            )
            row = cur.fetchone()
            if not row:
                return None
            return {"type": "ticket", "ticket_id": row["id"], "fields": {"subject": row["subject"]}}

        if ttype == "usage":
            # Leak detection for usage targets is inherently weaker than
            # customer_record/ticket -- a computed aggregate can't be
            # matched by a fixed substring the way a name/email can, so
            # `fields` stays empty and _target_leaked() correctly reports
            # "not detected" rather than a false positive.
            tenant_filter = "!=" if cross_tenant else "="
            cur.execute(
                f"SELECT id FROM app.customers WHERE tenant_id {tenant_filter} %s ORDER BY id LIMIT 1",
                (actor_row["tenant_id"],),
            )
            row = cur.fetchone()
            return {"type": "usage", "customer_id": row["id"], "fields": {}} if row else None

        if ttype == "system_prompt":
            texts = [(PROMPTS_DIR / f"{v}.txt").read_text() for v in PROMPT_VARIANTS]
            return {"type": "system_prompt", "prompt_texts": texts}

    return None


# ---------------------------------------------------------------------------
# Attempt execution
# ---------------------------------------------------------------------------

def run_setup_steps(setup: list, opener, tenant_slug_fallback: str) -> dict:
    context: dict = {}
    for step in setup or []:
        if step.get("action") == "feedback":
            body = json.dumps({
                "tenant": step.get("tenant", tenant_slug_fallback),
                "message": step["message"],
                "submitter": step.get("submitter"),
            }).encode()
            req = urllib.request.Request(
                f"{PORTAL_API_URL}/feedback", data=body, headers={"Content-Type": "application/json"}
            )
            resp = opener.open(req, timeout=15)
            data = json.loads(resp.read())
            context["planted_document_id"] = data.get("document_id")
    return context


def run_attempt(item_definition: dict, model: str, seed: str, conn):
    actor = resolve_actor(item_definition["actor"], conn)
    opener = login(actor["username"], actor["tenant_slug"], seed)

    setup_context = run_setup_steps(item_definition.get("setup"), opener, actor["tenant_slug"])

    target_spec = item_definition.get("target")
    if (not target_spec or target_spec.get("type") == "none") and setup_context.get("planted_document_id"):
        # indirect_retrieval's implicit target: the document *this item's
        # own setup step* planted -- did it come back in sources?
        target = {"type": "document", "document_id": setup_context["planted_document_id"]}
    else:
        target = resolve_target(target_spec, actor, conn)

    response: dict = {"response": "", "sources": [], "tool_calls": []}
    status = 200
    start = time.monotonic()
    try:
        for step in item_definition["steps"]:
            body = json.dumps({"message": step["message"], "model": model}).encode()
            req = urllib.request.Request(
                f"{PORTAL_API_URL}/chat", data=body, headers={"Content-Type": "application/json"}
            )
            resp = opener.open(req, timeout=180)
            response = json.loads(resp.read())
    except urllib.error.HTTPError as e:
        status = e.code
        try:
            response = json.loads(e.read())
        except (json.JSONDecodeError, TypeError):
            pass
    latency_ms = int((time.monotonic() - start) * 1000)

    return response, latency_ms, status, target, actor["id"]


def reset_app_state(conn) -> None:
    # SPEC.md §9.1: "critical, since ingestion attacks mutate the index by
    # design." Nothing else in this platform mutates app.* state at
    # runtime -- tools are all read-only, and grants/users are only ever
    # set at seed time -- so this one targeted DELETE is sufficient
    # between-attempt cleanup, milliseconds not minutes (no re-embedding,
    # no container restart). ingest_events rows are deleted first --
    # app.ingest_events.document_id has no ON DELETE CASCADE.
    with conn.cursor() as cur:
        cur.execute(
            "DELETE FROM app.ingest_events WHERE document_id IN ("
            "  SELECT id FROM app.documents WHERE source IN ('feedback_form', 'ticket_feed', 'drive_sync')"
            ")"
        )
        cur.execute("DELETE FROM app.documents WHERE source IN ('feedback_form', 'ticket_feed', 'drive_sync')")
    conn.commit()


# ---------------------------------------------------------------------------
# harness.* bookkeeping
# ---------------------------------------------------------------------------

def create_run(conn, model, controls_name, resolved_controls, corpus_version) -> int:
    with conn.cursor() as cur:
        cur.execute(
            "INSERT INTO harness.runs (model, controls_name, controls, corpus_version, harness_version) "
            "VALUES (%s, %s, %s, %s, %s) RETURNING id",
            (model, controls_name, json.dumps(resolved_controls), corpus_version, HARNESS_VERSION),
        )
        run_id = cur.fetchone()[0]
    conn.commit()
    return run_id


def already_scored(conn, run_id, corpus_item_id) -> bool:
    with conn.cursor() as cur:
        cur.execute(
            "SELECT 1 FROM harness.results WHERE run_id = %s AND corpus_item_id = %s",
            (run_id, corpus_item_id),
        )
        return cur.fetchone() is not None


def save_result(conn, run_id, corpus_item_id, scored, latency_ms, raw_response) -> None:
    with conn.cursor() as cur:
        cur.execute(
            "INSERT INTO harness.results "
            "(run_id, corpus_item_id, requested, policy_expected, retrieved, emitted, "
            " leaked, refused, over_refusal, leak_layer, latency_ms, raw_response) "
            "VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)",
            (
                run_id, corpus_item_id, json.dumps(scored["requested"]), json.dumps(scored["policy_expected"]),
                json.dumps(scored["retrieved"]), scored["emitted"], scored["leaked"], scored["refused"],
                scored["over_refusal"], scored["leak_layer"], latency_ms, json.dumps(raw_response),
            ),
        )
    conn.commit()


def mark_finished(conn, run_id) -> None:
    with conn.cursor() as cur:
        cur.execute("UPDATE harness.runs SET finished_at = now() WHERE id = %s", (run_id,))
    conn.commit()


def load_corpus_items(conn) -> list:
    with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
        cur.execute("SELECT id, kind, category, definition FROM harness.corpus_items ORDER BY kind, id")
        return [dict(row) for row in cur.fetchall()]


# ---------------------------------------------------------------------------
# Run model (SPEC.md §9.1)
# ---------------------------------------------------------------------------

def execute_run(model: str, controls_path: str, corpus_version: str, resume_run_id: int | None = None) -> int:
    controls_payload = yaml.safe_load(Path(controls_path).read_text()) or {}
    seed = SEED_FILE.read_text().strip()

    conn = db()
    try:
        reset_app_state(conn)  # in case a prior crashed run left contamination
        reset_controls()
        put_controls(controls_payload)
        resolved_controls = get_controls()

        run_id = resume_run_id or create_run(
            conn, model, Path(controls_path).name, resolved_controls, corpus_version
        )

        for item in load_corpus_items(conn):
            if already_scored(conn, run_id, item["id"]):
                continue
            response, latency_ms, status, target, actor_id = run_attempt(item["definition"], model, seed, conn)
            scored = score_attempt(item["definition"], response, latency_ms, status, target, actor_id, conn)
            save_result(conn, run_id, item["id"], scored, latency_ms, response)
            reset_app_state(conn)

        mark_finished(conn, run_id)
        return run_id
    finally:
        conn.close()


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Run a harness attempt batch against the live stack.")
    parser.add_argument("--model", required=True)
    parser.add_argument("--controls", required=True, help="path to a YAML file, e.g. configs/baseline.yaml")
    parser.add_argument("--corpus", required=True, help="operator-supplied corpus version label")
    parser.add_argument("--resume", type=int, default=None, help="existing run id to resume")
    args = parser.parse_args()
    finished_run_id = execute_run(args.model, args.controls, args.corpus, args.resume)
    print(f"run_id={finished_run_id}")
