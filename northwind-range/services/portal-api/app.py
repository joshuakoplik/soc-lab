"""portal-api: authN, session handling (SPEC.md §7, milestone 5), and the
chat/RAG orchestration path (milestone 7).

Control-toggle endpoints are deliberately not here yet -- the full control
matrix (SPEC.md §5) is milestone 10's job; /chat uses the stated defaults
(RET_PREFILTER=on, ENT_RETRIEVAL=on) as plain constants, not toggles, same
"mechanism now, full matrix later" split every milestone since 4 has used.
"""
import hashlib
import json
import os
import secrets
import urllib.request
from pathlib import Path

import psycopg2
import redis
from fastapi import Depends, FastAPI, HTTPException, Request, Response
from pydantic import BaseModel

from policy import policy

DATABASE_URL = os.environ.get(
    "DATABASE_URL", "postgresql://northwind:northwind-placeholder@postgres:5432/northwind"
)
REDIS_URL = os.environ.get("REDIS_URL", "redis://redis:6379/0")
RETRIEVAL_SVC_URL = os.environ.get("RETRIEVAL_SVC_URL", "http://retrieval-svc:8000")
LITELLM_URL = os.environ.get("LITELLM_URL", "http://litellm:4000")
LITELLM_MASTER_KEY = os.environ.get("LITELLM_MASTER_KEY", "sk-northwind-placeholder")
LITELLM_MODEL = os.environ.get("LITELLM_MODEL", "qwen3-8b")
SESSION_TTL_SECONDS = 8 * 60 * 60
SESSION_COOKIE = "nw_session"
SYSTEM_PROMPT = Path("/app/prompts/baseline.txt").read_text()

app = FastAPI()
r = redis.from_url(REDIS_URL, decode_responses=True)


def db():
    return psycopg2.connect(DATABASE_URL)


def _session_key(session_id: str) -> str:
    return f"session:{session_id}"


class LoginRequest(BaseModel):
    tenant: str
    username: str
    password: str


def get_current_user(request: Request) -> dict:
    session_id = request.cookies.get(SESSION_COOKIE)
    if session_id:
        data = r.hgetall(_session_key(session_id))
        if data:
            r.expire(_session_key(session_id), SESSION_TTL_SECONDS)
            return {
                "user_id": int(data["user_id"]),
                "tenant_id": int(data["tenant_id"]),
                "username": data["username"],
            }

    auth = request.headers.get("authorization", "")
    if auth.lower().startswith("bearer "):
        token_hash = hashlib.sha256(auth[7:].encode()).hexdigest()
        conn = db()
        try:
            with conn.cursor() as cur:
                cur.execute(
                    """
                    SELECT u.id, u.tenant_id, u.username
                    FROM app.api_tokens t JOIN app.users u ON u.id = t.user_id
                    WHERE t.token_hash = %s AND t.revoked_at IS NULL
                    """,
                    (token_hash,),
                )
                row = cur.fetchone()
                if row:
                    cur.execute(
                        "UPDATE app.api_tokens SET last_used_at = now() WHERE token_hash = %s",
                        (token_hash,),
                    )
                    conn.commit()
                    return {"user_id": row[0], "tenant_id": row[1], "username": row[2]}
        finally:
            conn.close()

    raise HTTPException(status_code=401, detail="not authenticated")


@app.get("/health")
def health():
    return {"status": "ok"}


@app.post("/auth/login")
def login(body: LoginRequest, response: Response):
    conn = db()
    try:
        with conn.cursor() as cur:
            cur.execute(
                """
                SELECT u.id, u.tenant_id, u.username, u.display_name,
                       (u.password_hash = crypt(%s, u.password_hash)) AS ok
                FROM app.users u JOIN app.tenants t ON t.id = u.tenant_id
                WHERE t.slug = %s AND u.username = %s AND u.is_active
                """,
                (body.password, body.tenant, body.username),
            )
            row = cur.fetchone()
    finally:
        conn.close()

    if not row or not row[4]:
        raise HTTPException(status_code=401, detail="invalid credentials")

    user_id, tenant_id, username, display_name, _ = row
    session_id = secrets.token_urlsafe(32)
    r.hset(
        _session_key(session_id),
        mapping={"user_id": user_id, "tenant_id": tenant_id, "username": username},
    )
    r.expire(_session_key(session_id), SESSION_TTL_SECONDS)
    # Secure flag intentionally not set -- this stack has no TLS termination
    # yet (edge-nginx's stated role, not built). SameSite=Strict is the CSRF
    # defense for this same-origin JSON API; see SPEC.md §4/§7 discussion.
    response.set_cookie(
        SESSION_COOKIE, session_id, httponly=True, samesite="strict", max_age=SESSION_TTL_SECONDS
    )
    return {"user_id": user_id, "username": username, "display_name": display_name, "tenant_id": tenant_id}


@app.post("/auth/logout")
def logout(request: Request, response: Response):
    session_id = request.cookies.get(SESSION_COOKIE)
    if session_id:
        r.delete(_session_key(session_id))
    response.delete_cookie(SESSION_COOKIE)
    return {"status": "logged out"}


@app.get("/auth/me")
def me(user: dict = Depends(get_current_user)):
    return user


@app.post("/auth/tokens")
def create_token(user: dict = Depends(get_current_user)):
    token = secrets.token_urlsafe(32)
    token_hash = hashlib.sha256(token.encode()).hexdigest()
    conn = db()
    try:
        with conn.cursor() as cur:
            cur.execute(
                "INSERT INTO app.api_tokens (user_id, token_hash) VALUES (%s, %s)",
                (user["user_id"], token_hash),
            )
        conn.commit()
    finally:
        conn.close()
    return {"token": token}


class ChatRequest(BaseModel):
    message: str


def _post_json(url: str, body: dict, headers: dict | None = None, timeout: int = 120) -> dict:
    req = urllib.request.Request(
        url, data=json.dumps(body).encode(),
        headers={"Content-Type": "application/json", **(headers or {})},
    )
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        return json.loads(resp.read())


def retrieval_search(user_id: int, query: str, k: int = 5, mode: str = "prefilter") -> dict:
    return _post_json(
        f"{RETRIEVAL_SVC_URL}/search", {"user_id": user_id, "query": query, "k": k, "mode": mode}
    )


def litellm_chat(system_prompt: str, user_turn: str) -> str:
    result = _post_json(
        f"{LITELLM_URL}/chat/completions",
        {
            "model": LITELLM_MODEL,
            "messages": [
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": user_turn},
            ],
        },
        headers={"Authorization": f"Bearer {LITELLM_MASTER_KEY}"},
        timeout=180,
    )
    return result["choices"][0]["message"]["content"]


@app.post("/chat")
def chat(body: ChatRequest, user: dict = Depends(get_current_user)):
    search_result = retrieval_search(user["user_id"], body.message, k=5, mode="prefilter")
    results = search_result["results"]

    # SPEC.md §5.2 RET_PLACEMENT default: user_delimited -- retrieved
    # content goes in the user turn, clearly fenced, never the system
    # turn. Same delimiter-fencing instinct as the parent lab's own
    # triage agent (<untrusted-evidence> in pipeline/triage/agent.py).
    context = "\n\n".join(f"[{res['title']}]\n{res['content']}" for res in results)
    user_turn = f"<retrieved-context>\n{context}\n</retrieved-context>\n\n{body.message}"

    answer = litellm_chat(SYSTEM_PROMPT, user_turn)
    return {"response": answer, "sources": [res["document_id"] for res in results]}
