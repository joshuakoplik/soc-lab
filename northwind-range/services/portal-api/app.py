"""portal-api: authN, session handling (SPEC.md §7, milestone 5).

Control-toggle endpoints are deliberately not here yet -- the full control
matrix (SPEC.md §5) is milestone 10's job; this milestone is authN/session/
policy-module only, per the build order's own scoping.
"""
import hashlib
import os
import secrets

import psycopg2
import redis
from fastapi import Depends, FastAPI, HTTPException, Request, Response
from pydantic import BaseModel

from policy import policy

DATABASE_URL = os.environ.get(
    "DATABASE_URL", "postgresql://northwind:northwind-placeholder@postgres:5432/northwind"
)
REDIS_URL = os.environ.get("REDIS_URL", "redis://redis:6379/0")
SESSION_TTL_SECONDS = 8 * 60 * 60
SESSION_COOKIE = "nw_session"

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
