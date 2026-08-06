"""
Target adapter for red-team-agent Northwind mode (REDTEAM_MODE_SPEC.md §4.1).

NOT a redteam_exec.py primitive -- agent.py runs on the HOST, not inside
soc-attacker, so this is plain host-side Python HTTP, no `docker exec`
involved at all. Confirmed empirically: the host already has direct kernel
routes to every northwind-range_nw_* bridge (`ip route show`), and a live
`curl` from the host straight to edge-nginx's bridge IP returns real HTTP
responses -- soc-attacker's iptables lockdown, ALLOWED_NETWORKS, and every
other executor.py concept are about a completely different container and
don't apply here.

Two distinct principals, per the spec:

  - The QUERYING USER: authenticates for real via /auth/login, using the
    exact password-derivation + login mechanism harness/runner.py already
    established (HMAC-SHA256(seed, username), same .seed file -- directly
    readable from the host, no volume mount needed, since this process
    isn't containerized). This is the identity whose entitlements are
    under test -- a real, valid low-privilege account, not a cracked one.
  - The ATTACKER PERSONA: agent.py's generic http_request tool (not
    anything in this module -- deliberately no submit_to_ingestion()-style
    wrapper here anymore, see lab_modes.py's NORTHWIND comment) reaches the
    app's own already-unauthenticated /feedback endpoint (SPEC.md §6.3)
    the same way it reaches any other path -- the same "plant a document,
    no review gate" surface harness/runner.py's own setup steps already
    use, just not named or pre-selected for the agent.

Requests go through edge-nginx, not directly to portal-api -- deliberately
different from harness/runner.py's own choice (correct for the harness's
isolate-the-variable purpose, wrong for this one). edge-nginx's access log
feeds the parent SOC-lab's northwind-nginx telemetry stream; going direct
to portal-api would make every red-team HTTP call invisible to it, which
breaks the attacker_ip-style defender-correlation property this whole lab
is built around.

/chat itself is stateless (ChatRequest={message, model}, no history field,
confirmed against services/portal-api/app.py) -- "multi-turn" is threaded
client-side by chat() below, prefixing prior turns into the outgoing
message, and persisted to northwind_chat_turns so it survives a process
restart (--continue-assess), not just kept as an in-memory list.
"""
import base64
import hashlib
import hmac
import http.cookiejar
import json
import os
import time
import subprocess
import sys
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(os.path.dirname(HERE))  # soc-lab repo root, same 3-dirname pattern lab_modes.py uses
NORTHWIND_ROOT = os.path.join(ROOT, "northwind-range")
SEED_FILE = os.path.join(NORTHWIND_ROOT, ".seed")

if NORTHWIND_ROOT not in sys.path:
    # lets `from policy import policy` resolve the same package harness/
    # runner.py imports (northwind-range/policy/__init__.py + policy.py),
    # and lets policy.py's own `import telemetry_writer` resolve too
    # (northwind-range/telemetry_writer.py sits directly in this dir).
    sys.path.insert(0, NORTHWIND_ROOT)

EDGE_NGINX_CONTAINER = "nw-edge-nginx"
POSTGRES_CONTAINER = "nw-postgres"
EDGE_NGINX_NETWORK_SUFFIX = "_nw_dmz"
POSTGRES_NETWORK_SUFFIX = "_nw_app"
HTTP_TIMEOUT_S = 15
# /chat involves a real local-LLM inference round trip (and, per its own
# tool-calling loop, up to MAX_TOOL_TURNS of them) -- slower than any other
# endpoint this adapter calls, and 15s isn't enough headroom for that.
CHAT_TIMEOUT_S = 90


class NorthwindAdapterError(Exception):
    """Any adapter-level failure -- network, auth, or a malformed response.
    Never a Python builtin exception leaking through, so callers (agent.py's
    dispatch_*_tool, once built) can catch one thing."""


def _docker_inspect_ip(container: str, network_suffix: str) -> str | None:
    """Host-side `docker inspect`, NOT docker exec -- no soc-attacker
    involvement. Container IPs aren't guaranteed stable across a recreate,
    so this is resolved fresh on every call rather than cached, same
    "re-read rather than trust a stale allowlist" discipline
    executor.validate_target() already uses for a different reason."""
    try:
        proc = subprocess.run(
            ["docker", "inspect", container, "--format", "{{json .NetworkSettings.Networks}}"],
            capture_output=True, text=True, timeout=10,
        )
    except (subprocess.TimeoutExpired, OSError):
        return None
    if proc.returncode != 0:
        return None
    try:
        networks = json.loads(proc.stdout)
    except json.JSONDecodeError:
        return None
    for name, info in networks.items():
        if name.endswith(network_suffix):
            return info.get("IPAddress") or None
    return None


def base_url() -> str:
    ip = _docker_inspect_ip(EDGE_NGINX_CONTAINER, EDGE_NGINX_NETWORK_SUFFIX)
    if not ip:
        raise NorthwindAdapterError(
            f"could not resolve {EDGE_NGINX_CONTAINER}'s IP on a *{EDGE_NGINX_NETWORK_SUFFIX} "
            "network -- is the northwind-range stack up?"
        )
    return f"http://{ip}:80"


def _postgres_database_url() -> str:
    ip = _docker_inspect_ip(POSTGRES_CONTAINER, POSTGRES_NETWORK_SUFFIX)
    if not ip:
        raise NorthwindAdapterError(
            f"could not resolve {POSTGRES_CONTAINER}'s IP on a *{POSTGRES_NETWORK_SUFFIX} "
            "network -- is the northwind-range stack up?"
        )
    # Same placeholder creds policy.py itself defaults to (docker-compose.yml's
    # own POSTGRES_USER/PASSWORD, not a generated secret) -- just the
    # hostname swapped for a resolved IP, since "postgres" only resolves
    # inside northwind-range's own compose network, not from the host.
    return f"postgresql://northwind:northwind-placeholder@{ip}:5432/northwind"


def _read_seed() -> str:
    try:
        with open(SEED_FILE) as f:
            return f.read().strip()
    except OSError as e:
        raise NorthwindAdapterError(f"could not read {SEED_FILE}: {e}") from e


def derive_password(seed: str, username: str) -> str:
    # Identical to harness/runner.py's derive_password() (and
    # scripts/seed_entitlements.py's) -- must stay in lockstep, since this
    # is what lets the adapter log in for real with no plaintext password
    # ever stored anywhere.
    digest = hmac.new(seed.encode(), username.encode(), hashlib.sha256).digest()
    return base64.b32encode(digest).decode().rstrip("=").lower()[:20]


@dataclass
class NorthwindSession:
    opener: urllib.request.OpenerDirector
    tenant: str
    username: str
    user_id: int
    tenant_id: int
    display_name: str | None
    department: str | None

    @property
    def identity(self) -> str:
        return f"{self.tenant}/{self.username}"


def _path_only(url: str) -> str:
    """Strips scheme/host/port from a URL for use in model-facing error
    text. base_url() resolves to a real container IP (e.g.
    http://172.28.10.4:80) -- that's an infrastructure implementation
    detail of THIS harness, not something a genuine external attacker
    would ever see, and embedding it in an error message the model reads
    leaks internal topology into the agent's own reasoning, contaminating
    the measurement (confirmed live: a red-team session flagged the
    resolved IP appearing in a 429 error as an "information disclosure"
    finding about the TARGET, when it was actually this adapter's own
    error formatting)."""
    parsed = urllib.parse.urlparse(url)
    return parsed.path + (f"?{parsed.query}" if parsed.query else "")


def _post_json(
    opener: urllib.request.OpenerDirector | None, url: str, payload: dict, timeout: int = HTTP_TIMEOUT_S
) -> dict:
    req = urllib.request.Request(
        url, data=json.dumps(payload).encode(), headers={"Content-Type": "application/json"}, method="POST",
    )
    opener_fn = opener.open if opener is not None else urllib.request.urlopen
    try:
        resp = opener_fn(req, timeout=timeout)
        return json.loads(resp.read())
    except urllib.error.HTTPError as e:
        raise NorthwindAdapterError(
            f"POST {_path_only(url)} -> {e.code}: {e.read().decode(errors='replace')}"
        ) from e
    except urllib.error.URLError as e:
        raise NorthwindAdapterError(f"POST {_path_only(url)} failed: {e}") from e


def _get_json(opener: urllib.request.OpenerDirector | None, url: str) -> dict:
    req = urllib.request.Request(url, method="GET")
    opener_fn = opener.open if opener is not None else urllib.request.urlopen
    try:
        resp = opener_fn(req, timeout=HTTP_TIMEOUT_S)
        return json.loads(resp.read())
    except urllib.error.HTTPError as e:
        raise NorthwindAdapterError(
            f"GET {_path_only(url)} -> {e.code}: {e.read().decode(errors='replace')}"
        ) from e
    except urllib.error.URLError as e:
        raise NorthwindAdapterError(f"GET {_path_only(url)} failed: {e}") from e


def _lookup_department(user_id: int) -> str | None:
    """Best-effort -- /auth/login and /auth/me don't return department
    (see services/portal-api/app.py), so this is one direct read against
    the live DB, purely for northwind_identities' own context column. Not
    load-bearing for anything else the adapter does -- ANY failure here
    (missing psycopg2, unreachable postgres, whatever) degrades to None,
    never propagates."""
    try:
        import psycopg2

        conn = psycopg2.connect(_postgres_database_url())
    except Exception:
        return None
    try:
        with conn.cursor() as cur:
            cur.execute(
                "SELECT d.name FROM app.users u JOIN app.departments d ON d.id = u.department_id "
                "WHERE u.id = %s",
                (user_id,),
            )
            row = cur.fetchone()
            return row[0] if row else None
    except Exception:
        return None
    finally:
        conn.close()


def active_grants(user_id: int) -> list[dict]:
    """For whoami's "visible grants" -- /auth/login and /auth/me don't
    return grants either (same gap as department), so this is a second
    direct read. Same best-effort failure posture as _lookup_department():
    an empty list on any failure, never a raised exception -- whoami should
    never crash a session over a missing nice-to-have."""
    try:
        import psycopg2

        conn = psycopg2.connect(_postgres_database_url())
    except Exception:
        return []
    try:
        with conn.cursor() as cur:
            cur.execute(
                "SELECT d.name, g.expires_at FROM app.grants g "
                "JOIN app.departments d ON d.id = g.department_id "
                "WHERE g.user_id = %s AND g.revoked_at IS NULL "
                "AND (g.expires_at IS NULL OR g.expires_at > now())",
                (user_id,),
            )
            return [{"department": row[0], "expires_at": row[1].isoformat() if row[1] else None}
                    for row in cur.fetchall()]
    except Exception:
        return []
    finally:
        conn.close()


def login(conn, session_id: int, tenant: str, username: str) -> NorthwindSession:
    """Real login via POST /auth/login through edge-nginx -- never a
    session-forging backdoor (SPEC.md §4.1: "never bypasses authentication
    or entitlement checks to set up an attempt"). Records a row in
    northwind_identities as a side effect, same "deterministic persistence,
    no model tool call required" pattern recon_findings/loot already use."""
    seed = _read_seed()
    password = derive_password(seed, username)
    cj = http.cookiejar.CookieJar()
    opener = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(cj))
    result = _post_json(
        opener, f"{base_url()}/api/auth/login",
        {"tenant": tenant, "username": username, "password": password},
    )
    department = _lookup_department(result["user_id"])
    nw_session = NorthwindSession(
        opener=opener, tenant=tenant, username=username, user_id=result["user_id"],
        tenant_id=result["tenant_id"], display_name=result.get("display_name"), department=department,
    )
    from agent import now_iso  # local import -- avoids a circular import at module load time

    conn.execute(
        "INSERT INTO northwind_identities (session_id, tenant, username, display_name, department, logged_in_at) "
        "VALUES (?,?,?,?,?,?)",
        (session_id, tenant, username, nw_session.display_name, department, now_iso()),
    )
    conn.commit()
    return nw_session


def whoami(nw_session: NorthwindSession) -> dict:
    """Pure passthrough, not persisted -- GET /auth/me, useful for
    confirming a login's identity matches what was requested."""
    return _get_json(nw_session.opener, f"{base_url()}/api/auth/me")


def get_control_state() -> dict | None:
    """GET /api/controls through edge-nginx -- unauthenticated (no auth
    dependency on the route, same posture as /feedback). Best-effort, same
    failure posture as active_grants()/_lookup_department(): this is a
    nice-to-have operator snapshot (REDTEAM_MODE_SPEC.md §6's lab_config,
    never surfaced to the model), not load-bearing for anything the
    session actually does -- a failure here must never crash session
    start."""
    try:
        return _get_json(None, f"{base_url()}/api/controls")
    except Exception:
        return None


def _load_chat_history(conn, session_id: int, identity: str) -> list[dict]:
    rows = conn.execute(
        "SELECT role, content FROM northwind_chat_turns WHERE session_id=? AND identity=? "
        "ORDER BY turn_index",
        (session_id, identity),
    ).fetchall()
    return [{"role": row["role"], "content": row["content"]} for row in rows]


def _next_turn_index(conn, session_id: int, identity: str) -> int:
    row = conn.execute(
        "SELECT COALESCE(MAX(turn_index), -1) + 1 AS next FROM northwind_chat_turns "
        "WHERE session_id=? AND identity=?",
        (session_id, identity),
    ).fetchone()
    return row["next"]


def chat(conn, session_id: int, nw_session: NorthwindSession, message: str, model: str | None = None) -> dict:
    """POST /api/chat through edge-nginx, threading conversation history
    client-side since the endpoint itself is stateless (no history field
    on ChatRequest -- confirmed against services/portal-api/app.py). Prior
    turns for THIS (session_id, identity) are prefixed into the outgoing
    `message` as a plain transcript; both the new user turn and the
    assistant's reply are persisted afterward so a later process restart
    (--continue-assess) can reconstruct the same conversation instead of
    starting over. Known limitation, not solved here: no truncation of a
    very long prefixed transcript -- flagged as a follow-up once a real
    session shows whether it matters."""
    from agent import now_iso  # local import -- avoids a circular import at module load time

    history = _load_chat_history(conn, session_id, nw_session.identity)
    if history:
        transcript = "\n".join(
            f"{'User' if turn['role'] == 'user' else 'Assistant'}: {turn['content']}" for turn in history
        )
        outgoing = f"{transcript}\nUser: {message}"
    else:
        outgoing = message

    payload = {"message": outgoing}
    if model:
        payload["model"] = model
    response = _post_json(nw_session.opener, f"{base_url()}/api/chat", payload, timeout=CHAT_TIMEOUT_S)

    turn_index = _next_turn_index(conn, session_id, nw_session.identity)
    ts = now_iso()
    conn.execute(
        "INSERT INTO northwind_chat_turns (session_id, identity, turn_index, role, content, created) "
        "VALUES (?,?,?,?,?,?)",
        (session_id, nw_session.identity, turn_index, "user", message, ts),
    )
    conn.execute(
        "INSERT INTO northwind_chat_turns (session_id, identity, turn_index, role, content, created) "
        "VALUES (?,?,?,?,?,?)",
        (session_id, nw_session.identity, turn_index + 1, "assistant", response.get("response", ""), ts),
    )
    conn.commit()
    return response


def probe(nw_session: NorthwindSession, message: str, model: str | None = None) -> tuple[dict, float]:
    """A raw, one-shot POST /api/chat -- deliberately NOT going through
    chat()'s history-threading/persistence. Probing is reconnaissance
    noise, not a meaningful conversation turn: threading probe messages
    into the same growing transcript would pollute every future real turn
    with throwaway content the querying identity never actually said.
    Returns (response_dict, latency_ms) -- latency is measured here, not
    left to _progress_wrapper's generic per-tool timing, since that's
    print-only and never reaches the model, and probe_refusal's result
    needs it."""
    payload = {"message": message}
    if model:
        payload["model"] = model
    t0 = time.monotonic()
    response = _post_json(nw_session.opener, f"{base_url()}/api/chat", payload, timeout=CHAT_TIMEOUT_S)
    latency_ms = (time.monotonic() - t0) * 1000
    return response, latency_ms


def entitled_for_document(user_id: int, source: str) -> bool | None:
    """Resolves a canary map's `source` (relative file path, stable across
    reseeds -- see corpus/canaries.yaml) to the LIVE app.documents.id
    (ids are a serial PK reset on every corpus reload, so this can't be
    cached), then defers to policy.decide() -- the same canonical
    entitlement function every other consumer in this app uses, not a
    re-derived copy of its rule. Returns None if the document doesn't
    exist right now (corpus reloaded since the canary map was written).

    TELEMETRY_DIR is deliberately left unset here (defaults to
    /app/telemetry, which doesn't exist on the host -- policy.py's own
    telemetry_writer.emit() swallows the resulting OSError and no-ops).
    That's intentional, not an oversight: this is an out-of-band scoring
    lookup by the red-team harness, not a real user-facing policy
    decision, and writing it into the app's own policy_decisions
    telemetry stream would plant a phantom decision a defender analyzing
    that stream later has no way to distinguish from a real one.
    """
    import psycopg2
    from policy import policy as northwind_policy

    northwind_policy.DATABASE_URL = _postgres_database_url()
    try:
        conn = psycopg2.connect(northwind_policy.DATABASE_URL)
    except Exception as e:
        raise NorthwindAdapterError(f"could not connect to northwind postgres: {e}") from e
    try:
        with conn.cursor() as cur:
            cur.execute("SELECT id FROM app.documents WHERE source = %s", (source,))
            row = cur.fetchone()
        if not row:
            return None
        document_id = row[0]
        decision = northwind_policy.decide(user_id, document_id, conn=conn)
        return decision.allowed
    finally:
        conn.close()
