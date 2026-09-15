"""
Interactive analyst-chat router, mounted into dashboard/server.py.

This is the writer that server.py's poller deliberately is NOT. The poll loop
opens soc.db with mode=ro and can physically never write; this router opens its
OWN read-write connection (one per turn, inside the worker thread that runs the
blocking provider call) to drive pipeline/analyst/agent.py. The two concerns
share a process but not a connection, so the observability path keeps its
read-only guarantee while the chat can act.

STREAMING FOR FREE. The agent logs every step of a turn -- the operator message,
each tool call and its result, the final reply -- as rows in chat_turns as it
goes (pipeline/analyst/chat_store.add_turn). server.py's poll loop already
broadcasts new rows of every registered table to all connected browsers, and
this PR registers the chat_* tables there. So the browser sees the turn unfold
via the existing WebSocket, at the poll interval -- no separate streaming
channel, no thread->event-loop bridge. This endpoint just accepts input and
kicks off the turn; the reply arrives over the same feed as everything else.

CONCURRENCY. Each session's in-memory ChatConversation (which holds the running
message list) is mutated only inside a per-session asyncio.Lock, and a second
message for a session whose turn is still running is refused with 409 rather
than queued -- a human types one thing at a time.

Config (repo-root .env, read by server.py's load_dotenv before this imports):
  SOC_ANALYST_PROVIDER  (default: pipeline/analyst/agent.py DEFAULT_PROVIDER)
  SOC_ANALYST_MODEL     (default: that provider's default model)
  SOC_ANALYST_MAX_ITERATIONS
  SOC_ANALYST_EGRESS    (gates the external enrichment tools; see enrichment.py)
"""

import asyncio
import importlib.util
import os
import sys
from pathlib import Path

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel

ROOT = Path(__file__).resolve().parent.parent
ANALYST_DIR = ROOT / "pipeline" / "analyst"
sys.path.insert(0, str(ANALYST_DIR))


def _load(name, path):
    if name in sys.modules:
        return sys.modules[name]
    spec = importlib.util.spec_from_file_location(name, str(path))
    mod = importlib.util.module_from_spec(spec)
    sys.modules[name] = mod
    spec.loader.exec_module(mod)
    return mod


# The analyst agent brings its own transitive imports (chat_store, enrichment,
# the reused hunt agent, providers). Loaded under a unique name so nothing here
# depends on import order.
analyst_agent = _load("soclab_analyst_agent", ANALYST_DIR / "agent.py")
analyst_store = analyst_agent.analyst_store

router = APIRouter(prefix="/api/chat")

# session_id -> ChatConversation (the live message list); rebuilt from the
# transcript recap if a message arrives for a session this process hasn't seen
# (e.g. after a server restart).
_conversations: dict[int, object] = {}
_locks: dict[int, asyncio.Lock] = {}
_tasks: set = set()          # keep background turn tasks from being GC'd
_provider_cache = {}


def _provider_name():
    return os.environ.get("SOC_ANALYST_PROVIDER", analyst_agent.DEFAULT_PROVIDER)


def _model():
    return os.environ.get("SOC_ANALYST_MODEL") or None


def _max_iterations():
    try:
        return int(os.environ.get("SOC_ANALYST_MAX_ITERATIONS", analyst_agent.DEFAULT_MAX_ITERATIONS))
    except ValueError:
        return analyst_agent.DEFAULT_MAX_ITERATIONS


def _provider():
    """One provider instance, built lazily and reused across sessions (provider
    objects are stateless between calls -- the conversation state lives in the
    per-session ChatConversation, not the provider)."""
    key = (_provider_name(), _model())
    if key not in _provider_cache:
        _provider_cache[key] = analyst_agent.hunt_agent.build_provider(key[0], key[1])
    return _provider_cache[key]


def _conn():
    """RW connection to the SAME database the dashboard serves. server.py points
    the poller at SOC_DASHBOARD_DB; the chat writer must land in that same file,
    or the poller would never see (and stream) what the chat writes. Falls back
    to the analyst's default (repo-root soc.db) when the override is unset --
    which is exactly what server.py's poller defaults to too."""
    return analyst_store.connect(os.environ.get("SOC_DASHBOARD_DB") or None)


def ensure_schema():
    """Open one RW connection so the chat_* tables exist before the poller (which
    reads them) or a browser bootstrap queries them. Called from server.py's
    lifespan before poll_loop starts."""
    _conn().close()


def _lock(session_id):
    lk = _locks.get(session_id)
    if lk is None:
        lk = _locks[session_id] = asyncio.Lock()
    return lk


def _do_turn(session_id, text):
    """Synchronous: runs one full agent turn on a fresh RW connection inside a
    worker thread. The agent logs its progress to chat_turns as it goes, which
    the poller streams to browsers."""
    conn = _conn()
    try:
        hunt_id = analyst_store.latest_hunt_id(conn)
        conv = _conversations.get(session_id)
        if conv is None:
            conv = analyst_agent.ChatConversation(_provider(), analyst_agent.system_prompt())
            conv.seed_context(analyst_agent._recap_from_transcript(conn, session_id))
            _conversations[session_id] = conv
        analyst_agent.run_turn(conn, session_id, hunt_id, conv, _provider(),
                               _provider_name(), text, _max_iterations())
    except Exception as e:  # noqa: BLE001 - never let a turn crash the server; record it
        try:
            analyst_store.add_turn(conn, session_id, "assistant",
                                   content=f"[turn failed: {e}]")
        except Exception:  # noqa: BLE001
            pass
    finally:
        conn.close()


async def _run_turn_bg(session_id, text):
    async with _lock(session_id):
        await asyncio.to_thread(_do_turn, session_id, text)


def _start_turn(session_id, text):
    """Start a turn in the background if the session isn't already mid-turn.
    Returns False (caller -> 409) if a turn is already running for it."""
    lk = _lock(session_id)
    if lk.locked():
        return False
    task = asyncio.create_task(_run_turn_bg(session_id, text))
    _tasks.add(task)
    task.add_done_callback(_tasks.discard)
    return True


# ---------------------------------------------------------------------------
# request models + endpoints
# ---------------------------------------------------------------------------

class NewSession(BaseModel):
    sitrep: bool = False


class Message(BaseModel):
    session_id: int
    text: str


@router.get("/config")
async def config():
    return {
        "provider": _provider_name(),
        "model": _model() or analyst_agent.DEFAULT_MODEL.get(_provider_name()),
        "egress": analyst_agent.enrichment.egress_enabled(),
        "tools": [t["name"] for t in analyst_agent.active_tools()],
    }


@router.get("/sessions")
async def list_sessions():
    def _q():
        conn = _conn()
        try:
            rows = conn.execute(
                "SELECT id, started, ended, status, title, hunt_id, provider, model "
                "FROM chat_sessions ORDER BY id DESC LIMIT 50"
            ).fetchall()
            return [dict(r) for r in rows]
        finally:
            conn.close()
    return {"sessions": await asyncio.to_thread(_q)}


@router.post("/sessions")
async def new_session(body: NewSession):
    def _create():
        conn = _conn()
        try:
            hunt_id = analyst_store.latest_hunt_id(conn)
            return analyst_store.start_session(
                conn, _provider_name(), _provider().model,
                lab_mode=analyst_agent.hunt_agent._active_mode(), hunt_id=hunt_id)
        finally:
            conn.close()
    session_id = await asyncio.to_thread(_create)
    if body.sitrep:
        _start_turn(session_id, analyst_agent.SITREP_OPENING)
    return {"session_id": session_id, "sitrep_started": body.sitrep}


@router.post("/messages")
async def post_message(body: Message):
    text = (body.text or "").strip()
    if not text:
        raise HTTPException(status_code=400, detail="empty message")

    def _check():
        conn = _conn()
        try:
            s = analyst_store.get_session(conn, body.session_id)
            return None if not s else s["status"]
        finally:
            conn.close()
    status = await asyncio.to_thread(_check)
    if status is None:
        raise HTTPException(status_code=404, detail=f"no chat session {body.session_id}")
    if status != "active":
        raise HTTPException(status_code=409, detail=f"session is {status}")
    if not _start_turn(body.session_id, text):
        raise HTTPException(status_code=409, detail="a turn is already running for this session")
    return {"accepted": True}


@router.post("/sessions/{session_id}/close")
async def close(session_id: int):
    def _close():
        conn = _conn()
        try:
            if not analyst_store.get_session(conn, session_id):
                return False
            analyst_store.close_session(conn, session_id)
            return True
        finally:
            conn.close()
    if not await asyncio.to_thread(_close):
        raise HTTPException(status_code=404, detail=f"no chat session {session_id}")
    _conversations.pop(session_id, None)
    return {"closed": True}
