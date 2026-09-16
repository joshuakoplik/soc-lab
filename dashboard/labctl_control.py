"""
Lab-control router, mounted into dashboard/server.py -- the Phase-2 UI backend
for the lab manager. Mirrors the analyst-chat router's shape: the browser POSTs
to kick off an ACTION, a worker runs the blocking call in asyncio.to_thread, and
a single module-level lock serialises mutating ops so two clicks can't race a
mode switch (a second mutating call while one is in flight is refused 409).

Unlike chat, this router does NOT write soc.db. It imports pipeline.labctl and
calls orchestrate/procman/state directly -- the SAME code path `./labctl` uses on
the command line, never a reimplementation. Lab actions run the existing scripts
(lab-mode.sh / reset.sh / npc-range Makefile) as subprocesses.

Status transport: the Lab tab POLLS GET /api/lab/status (a control panel doesn't
need sub-second streaming, and `docker compose ps` must stay OUT of server.py's
1.5s WS poller). Live agent state (hunt_sessions/redteam_sessions) still rides the
existing WebSocket table broadcasts. The docker view is cached briefly so rapid
polls don't spawn a `docker ps` each time.

Safety: this runs powerful controls (start the attacker, switch modes, wipe the
DB). The dashboard binds 127.0.0.1 only by default -- keep it there. Every
destructive reset (--db/--all) requires an explicit confirm=true, enforced in
orchestrate.reset() AND surfaced as a 409 here. Every action is appended to
.labctl/logs/actions.log as an audit record.
"""

import asyncio
import os
import sys
import time
from pathlib import Path

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel

# Make `pipeline.labctl` importable: the dashboard runs as `python3
# dashboard/server.py`, so sys.path[0] is dashboard/, not the repo root.
ROOT = Path(__file__).resolve().parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from pipeline.labctl import config as lab_config  # noqa: E402
from pipeline.labctl import orchestrate, procman, state  # noqa: E402

router = APIRouter(prefix="/api/lab")

# Serialises MUTATING ops (a mode switch, a process start, a reset). Reads
# (status) don't take it. A held lock -> 409, same posture as chat's per-session
# lock, but lab ops are global so the lock is too.
_mutate_lock = asyncio.Lock()

# brief cache for the (slow) docker-inclusive status
_status_cache = {"at": 0.0, "data": None}
_STATUS_TTL = 4.0

_MANAGED = set(lab_config.MANAGED)
_MODE_VERBS = {"up", "down", "switch", "posture", "bootstrap", "status"}


def _audit(action, detail):
    try:
        os.makedirs(lab_config.LOG_DIR, exist_ok=True)
        with open(os.path.join(lab_config.LOG_DIR, "actions.log"), "a") as f:
            ts = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
            f.write(f"{ts} [dashboard] {action} {detail}\n")
    except OSError:
        pass


async def _mutate(fn, *args, **kwargs):
    """Run a blocking mutating op under the global lock; 409 if one's in flight."""
    if _mutate_lock.locked():
        raise HTTPException(status_code=409, detail="another lab action is in progress")
    async with _mutate_lock:
        return await asyncio.to_thread(fn, *args, **kwargs)


# --------------------------------------------------------------------------- #
# request models
# --------------------------------------------------------------------------- #

class ModeAction(BaseModel):
    verb: str
    mode: str | None = None
    target: str | None = None


class ProcessAction(BaseModel):
    name: str
    action: str            # start | stop | restart
    provider: str | None = None
    model: str | None = None


class FlockAction(BaseModel):
    action: str            # up | down | status | reconcile
    name: str | None = None      # template (up) or flock name / --all (down)
    network: str | None = None


class SupervisorAction(BaseModel):
    action: str            # start | stop | policies
    policies: dict | None = None


class ResetAction(BaseModel):
    flags: list[str] = []
    confirm: bool = False


# --------------------------------------------------------------------------- #
# read: status
# --------------------------------------------------------------------------- #

@router.get("/status")
async def status(docker: bool = True):
    if docker:
        now = time.time()
        if _status_cache["data"] is not None and (now - _status_cache["at"]) < _STATUS_TTL:
            return _status_cache["data"]
        data = await asyncio.to_thread(orchestrate.status, True)
        _status_cache["at"] = now
        _status_cache["data"] = data
        return data
    return await asyncio.to_thread(orchestrate.status, False)


@router.get("/config")
async def get_config():
    cfg = lab_config.load()
    return {
        "modes": list(orchestrate.VALID_MODES),
        "managed": list(lab_config.MANAGED),
        "policies": {k: cfg[k] for k in cfg if k.startswith("policy_")},
        "timers": {k: cfg[k] for k in ("idle_timeout", "attack_drain_max",
                                       "poll_interval", "detect_interval")},
        "hunter": {"provider": cfg["hunter_provider"], "model": cfg["hunter_model"]},
        "destructive_reset_flags": sorted(orchestrate.DESTRUCTIVE_RESET_FLAGS),
    }


# --------------------------------------------------------------------------- #
# mutating actions
# --------------------------------------------------------------------------- #

@router.post("/mode")
async def mode_action(body: ModeAction):
    if body.verb not in _MODE_VERBS:
        raise HTTPException(status_code=400, detail=f"bad verb '{body.verb}'")
    if body.verb in ("up", "switch") and body.mode not in orchestrate.VALID_MODES:
        raise HTTPException(status_code=400, detail=f"bad mode '{body.mode}'")
    _audit("mode", f"{body.verb} {body.mode or ''} {body.target or ''}".strip())
    res = await _mutate(orchestrate.lab_mode, body.verb, body.mode, body.target)
    return res


@router.post("/process")
async def process_action(body: ProcessAction):
    if body.name not in _MANAGED:
        raise HTTPException(status_code=400, detail=f"unknown process '{body.name}'")
    if body.action not in ("start", "stop", "restart"):
        raise HTTPException(status_code=400, detail=f"bad action '{body.action}'")
    opts = {"provider": body.provider, "model": body.model}
    _audit("process", f"{body.action} {body.name}")

    def _do():
        if body.action == "stop":
            stopped = procman.stop(body.name)
            return {"name": body.name, "action": "stop", "stopped": stopped}
        fn = procman.restart if body.action == "restart" else procman.start
        started, entry = fn(body.name, opts)
        return {"name": body.name, "action": body.action,
                "started": started, "pid": entry.get("pid") if entry else None}

    return await _mutate(_do)


@router.post("/flock")
async def flock_action(body: FlockAction):
    if body.action not in ("up", "down", "status", "reconcile"):
        raise HTTPException(status_code=400, detail=f"bad flock action '{body.action}'")
    _audit("flock", f"{body.action} {body.name or ''}".strip())
    template = body.name if body.action == "up" else None
    name = body.name if body.action == "down" else None
    return await _mutate(orchestrate.flock, body.action, template, name, body.network)


@router.post("/supervisor")
async def supervisor_action(body: SupervisorAction):
    if body.action not in ("start", "stop", "policies"):
        raise HTTPException(status_code=400, detail=f"bad action '{body.action}'")
    _audit("supervisor", f"{body.action} {body.policies or ''}".strip())

    def _do():
        result = {}
        if body.policies:
            lab_config.write_policies(body.policies)
            result["policies_written"] = True
        if body.action == "start":
            started, entry = procman.start("supervisor")
            result.update(started=started, pid=entry.get("pid") if entry else None)
        elif body.action == "stop":
            result["stopped"] = procman.stop("supervisor")
        return result

    return await _mutate(_do)


@router.post("/reset")
async def reset_action(body: ResetAction):
    destructive = any(f in orchestrate.DESTRUCTIVE_RESET_FLAGS for f in body.flags)
    if destructive and not body.confirm:
        raise HTTPException(status_code=409,
                            detail="destructive reset requires confirm=true")
    _audit("reset", f"{' '.join(body.flags)} confirm={body.confirm}")
    res = await _mutate(orchestrate.reset, body.flags, body.confirm)
    return res
