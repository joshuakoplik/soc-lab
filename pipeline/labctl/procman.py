"""Launch / stop / keep-alive for the processes labctl manages.

Launch shape is copied from the one launcher that already exists in this repo,
pipeline/redteam/jobs.py:518-527: subprocess.Popen(start_new_session=True) with
stdin=DEVNULL and stdout/stderr to a log file. start_new_session (setsid) means
the child leads its own process group and survives labctl exiting -- these are
daemons, not children of the CLI invocation.

Graceful stop = SIGTERM once, wait up to stop_timeout, then SIGKILL. For the
hunter this is exactly the clean drain the agent implements (hunt/agent.py:
first SIGTERM finishes the in-flight chunk, compacts a handoff note, sets
status='stopped', exits; a second signal is immediate) -- so labctl stops the
hunter by SIGTERM and simply waits, and the hunter loses no context. The
analyst responder (analyst/responder.py) has the same contract: first SIGTERM
finishes the in-flight handoff, then exits.

Interpreter policy: agents and ingest launch under the SAME interpreter labctl
runs (sys.executable) -- the top-level `labctl` wrapper prefers .venv/bin/python3,
which carries the provider SDKs. The dashboard is special: it needs fastapi/
uvicorn, so it launches under the venv interpreter explicitly and is pointed at
this checkout's soc.db via SOC_DASHBOARD_DB (mirrors reset.sh's relaunch).
"""

import os
import signal
import subprocess
import sys
import time

from . import config, state


def venv_python():
    """The venv interpreter for fastapi/uvicorn work (the dashboard). Falls back
    to the running interpreter, which is already the venv when launched via the
    `labctl` wrapper."""
    cand = os.path.join(config.ROOT, ".venv", "bin", "python3")
    if os.access(cand, os.X_OK):
        return cand
    return sys.executable


def _log_path(name):
    os.makedirs(config.LOG_DIR, exist_ok=True)
    return os.path.join(config.LOG_DIR, f"{name}.log")


def _launch(name, argv, env=None):
    """Spawn a detached process for `name`, record it, return the registry entry."""
    log = _log_path(name)
    logf = open(log, "ab")
    logf.write(
        f"\n===== labctl launched {name} at "
        f"{time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime())} =====\n".encode()
    )
    logf.flush()
    full_env = dict(os.environ)
    if env:
        full_env.update(env)
    proc = subprocess.Popen(
        argv,
        cwd=config.ROOT,
        stdin=subprocess.DEVNULL,
        stdout=logf,
        stderr=subprocess.STDOUT,
        start_new_session=True,
        close_fds=True,
        env=full_env,
    )
    return state.record(name, proc.pid, argv, log)


def _argv_for(name, opts, cfg):
    """Build the launch argv for a managed process. opts is a dict of extras."""
    opts = opts or {}
    py = sys.executable
    if name == "ingest":
        return [py, "pipeline/ingest.py", "--follow"]
    if name == "hunter":
        argv = [
            py, "pipeline/hunt/agent.py",
            "--provider", str(opts.get("provider") or cfg["hunter_provider"]),
        ]
        model = opts.get("model") or cfg["hunter_model"]
        if model:
            argv += ["--model", str(model)]
        argv += [str(a) for a in opts.get("extra", [])]
        return argv
    if name == "analyst":
        argv = [
            py, "pipeline/analyst/agent.py", "--serve",
            "--provider", str(opts.get("provider") or cfg["analyst_provider"]),
        ]
        model = opts.get("model") or cfg["analyst_model"]
        if model:
            argv += ["--model", str(model)]
        argv += [str(a) for a in opts.get("extra", [])]
        return argv
    if name == "attacker":
        argv = [
            py, "pipeline/redteam/agent.py",
            "--provider", str(opts.get("provider") or cfg["hunter_provider"]),
        ]
        model = opts.get("model") or cfg["hunter_model"]
        if model:
            argv += ["--model", str(model)]
        argv += [str(a) for a in opts.get("extra", [])]
        return argv
    if name == "dashboard":
        return [venv_python(), "dashboard/server.py"]
    if name == "supervisor":
        return [py, "-m", "pipeline.labctl", "watch"]
    raise ValueError(f"unknown managed process: {name}")


def _env_for(name):
    if name == "dashboard":
        # Point the dashboard at THIS checkout's soc.db, same file the agents
        # write and the poller serves.
        return {"SOC_DASHBOARD_DB": config.SOC_DB}
    return None


def is_up(name):
    """Confirmed-live PID for name, else None (adopts a matching /proc process)."""
    return state.live_pid(name)


LAUNCH_SETTLE_S = float(os.environ.get("LABCTL_LAUNCH_SETTLE_S", "1.5"))


def _crash_tail(logpath, cap=1500):
    """The tail of a just-crashed process's log (its traceback), for surfacing
    to the operator. Best-effort; returns '' if the log can't be read."""
    if not logpath:
        return ""
    try:
        with open(logpath, "r", errors="replace") as f:
            text = f.read()
    except OSError:
        return ""
    marker = "===== labctl launched"          # only this launch's output
    idx = text.rfind(marker)
    if idx != -1:
        text = text[idx:]
    return text.strip()[-cap:]


def start(name, opts=None, cfg=None, verify=True):
    """Start `name` if it isn't already up. Returns (started: bool, entry).

    When verify (default), wait briefly and confirm the process is still alive:
    a misconfigured or immediately-crashing process (e.g. a DB-locked agent)
    exits within a second, and without this the caller reports a bare "started"
    while the process is already gone. On a fast crash the returned entry gets
    crashed=True and error=<log tail> so the CLI/dashboard can show WHY."""
    if name not in state.PATTERNS:
        raise ValueError(f"unknown managed process: {name}")
    cfg = cfg or config.load()
    pid = is_up(name)
    if pid:
        return False, state.get(name) or {"pid": pid}
    entry = _launch(name, _argv_for(name, opts, cfg), _env_for(name))
    if verify:
        time.sleep(LAUNCH_SETTLE_S)
        if is_up(name) is None:            # died during the settle window
            entry = dict(entry)
            entry["crashed"] = True
            entry["error"] = _crash_tail(entry.get("log"))
            state.remove(name)             # it's gone; don't leave a stale entry
    return True, entry


def stop(name, cfg=None):
    """SIGTERM -> wait stop_timeout -> SIGKILL. Returns True if a process was
    signalled. Removes the registry entry once it's gone."""
    cfg = cfg or config.load()
    pid = is_up(name)
    if not pid:
        state.remove(name)
        return False
    _signal(pid, signal.SIGTERM)
    deadline = time.time() + float(cfg["stop_timeout"])
    while time.time() < deadline:
        if not state.matches(pid, name):
            state.remove(name)
            return True
        time.sleep(0.4)
    # still alive -> hard kill
    _signal(pid, signal.SIGKILL)
    time.sleep(0.3)
    state.remove(name)
    return True


def restart(name, opts=None, cfg=None):
    cfg = cfg or config.load()
    stop(name, cfg)
    return start(name, opts, cfg)


def ensure(name, opts=None, cfg=None):
    """Keep-alive: start `name` if it's down. Used by the supervisor. Returns
    True if it had to (re)launch."""
    started, _ = start(name, opts, cfg)
    return started


def _signal(pid, sig):
    """Signal the process, preferring its whole group when it leads one (our
    daemons do, via start_new_session). Never signals labctl's own group."""
    try:
        pgid = os.getpgid(pid)
    except (ProcessLookupError, PermissionError, OSError):
        pgid = None
    try:
        if pgid is not None and pgid == pid and pgid != os.getpgid(0):
            os.killpg(pgid, sig)
        else:
            os.kill(pid, sig)
    except (ProcessLookupError, PermissionError, OSError):
        pass
