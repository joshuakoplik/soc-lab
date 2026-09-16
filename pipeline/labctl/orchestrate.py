"""The single implementation of every lab ACTION.

labctl complements the existing scripts rather than replacing them: each function
here shells out to the canonical tool (lab-mode.sh / reset.sh / npc-range Makefile
/ detect-rules) with cwd pinned to the repo root, so those scripts stay the one
definition of how the lab comes up -- and still work standalone. The Phase-2
dashboard router imports and calls THIS module; it never reimplements an action.

cwd is always config.ROOT (never the caller's cwd): nested compose projects mean a
stale cwd can point `docker compose down` at the wrong stack (a known trap), so we
never rely on the ambient working directory.
"""

import json
import os
import subprocess

from . import config, procman, signals, state

LAB_MODE_SH = os.path.join(config.ROOT, "lab-mode.sh")
RESET_SH = os.path.join(config.ROOT, "reset.sh")
NPC_DIR = os.path.join(config.ROOT, "npc-range")

VALID_MODES = ("easy", "hard", "wordpress", "northwind", "dealer")
# Destructive reset flags that must not run without an explicit confirm.
DESTRUCTIVE_RESET_FLAGS = {"--db", "--all"}


def _run(argv, timeout=600):
    """Run a command from the repo root, capturing text. Returns a result dict
    -- never raises on a non-zero exit (the caller inspects `rc`)."""
    try:
        p = subprocess.run(
            argv,
            cwd=config.ROOT,
            capture_output=True,
            text=True,
            timeout=timeout,
        )
        return {"rc": p.returncode, "stdout": p.stdout, "stderr": p.stderr, "argv": argv}
    except subprocess.TimeoutExpired as e:
        return {"rc": 124, "stdout": e.stdout or "", "stderr": f"timed out after {timeout}s", "argv": argv}
    except (OSError, ValueError) as e:
        return {"rc": 127, "stdout": "", "stderr": str(e), "argv": argv}


# --------------------------------------------------------------------------- #
# lab_mode.json (read-only here; only lab-mode.sh writes it)
# --------------------------------------------------------------------------- #

def read_lab_mode():
    try:
        with open(config.LAB_MODE_JSON) as f:
            d = json.load(f)
        return d if isinstance(d, dict) else {}
    except (FileNotFoundError, json.JSONDecodeError, OSError):
        return {}


# --------------------------------------------------------------------------- #
# Mode lifecycle -> lab-mode.sh
# --------------------------------------------------------------------------- #

def lab_mode(verb, mode=None, target=None, timeout=600):
    """Delegate to ./lab-mode.sh <verb> [mode] [target]. verb in
    up|down|switch|status|bootstrap|posture. Reconciles the process registry
    afterward (a switch can churn containers, not our procs, but stay honest)."""
    argv = [LAB_MODE_SH, verb]
    if mode:
        argv.append(mode)
    if target:
        argv.append(target)
    res = _run(argv, timeout=timeout)
    state.reconcile()
    return res


# --------------------------------------------------------------------------- #
# Reset -> reset.sh  (destructive flags gated on an explicit confirm)
# --------------------------------------------------------------------------- #

def reset(flags, confirm=False, timeout=600):
    """Delegate to ./reset.sh <flags...>. Any flag in DESTRUCTIVE_RESET_FLAGS
    (a DB wipe) requires confirm=True; otherwise refused without running. reset.sh
    itself kills the pipeline procs it needs to, so we reconcile afterward to prune
    what it killed and re-adopt the dashboard it relaunched."""
    flags = list(flags or [])
    if any(f in DESTRUCTIVE_RESET_FLAGS for f in flags) and not confirm:
        return {"rc": 1, "stdout": "", "stderr": "refused: destructive reset needs confirm=True",
                "argv": [RESET_SH, *flags]}
    res = _run([RESET_SH, *flags], timeout=timeout)
    state.reconcile()
    return res


def clean(what="hunt", confirm=False):
    """Convenience: `labctl clean --hunt` (default, non-destructive to events) or
    `--db` (destructive, needs confirm). Just a friendly front to reset()."""
    flag = "--db" if what == "db" else "--hunt"
    return reset([flag], confirm=confirm)


# --------------------------------------------------------------------------- #
# NPC flocks -> npc-range Makefile
# --------------------------------------------------------------------------- #

def flock(action, template=None, name=None, network=None, extra_vars=None, timeout=600):
    """Delegate to `make -C npc-range <target> [VARS]`.
    action: up (needs template) | down (needs name, or all) | status | reconcile.
    """
    if action == "up":
        if not template:
            return {"rc": 1, "stdout": "", "stderr": "flock up needs a template", "argv": []}
        argv = ["make", "-C", NPC_DIR, "up", f"TEMPLATE={template}"]
        if network:
            argv.append(f"NETWORK={network}")
    elif action == "down":
        if name in (None, "", "--all", "all"):
            argv = ["make", "-C", NPC_DIR, "down-all"]
        else:
            argv = ["make", "-C", NPC_DIR, "down", f"FLOCK={name}"]
    elif action in ("status", "reconcile"):
        argv = ["make", "-C", NPC_DIR, action]
    else:
        return {"rc": 1, "stdout": "", "stderr": f"unknown flock action: {action}", "argv": []}
    for kv in (extra_vars or []):
        argv.append(kv)
    return _run(argv, timeout=timeout)


# --------------------------------------------------------------------------- #
# Detection -> one-shot detect/rules.py (there is no scheduler in-repo)
# --------------------------------------------------------------------------- #

def detect_once(timeout=300):
    """Run pipeline/detect/rules.py once. The supervisor calls this on an interval
    so `candidates` keep flowing without a manual cron. Uses the same interpreter
    labctl runs under (detect is stdlib-only)."""
    import sys
    return _run([sys.executable, "pipeline/detect/rules.py"], timeout=timeout)


# --------------------------------------------------------------------------- #
# Composite status
# --------------------------------------------------------------------------- #

def _process_view():
    data = state.reconcile()
    out = {}
    for name in config.MANAGED:
        ent = data.get(name)
        out[name] = {
            "up": bool(ent),
            "pid": ent.get("pid") if ent else None,
            "adopted": ent.get("adopted", False) if ent else False,
            "argv": ent.get("argv") if ent else None,
            "log": ent.get("log") if ent else None,
        }
    return out


def supervisor_state():
    pid = state.live_pid("supervisor")
    return {"up": bool(pid), "pid": pid}


def status(include_docker=True, docker_timeout=60):
    """The composite lab-status dict consumed by `labctl status --json` and the
    dashboard Lab tab. Structured process/signal/mode data always; the (slower)
    docker+flock text view only when include_docker is set."""
    lm = read_lab_mode()
    cfg = config.load()
    out = {
        "mode": lm.get("mode"),
        "posture": lm.get("posture"),
        "switched_at": lm.get("switched_at"),
        "processes": _process_view(),
        "supervisor": supervisor_state(),
        "signals": signals.summary(),
        "policies": {k: cfg[k] for k in cfg if k.startswith("policy_")},
        "config": {
            "idle_timeout": cfg["idle_timeout"],
            "attack_drain_max": cfg["attack_drain_max"],
            "poll_interval": cfg["poll_interval"],
            "detect_interval": cfg["detect_interval"],
            "hunter_provider": cfg["hunter_provider"],
            "hunter_model": cfg["hunter_model"],
        },
    }
    if include_docker:
        res = lab_mode("status", timeout=docker_timeout)
        out["lab_status_text"] = res.get("stdout", "") + (
            ("\n[stderr]\n" + res["stderr"]) if res.get("stderr") else ""
        )
    return out
