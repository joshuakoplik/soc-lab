"""Managed-process registry -- labctl's memory of what it launched.

Persisted to .labctl/state.json (gitignored). One entry per managed process:
{name: {pid, argv, log, started, adopted}}. There are no PID files elsewhere in
this repo for the agents (only jobs.py has a flock, for a different concern), so
this is the authority for "is the hunter/ingest/dashboard running and which PID".

Liveness is checked the way reset.sh already does it (reset.sh:412-421): read
/proc/<pid>/cmdline and confirm the expected pattern is still there. A bare
os.kill(pid, 0) is not enough -- PIDs get reused, and reset.sh's `pkill -f` can
kill a process out from under us, after which a reused PID could look "alive" but
be something unrelated. The cmdline check closes that.

reconcile() is the load-bearing call: every labctl invocation runs it so the
registry never lies. It (1) drops entries whose PID is dead or no longer matches,
and (2) ADOPTS a live, matching process that isn't in the registry -- so a
hand-started hunter, or the dashboard that reset.sh relaunched from /proc, is
still seen and controllable. This is what keeps labctl consistent with the fact
that reset.sh will happily kill and relaunch these processes behind its back.
"""

import json
import os
import time

from . import config

# How to recognise each managed process in /proc/<pid>/cmdline. A process counts
# as this managed name iff EVERY token here appears in its cmdline. Kept narrow
# enough that the hunter isn't mistaken for the attacker, etc.
PATTERNS = {
    "dashboard": ("dashboard/server.py",),
    "ingest": ("pipeline/ingest.py", "--follow"),
    "hunter": ("pipeline/hunt/agent.py",),
    "attacker": ("pipeline/redteam/agent.py",),
    # The supervisor is manageable (start/stop, adopt-on-scan) but is NOT in
    # config.MANAGED -- it's the watcher, not one of the watched daemons, so the
    # keep-alive loop never tries to resurrect itself.
    "supervisor": ("pipeline.labctl", "watch"),
}


def _now():
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())


def proc_argv(pid):
    """The process's argv as a list, or None if it's gone/unreadable. Split on
    the real NUL separators from /proc so an argv[0] check is exact."""
    try:
        with open(f"/proc/{pid}/cmdline", "rb") as f:
            raw = f.read()
    except (FileNotFoundError, ProcessLookupError, PermissionError, OSError):
        return None
    if not raw:
        return None
    parts = raw.split(b"\x00")
    return [p.decode("utf-8", "replace") for p in parts if p]


def proc_cmdline(pid):
    """The process's argv joined by spaces, or None if it's gone/unreadable."""
    argv = proc_argv(pid)
    return " ".join(argv) if argv else None


def _is_python(argv):
    """True if argv[0] is a python interpreter. All managed processes ARE python
    (agents, ingest, dashboard, the supervisor), so requiring this excludes shell
    wrappers whose command string merely MENTIONS the script path -- the same
    false-positive class `pkill -f` suffers, which would otherwise let a `bash -c`
    that references pipeline/hunt/agent.py be adopted as the hunter."""
    if not argv:
        return False
    import os as _os
    return "python" in _os.path.basename(argv[0]).lower()


def matches(pid, name):
    """True if pid is alive, is a python process, AND its cmdline matches managed
    `name`'s pattern (every pattern token present in the joined argv)."""
    argv = proc_argv(pid)
    if not argv or not _is_python(argv):
        return False
    cmd = " ".join(argv)
    return all(tok in cmd for tok in PATTERNS[name])


def find_by_pattern(name):
    """Scan /proc for live PIDs whose cmdline matches managed `name`. Excludes
    this process. Returns lowest-PID-first (oldest-ish) for determinism."""
    hits = []
    mypid = os.getpid()
    try:
        entries = os.listdir("/proc")
    except OSError:
        return hits
    for e in entries:
        if not e.isdigit():
            continue
        pid = int(e)
        if pid == mypid:
            continue
        if matches(pid, name):
            hits.append(pid)
    hits.sort()
    return hits


def load():
    try:
        with open(config.STATE_FILE) as f:
            data = json.load(f)
        return data if isinstance(data, dict) else {}
    except (FileNotFoundError, json.JSONDecodeError, OSError):
        return {}


def save(data):
    os.makedirs(config.STATE_DIR, exist_ok=True)
    tmp = config.STATE_FILE + ".tmp"
    with open(tmp, "w") as f:
        json.dump(data, f, indent=2)
        f.write("\n")
    os.replace(tmp, config.STATE_FILE)


def record(name, pid, argv, log):
    data = load()
    data[name] = {
        "pid": pid,
        "argv": argv,
        "log": log,
        "started": _now(),
        "adopted": False,
    }
    save(data)
    return data[name]


def remove(name):
    data = load()
    if name in data:
        del data[name]
        save(data)


def get(name):
    return load().get(name)


def live_pid(name):
    """The confirmed-live PID for a managed name, else None.

    Prefers the recorded PID if it still matches; otherwise falls back to
    adopting any matching process in /proc. Does NOT mutate the registry --
    reconcile() does that. Use this for a quick 'is it up?' check.
    """
    if name not in PATTERNS:
        return None
    ent = get(name)
    if ent and isinstance(ent.get("pid"), int) and matches(ent["pid"], name):
        return ent["pid"]
    found = find_by_pattern(name)
    return found[0] if found else None


def reconcile():
    """Make the registry match reality. Returns the reconciled dict.

    - Prune entries whose PID is dead or no longer matches the pattern.
    - Adopt a live, matching process that isn't recorded (or whose recorded PID
      died and a fresh one of the same kind exists -- e.g. reset.sh relaunched
      the dashboard). Adopted entries are flagged so `status` can show it.
    """
    data = load()
    changed = False

    # 1. prune stale recorded entries
    for name in list(data.keys()):
        ent = data[name]
        pid = ent.get("pid")
        if not isinstance(pid, int) or not matches(pid, name):
            del data[name]
            changed = True

    # 2. adopt live processes we aren't tracking
    for name in PATTERNS:
        if name in data:
            continue
        found = find_by_pattern(name)
        if found:
            pid = found[0]
            data[name] = {
                "pid": pid,
                "argv": proc_cmdline(pid),
                "log": None,
                "started": _now(),  # unknown; stamp adoption time
                "adopted": True,
            }
            changed = True

    if changed:
        save(data)
    return data
