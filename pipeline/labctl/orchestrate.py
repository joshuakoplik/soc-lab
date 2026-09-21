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

DEALER_CACHE = os.path.join(config.ROOT, "dealer-range", ".cache", "vulhub")
# Locally-built target-designer targets (committed spec.json + Dockerfile). These
# surface in the dealer catalog alongside Vulhub entries -- a designed image is a
# plain image ref the dealer path already accepts (see dealer-range/up.py resolve).
DESIGNED_TARGETS_DIR = os.path.join(config.ROOT, "target-designer", "targets")
NPC_TEMPLATES_DIR = os.path.join(NPC_DIR, "templates")
NPC_RUN_DIR = os.path.join(NPC_DIR, ".run")

# A few well-known Vulhub targets to seed the dealer combo box when the local
# cache isn't cloned yet. Suggestions only -- the field stays free-text, since
# "dealer's choice" is the whole open-ended Vulhub catalog (software/CVE or a
# docker image ref), not a fixed list.
DEALER_SUGGESTIONS = (
    "struts2/CVE-2017-5638",
    "spring/CVE-2022-22965",
    "weblogic/CVE-2019-2725",
    "fastjson/1.2.24-rce",
    "gitlab/CVE-2021-22205",
    "httpd/CVE-2021-41773",
    "log4j/CVE-2021-44228",
    "couchdb/CVE-2017-12635",
)


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
    elif action in ("traffic-start", "traffic-stop"):
        if not name:
            return {"rc": 1, "stdout": "", "stderr": f"flock {action} needs a flock name", "argv": []}
        argv = ["make", "-C", NPC_DIR, action, f"FLOCK={name}"]
    elif action in ("status", "reconcile"):
        argv = ["make", "-C", NPC_DIR, action]
    else:
        return {"rc": 1, "stdout": "", "stderr": f"unknown flock action: {action}", "argv": []}
    for kv in (extra_vars or []):
        argv.append(kv)
    return _run(argv, timeout=timeout)


# --------------------------------------------------------------------------- #
# Enumeration for the dashboard pickers (flock templates, live flocks, the
# dealer/Vulhub catalog). All stdlib filesystem reads -- cheap, no subprocess.
# --------------------------------------------------------------------------- #

def list_flock_templates():
    """NPC flock template names (npc-range/templates/*.yaml, minus extension)."""
    names = []
    try:
        for f in os.listdir(NPC_TEMPLATES_DIR):
            if f.endswith(".yaml"):
                names.append(f[:-5])
            elif f.endswith(".yml"):
                names.append(f[:-4])
    except OSError:
        return []
    return sorted(set(names))


def list_live_flocks():
    """Names of live flocks -- npc-range/.run/<flock>/manifest.json dirs."""
    out = []
    try:
        for name in os.listdir(NPC_RUN_DIR):
            d = os.path.join(NPC_RUN_DIR, name)
            if os.path.isdir(d) and os.path.exists(os.path.join(d, "manifest.json")):
                out.append(name)
    except OSError:
        pass
    return sorted(out)


def flocks_status():
    """Per live flock: {name, clients, traffic}. `clients` is how many workstation
    clients the flock was created with (manifest); `traffic` is whether their
    containers (compose profile 'traffic', label com.soclab.kind=client) are
    currently running -- i.e. the benign traffic generator is on. One `docker ps`
    for all flocks; skipped entirely when no flocks are live."""
    names = list_live_flocks()
    if not names:
        return []
    flocks = {}
    for name in names:
        clients = 0
        try:
            with open(os.path.join(NPC_RUN_DIR, name, "manifest.json")) as f:
                clients = len(json.load(f).get("clients", []))
        except (OSError, json.JSONDecodeError, ValueError):
            pass
        flocks[name] = {"name": name, "clients": clients, "traffic": False}
    res = _run(["docker", "ps", "--filter", "label=com.soclab.kind=client",
                "--format", "{{.Labels}}"], timeout=15)
    if res["rc"] == 0:
        for line in res["stdout"].splitlines():
            for kv in line.split(","):
                if kv.startswith("com.soclab.flock="):
                    fl = kv.split("=", 1)[1].strip()
                    if fl in flocks:
                        flocks[fl]["traffic"] = True
    return [flocks[n] for n in names]


_catalog_cache = {"mtime": None, "data": None}


def _read_readme_meta(entry_dir):
    """(title, description) pulled from an entry's README, best-effort. Vulhub
    ships README.md (English) + README.zh-cn.md; prefer the English one."""
    for fname in ("README.md", "README.en.md", "readme.md"):
        path = os.path.join(entry_dir, fname)
        if not os.path.exists(path):
            continue
        try:
            with open(path, encoding="utf-8", errors="replace") as f:
                text = f.read()
        except OSError:
            return None, None
        title, desc = None, None
        for line in text.splitlines():
            s = line.strip()
            if not s:
                continue
            if s.startswith("#"):
                if title is None:
                    title = s.lstrip("#").strip()
                continue
            if title is not None and desc is None and not s.startswith(("![", "[!", "|", ">", "-", "*")):
                desc = s
                break
        if desc:
            desc = (desc[:240] + "…") if len(desc) > 240 else desc
        return title, desc
    return None, None


def _designed_catalog_entries():
    """target-designer targets as dealer catalog entries. Cheap dir-walk, not
    memoized (the catalog is small). `target` is the image ref you stand up with
    `up dealer <target>`; `image_built` says whether it's present locally now
    (rebuild a missing one with `designer.py --from-spec <id>`)."""
    entries = []
    if not os.path.isdir(DESIGNED_TARGETS_DIR):
        return entries
    for tid in sorted(os.listdir(DESIGNED_TARGETS_DIR)):
        specp = os.path.join(DESIGNED_TARGETS_DIR, tid, "spec.json")
        if not os.path.exists(specp):
            continue
        try:
            with open(specp) as f:
                s = json.load(f)
        except (OSError, json.JSONDecodeError):
            continue
        tag = (s.get("extra") or {}).get("image_tag") or f"soclab-td/{s.get('id', tid)}:latest"
        fh = (s.get("foothold") or {}).get("cve", "")
        pe = (s.get("privesc") or {}).get("cve", "")
        built = _image_present(tag)
        entries.append({
            "target": tag,
            "kind": "designed",
            "software": "target-designer",
            "cve": f"{fh}->{pe}" if pe else fh,
            "title": s.get("title", s.get("id", tid)),
            "description": (s.get("difficulty_notes") or "")[:200],
            "image_built": built,
            "created_at": s.get("created_at", ""),
        })
    entries.sort(key=lambda e: e["created_at"], reverse=True)
    return entries


def _image_present(ref):
    try:
        r = subprocess.run(["docker", "image", "inspect", ref],
                           stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=15)
        return r.returncode == 0
    except (OSError, subprocess.SubprocessError):
        return False


def dealer_catalog(force=False):
    """The dealer catalog: locally-built target-designer targets FIRST (freshest,
    most relevant), then the Vulhub catalog from the local cache. Each entry:
    {target, kind, software, cve, title, description, ...}. `cached` reflects the
    Vulhub clone; designed targets are always available. See _vulhub_catalog for
    the Vulhub half."""
    vh = _vulhub_catalog(force)
    designed = _designed_catalog_entries()
    vh_entries = [{**e, "kind": "vulhub"} for e in vh["entries"]]
    entries = designed + vh_entries
    return {"cached": vh["cached"], "count": len(entries),
            "designed": len(designed), "entries": entries}


def _vulhub_catalog(force=False):
    """The Vulhub catalog available in the local cache, with light metadata.

    Returns {cached, count, entries:[{target, software, cve, title, description}]}.
    `cached` is False when the shallow Vulhub clone hasn't been fetched yet --
    the UI then offers a 'fetch catalog' action (fetch_dealer_catalog). Memoized
    on the cache dir's mtime so repeated opens of the picker are instant."""
    if not os.path.isdir(DEALER_CACHE):
        return {"cached": False, "count": 0, "entries": []}
    try:
        mtime = os.path.getmtime(DEALER_CACHE)
    except OSError:
        mtime = None
    if not force and _catalog_cache["data"] is not None and _catalog_cache["mtime"] == mtime:
        return _catalog_cache["data"]

    entries = []
    try:
        softwares = sorted(os.listdir(DEALER_CACHE))
    except OSError:
        softwares = []
    for software in softwares:
        if software.startswith("."):
            continue
        sw_dir = os.path.join(DEALER_CACHE, software)
        if not os.path.isdir(sw_dir):
            continue
        try:
            subs = sorted(os.listdir(sw_dir))
        except OSError:
            continue
        for sub in subs:
            entry_dir = os.path.join(sw_dir, sub)
            if not os.path.isdir(entry_dir):
                continue
            if not (os.path.exists(os.path.join(entry_dir, "docker-compose.yml"))
                    or os.path.exists(os.path.join(entry_dir, "docker-compose.yaml"))):
                continue
            title, desc = _read_readme_meta(entry_dir)
            entries.append({
                "target": f"{software}/{sub}",
                "software": software,
                "cve": sub,
                "title": title or f"{software} {sub}",
                "description": desc or "",
            })
    data = {"cached": True, "count": len(entries), "entries": entries}
    _catalog_cache["mtime"] = mtime
    _catalog_cache["data"] = data
    return data


def fetch_dealer_catalog(timeout=1200):
    """Shallow-clone the Vulhub catalog into the dealer cache (make -C
    dealer-range cache). Slow (a git clone); run under the mutate lock. Invalidates
    the in-memory catalog memo so the next dealer_catalog() re-walks."""
    res = _run(["make", "-C", "dealer-range", "cache"], timeout=timeout)
    _catalog_cache["mtime"] = None
    _catalog_cache["data"] = None
    return res


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
        "flocks": flocks_status(),
        "signals": signals.summary(),
        "policies": {k: cfg[k] for k in cfg if k.startswith("policy_")},
        "config": {
            "idle_timeout": cfg["idle_timeout"],
            "attack_drain_max": cfg["attack_drain_max"],
            "poll_interval": cfg["poll_interval"],
            "detect_interval": cfg["detect_interval"],
            "hunter_provider": cfg["hunter_provider"],
            "hunter_model": cfg["hunter_model"],
            "analyst_provider": cfg["analyst_provider"],
            "analyst_model": cfg["analyst_model"],
        },
    }
    if include_docker:
        res = lab_mode("status", timeout=docker_timeout)
        out["lab_status_text"] = res.get("stdout", "") + (
            ("\n[stderr]\n" + res["stderr"]) if res.get("stderr") else ""
        )
    return out
