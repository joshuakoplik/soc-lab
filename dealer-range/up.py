#!/usr/bin/env python3
"""
Resolve one OR MORE "dealer's choice" targets into a lab-adapted docker compose
under .run/, all on the internal soclab-dealer bridge.

Target(s) come from argv[1] or $DEALER_TARGET as a space/comma-separated list;
each is either a Vulhub path ("<software>/<CVE>") or a plain docker image ref.

Single target  -> the original rewrite: every service on soclab-dealer, the
                  externally-facing one aliased to a random opaque hostname
                  (recon-from-zero), siblings reachable by their compose name.
Multiple targets -> MERGE them into one compose. Multi-target mode supports
                  SINGLE-CONTAINER targets only (the common Vulhub RCE shape):
                  each becomes one service with an opaque container_name + its
                  own opaque hostname alias on soclab-dealer, service keys
                  namespaced per target so two targets that both call a service
                  "app"/"db" don't collide. A multi-container target in a
                  multi-target list is SKIPPED with a warning (its intra-target
                  DNS would collide on the shared bridge).

state.json is ALWAYS a LIST of {target,kind,primary_service,hostname,source}
now (a one-element list for a single target) -- consumers (lab_modes
_dealer_hostnames, wire.py plant_flag, lab-mode.sh status) read the list.
"""
import glob
import json
import os
import secrets
import string
import subprocess
import sys

try:
    import yaml
except ImportError:
    sys.exit("[dealer] PyYAML is required (it's in requirements.txt / the venv)")

HERE = os.path.dirname(os.path.abspath(__file__))
CACHE = os.path.join(HERE, ".cache", "vulhub")
RUN = os.path.join(HERE, ".run")
DEALER_NET = "soclab-dealer"


def rand_host():
    """A meaningless, DNS-valid hostname (starts with a letter). Recon-from-zero:
    docker reverse-DNS returns the container NAME, so a name derived from the
    software/mode would leak it; an opaque random name leaks nothing."""
    return secrets.choice(string.ascii_lowercase) + "".join(
        secrets.choice(string.ascii_lowercase + string.digits) for _ in range(7)
    )


def die(msg, code=2):
    print(f"[dealer] {msg}", file=sys.stderr)
    sys.exit(code)


def warn(msg):
    print(f"[dealer] {msg}", file=sys.stderr)


def find_compose(d):
    for name in ("docker-compose.yml", "docker-compose.yaml", "compose.yml", "compose.yaml"):
        p = os.path.join(d, name)
        if os.path.isfile(p):
            return p
    return None


def _image_exists_locally(ref):
    """True if `ref` is a docker image already present in the local daemon."""
    try:
        r = subprocess.run(["docker", "image", "inspect", ref],
                           stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=15)
        return r.returncode == 0
    except (OSError, subprocess.SubprocessError):
        return False


def resolve(target):
    """(kind, compose_file, source_dir) for a Vulhub path, or ('image', None, None)."""
    cand = os.path.normpath(os.path.join(CACHE, target))
    if cand.startswith(CACHE + os.sep) and os.path.isdir(cand):
        cf = find_compose(cand)
        if cf:
            return ("vulhub", cf, cand)
        die(f"'{target}' is a Vulhub directory but has no docker-compose file")
    # A docker image already present locally (e.g. a target-designer build,
    # soclab-td/<id>) is an IMAGE target, not a Vulhub path -- check the daemon
    # before treating a "/"-containing ref as "software/CVE", which would
    # otherwise wrongly die() below.
    if _image_exists_locally(target):
        return ("image", None, None)
    if "/" in target and os.path.isdir(CACHE):
        top = target.split("/")[0]
        near = sorted(
            os.path.relpath(os.path.dirname(p), CACHE)
            for p in glob.glob(os.path.join(CACHE, top, "*", "docker-compose.y*ml"))
        )
        hint = ("\n  under " + top + "/: " + ", ".join(near[:10])) if near else ""
        die(f"no Vulhub target '{target}' in the cache (try `make refresh`, or check the path){hint}")
    return ("image", None, None)


def load_target(target):
    """(kind, compose_dict, source_dir)."""
    kind, cf, srcdir = resolve(target)
    if kind == "image":
        return ("image", {"services": {"app": {"image": target, "restart": "no"}}}, HERE)
    with open(cf) as f:
        return (kind, yaml.safe_load(f) or {}, srcdir)


def _abs_build(svc, srcdir):
    b = svc.get("build")
    if isinstance(b, str):
        svc["build"] = {"context": os.path.normpath(os.path.join(srcdir, b))}
    elif isinstance(b, dict) and "context" in b and not os.path.isabs(b["context"]):
        b["context"] = os.path.normpath(os.path.join(srcdir, b["context"]))


def _abs_volumes(svc, srcdir):
    vols = svc.get("volumes")
    if not isinstance(vols, list):
        return
    out = []
    for v in vols:
        if isinstance(v, str) and ":" in v:
            host, rest = v.split(":", 1)
            if host.startswith((".", "/", "~")):
                if not os.path.isabs(host):
                    host = os.path.normpath(os.path.join(srcdir, host))
                out.append(f"{host}:{rest}")
            else:
                out.append(v)   # named volume -- left as-is (rare for single-container)
        else:
            out.append(v)
    svc["volumes"] = out


def rewrite_single(doc):
    """Single-target: mutate compose in place; return (primary, hostname)."""
    services = doc.get("services") or {}
    if not services:
        die("source compose has no services")
    primary = next((n for n, s in services.items() if s.get("ports")), None)
    if primary is None:
        primary = next(iter(services))
    hostname = rand_host()
    for name, svc in services.items():
        svc.pop("ports", None)
        svc.pop("network_mode", None)
        svc.pop("container_name", None)
        if name == primary:
            svc["container_name"] = hostname
            aliases = [hostname]
        else:
            svc["container_name"] = rand_host()
            aliases = [name]
        svc["networks"] = {DEALER_NET: {"aliases": aliases}}
    doc["services"] = services
    doc["networks"] = {DEALER_NET: {"external": True}}
    doc.pop("version", None)
    return primary, hostname


def build_multi(targets):
    """Merge SINGLE-CONTAINER targets onto soclab-dealer. Returns (doc, state)."""
    services = {}
    state = []
    for i, target in enumerate(targets):
        kind, doc, srcdir = load_target(target)
        svcs = doc.get("services") or {}
        if len(svcs) != 1:
            warn(f"SKIP '{target}': {len(svcs)} services -- multi-target mode is single-container only")
            continue
        name, svc = next(iter(svcs.items()))
        hostname = rand_host()
        svc.pop("ports", None)
        svc.pop("network_mode", None)
        svc.pop("container_name", None)
        svc.pop("depends_on", None)   # single service -> nothing to depend on
        _abs_build(svc, srcdir)
        _abs_volumes(svc, srcdir)
        svc["container_name"] = hostname
        svc["networks"] = {DEALER_NET: {"aliases": [hostname]}}
        services[f"t{i}_{name}"] = svc
        state.append({"target": target, "kind": kind, "primary_service": name,
                      "hostname": hostname, "source": target})
        print(f"[dealer] + '{target}' ({kind}) -> opaque '{hostname}' on {DEALER_NET}")
    if not services:
        die("no usable single-container targets in the list")
    doc = {"services": services, "networks": {DEALER_NET: {"external": True}}}
    return doc, state


def main():
    raw = (sys.argv[1] if len(sys.argv) > 1 else os.environ.get("DEALER_TARGET", "")).strip()
    if not raw:
        die("no target given (set DEALER_TARGET or pass one/more as arguments)")
    targets = raw.replace(",", " ").split()

    os.makedirs(RUN, exist_ok=True)
    if len(targets) == 1:
        kind, doc, srcdir = load_target(targets[0])
        primary, hostname = rewrite_single(doc)
        project_dir = srcdir
        state = [{"target": targets[0], "kind": kind, "primary_service": primary,
                  "hostname": hostname, "source": targets[0]}]
        print(f"[dealer] target={targets[0]} ({kind}); service '{primary}' reachable only "
              f"as opaque '{hostname}' on {DEALER_NET}")
    else:
        doc, state = build_multi(targets)
        project_dir = HERE   # every build context / bind mount is absolutized in build_multi
        print(f"[dealer] {len(state)} target(s) merged onto {DEALER_NET}")

    with open(os.path.join(RUN, "compose.yml"), "w") as f:
        yaml.safe_dump(doc, f, sort_keys=False)
    with open(os.path.join(RUN, "project_dir"), "w") as f:
        f.write(project_dir + "\n")
    with open(os.path.join(RUN, "state.json"), "w") as f:
        json.dump(state, f, indent=2)   # ALWAYS a list now
    print(f"[dealer] wrote .run/compose.yml (project_dir={project_dir})")


if __name__ == "__main__":
    main()
