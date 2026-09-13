#!/usr/bin/env python3
"""
Resolve a "dealer's choice" target into a lab-adapted docker compose under .run/.

Target comes from argv[1] or $DEALER_TARGET, in one of two forms:
  - a Vulhub path, "<software>/<CVE-id>" -> reads
    .cache/vulhub/<path>/docker-compose.y*ml (Vulhub = github.com/vulhub/vulhub,
    the docker analog of VulnHub; the cache is a shallow clone, see the Makefile).
  - a plain docker image ref, "org/image:tag" -> synthesizes a one-service compose.

The source compose is rewritten to run on the lab's INTERNAL `soclab-dealer`
bridge (see pipeline/net_topology.py):
  - every host `ports:` mapping is stripped (nothing is exposed off the bridge);
  - every service is put on `soclab-dealer` -- Docker still provides
    service-name DNS on a user-defined network, so app<->db comms are preserved
    (and other services are reachable by IP for lateral movement, which is
    realistic);
  - the externally-facing service (the one that HAD published ports) gets the
    network alias `target`, so soc-attacker reaches it as `target.soclab-dealer`
    exactly the way it resolves stock targets (executor.resolve_target_ip()).

No model, no discovery, no random selection -- the target is chosen by the
operator/assistant at invocation (see lab-mode.sh). Writes:
  .run/compose.yml    the rewritten compose
  .run/project_dir    base dir for docker compose --project-directory (so a
                      Vulhub env's relative build/volume paths still resolve)
  .run/state.json     what's up, for the operator/`lab-mode.sh status` (never
                      surfaced to the agent -- dealer's choice is recon-from-zero)
"""
import glob
import json
import os
import secrets
import string
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
    """A meaningless, DNS-valid hostname (starts with a letter). Recon-from-zero
    means the agent must learn what the box is by probing it, not from its name:
    docker's reverse-DNS hands back a container's NAME (confirmed: `getent hosts
    <ip>` returned `dealer-range-n8n-1.soclab-dealer`), so a name derived from the
    Vulhub service (`n8n`) or the mode (`dealer`) leaks both the software AND the
    fact that this is a disposable lab. An opaque random name leaks neither."""
    return secrets.choice(string.ascii_lowercase) + "".join(
        secrets.choice(string.ascii_lowercase + string.digits) for _ in range(7)
    )


def die(msg, code=2):
    print(f"[dealer] {msg}", file=sys.stderr)
    sys.exit(code)


def find_compose(d):
    for name in ("docker-compose.yml", "docker-compose.yaml", "compose.yml", "compose.yaml"):
        p = os.path.join(d, name)
        if os.path.isfile(p):
            return p
    return None


def resolve(target):
    """(kind, compose_file, source_dir) for a Vulhub path, or ('image', None, None)."""
    cand = os.path.normpath(os.path.join(CACHE, target))
    if cand.startswith(CACHE + os.sep) and os.path.isdir(cand):
        cf = find_compose(cand)
        if cf:
            return ("vulhub", cf, cand)
        die(f"'{target}' is a Vulhub directory but has no docker-compose file")
    if "/" in target and os.path.isdir(CACHE):
        # A path-shaped target that isn't in the cache -- help with near matches.
        top = target.split("/")[0]
        near = sorted(
            os.path.relpath(os.path.dirname(p), CACHE)
            for p in glob.glob(os.path.join(CACHE, top, "*", "docker-compose.y*ml"))
        )
        hint = ("\n  under " + top + "/: " + ", ".join(near[:10])) if near else ""
        die(f"no Vulhub target '{target}' in the cache (try `make refresh`, or check the path){hint}")
    # Not a Vulhub path -- treat it as a docker image reference.
    return ("image", None, None)


def rewrite(doc):
    """Mutate a loaded compose dict in place; return (primary service name,
    opaque hostname the primary answers to)."""
    services = doc.get("services") or {}
    if not services:
        die("source compose has no services")
    primary = next((n for n, s in services.items() if s.get("ports")), None)
    if primary is None:
        primary = next(iter(services))
    hostname = rand_host()              # what soc-attacker reaches the target as
    for name, svc in services.items():
        svc.pop("ports", None)          # no host exposure
        svc.pop("network_mode", None)   # would conflict with our networks: block
        svc.pop("container_name", None)  # source may hard-code a leaky name
        # Every service gets an OPAQUE container_name so reverse-DNS of the box
        # leaks nothing (docker's PTR answers with the container name). The
        # primary -- the one the attacker reaches -- answers to the random
        # `hostname` and NOTHING else (no compose service name like "n8n", no
        # "target": both would give away software / lab identity for free).
        # Non-primary services keep their compose-service-name alias, because the
        # app resolves its db/cache by that name internally, but still get an
        # opaque container_name of their own. (Edge case: a source compose whose
        # primary is dialed BY NAME by a sibling would need its name kept -- rare
        # for the ports/ingress service; such a target just won't come up and the
        # operator picks another, same as an image that won't boot.)
        if name == primary:
            svc["container_name"] = hostname
            aliases = [hostname]
        else:
            svc["container_name"] = rand_host()
            aliases = [name]
        svc["networks"] = {DEALER_NET: {"aliases": aliases}}
    doc["services"] = services
    doc["networks"] = {DEALER_NET: {"external": True}}
    doc.pop("version", None)            # obsolete key -> silence the warning
    return primary, hostname


def main():
    target = (sys.argv[1] if len(sys.argv) > 1 else os.environ.get("DEALER_TARGET", "")).strip()
    if not target:
        die("no target given (set DEALER_TARGET or pass one as an argument)")

    kind, cf, srcdir = resolve(target)
    if kind == "image":
        doc = {"services": {"app": {"image": target, "restart": "no"}}}
        project_dir = HERE
    else:
        with open(cf) as f:
            doc = yaml.safe_load(f) or {}
        project_dir = srcdir

    primary, hostname = rewrite(doc)

    os.makedirs(RUN, exist_ok=True)
    with open(os.path.join(RUN, "compose.yml"), "w") as f:
        yaml.safe_dump(doc, f, sort_keys=False)
    with open(os.path.join(RUN, "project_dir"), "w") as f:
        f.write(project_dir + "\n")
    # `hostname` is the ONLY thing the agent is told about the box (via
    # lab_modes.active_config()["targets"], which reads it back from here); the
    # rest of state.json is operator-only. `target` is the Vulhub path the
    # operator chose, NOT anything the agent sees.
    with open(os.path.join(RUN, "state.json"), "w") as f:
        json.dump({"target": target, "kind": kind, "primary_service": primary,
                   "hostname": hostname, "source": cf or target,
                   "project_dir": project_dir}, f, indent=2)

    print(f"[dealer] target={target} ({kind}); service '{primary}' reachable only as "
          f"opaque '{hostname}' on {DEALER_NET}")
    print(f"[dealer] wrote .run/compose.yml (project_dir={project_dir})")


if __name__ == "__main__":
    main()
