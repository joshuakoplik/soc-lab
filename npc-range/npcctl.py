#!/usr/bin/env python3
"""npcctl -- manage NPC flocks.

An NPC is a benign, fully-patched, functional-but-shallow service (web server,
database, cache, ...) that you'd find in any cloud environment. A *flock* is a
plausible collection of them, instantiated from a template onto the ACTIVE lab
mode's docker bridge, right next to the real target. Flocks exist to be noise
and distraction for both agents: the attacker must tell decoys from the real
(intentionally-vulnerable) targets on its own, and the defender sees a realistic
mix of hosts rather than only attack telemetry.

Design mirrors dealer-range/ and northwind-range/: a self-contained range with
its own Makefile and its own .run/ state, that the repo root only ever drives
through `make -C npc-range` (lab-mode.sh status). NPCs attach to an existing
external net_topology bridge (pipeline/net_topology.py) -- no new subnet, no
published ports.

Leak rule (recon-from-zero): docker reverse-DNS returns a container's NAME, so
each NPC's container_name IS its plausible hostname (hr-wiki-01), and flock
membership lives only in docker labels. Nothing reachable by the attacker may
say npc/decoy/flock/lure/honey. See README.md.

Telemetry: NPC logs are tailed to logs/fleet/<hostname>.log, wazuh reads them
via a permanent wildcard <localfile> (wazuh/ossec.conf); only Wazuh/Suricata
*alerts* ever reach soc.db -- never raw logs. The defender also gets an `assets`
inventory row per NPC (CMDB-style, no decoy marker), surfaced by enrich_ip.
"""
import argparse
import json
import os
import re
import secrets
import signal
import string
import subprocess
import sys
import time

try:
    import yaml
except ImportError:
    sys.exit("[npcctl] PyYAML is required (it's in requirements.txt / the venv)")

HERE = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.dirname(HERE)
LIBRARY = os.path.join(HERE, "library")
TEMPLATES = os.path.join(HERE, "templates")
TRAFFIC_DIR = os.path.join(HERE, "traffic")
RUN = os.path.join(HERE, ".run")
FLEET_LOGDIR = os.path.join(REPO, "logs", "fleet")
SOC_DB = os.path.join(REPO, "soc.db")
FLAGS_PRESENT = os.path.join(RUN, "flags-present.json")

sys.path.insert(0, os.path.join(REPO, "pipeline"))
import net_topology  # noqa: E402

PROJECT_PREFIX = "npc-"
LABEL_FLOCK = "com.soclab.flock"
LABEL_TYPE = "com.soclab.type"
LABEL_ROLE = "com.soclab.role"
LABEL_KIND = "com.soclab.kind"   # "npc" | "client" -- operator-only (labels aren't attacker-visible)

FLAG_FMT = "FLAG{{{}}}"  # FLAG{...}


def log(msg):
    print(f"[npcctl] {msg}", file=sys.stderr)


def die(msg, code=2):
    log(msg)
    sys.exit(code)


def run(cmd, timeout=120, check=False):
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
    except (subprocess.TimeoutExpired, OSError) as e:
        if check:
            die(f"command failed: {' '.join(cmd)}: {e}")
        return subprocess.CompletedProcess(cmd, 1, "", str(e))
    if check and r.returncode != 0:
        die(f"command failed ({r.returncode}): {' '.join(cmd)}\n{r.stderr}")
    return r


# --------------------------------------------------------------------------
# Library / template loading
# --------------------------------------------------------------------------
def load_type(type_name):
    path = os.path.join(LIBRARY, type_name, "npc.yaml")
    if not os.path.isfile(path):
        die(f"unknown NPC type {type_name!r} (no {path})")
    with open(path) as f:
        t = yaml.safe_load(f) or {}
    t.setdefault("type", type_name)
    return t


def load_all_types():
    out = {}
    if not os.path.isdir(LIBRARY):
        return out
    for name in sorted(os.listdir(LIBRARY)):
        if os.path.isfile(os.path.join(LIBRARY, name, "npc.yaml")):
            out[name] = load_type(name)
    return out


def load_template(name):
    path = os.path.join(TEMPLATES, name + ".yaml")
    if not os.path.isfile(path):
        die(f"unknown template {name!r} (no {path})")
    with open(path) as f:
        return yaml.safe_load(f) or {}


def load_all_templates():
    out = {}
    if not os.path.isdir(TEMPLATES):
        return out
    for fn in sorted(os.listdir(TEMPLATES)):
        if fn.endswith(".yaml"):
            out[fn[:-5]] = load_template(fn[:-5])
    return out


# --------------------------------------------------------------------------
# .run state
# --------------------------------------------------------------------------
def flock_dir(flock):
    return os.path.join(RUN, flock)


def load_manifest(flock):
    p = os.path.join(flock_dir(flock), "manifest.json")
    if not os.path.isfile(p):
        return None
    with open(p) as f:
        return json.load(f)


def all_manifests():
    out = []
    if not os.path.isdir(RUN):
        return out
    for name in sorted(os.listdir(RUN)):
        m = load_manifest(name)
        if m:
            out.append(m)
    return out


def used_hostnames():
    """Every NPC + client hostname already claimed by a running flock -- so a
    second flock of the same template gets hr-wiki-03/04 rather than colliding
    on a docker container_name (which must be globally unique)."""
    names = set()
    for m in all_manifests():
        for h in m.get("hosts", []):
            names.add(h["hostname"])
        for c in m.get("clients", []):
            names.add(c["hostname"])
    return names


# --------------------------------------------------------------------------
# Network resolution
# --------------------------------------------------------------------------
def resolve_network(arg):
    """arg is a mode key (easy/hard/wordpress/dealer), a compose network name
    (soclab-easy), or None -> caller supplies the template default."""
    for net in net_topology.LAB_NETWORKS:
        if arg == net.mode or arg == net.compose_name:
            return net
    die(f"no lab network for {arg!r} (modes: "
        f"{', '.join(n.mode for n in net_topology.LAB_NETWORKS)})")


# --------------------------------------------------------------------------
# Rendering
# --------------------------------------------------------------------------
def _gen_secret():
    return secrets.token_hex(12)


def _resolve_env(env, secret):
    out = {}
    for k, v in (env or {}).items():
        if isinstance(v, str) and v == "{secret}":
            out[k] = secret
        else:
            out[k] = v
    return out


def allocate_hostnames(template, scale, taken):
    """-> list of host dicts (pre-IP): hostname, type, role, team.
    Numbers continue past any already-claimed hostname of the same role."""
    hosts = []
    counters = {}
    for inst in template.get("instances", []):
        typ = inst["type"]
        role = inst["role"]
        team = inst.get("team", "")
        count = int(inst.get("count", 1)) * scale.get(typ, 1)
        n = counters.get(role, 0)
        made = 0
        while made < count:
            n += 1
            hostname = f"{role}-{n:02d}"
            if hostname in taken:
                continue
            taken.add(hostname)
            hosts.append({"hostname": hostname, "type": typ, "role": role, "team": team})
            made += 1
        counters[role] = n
    return hosts


def allocate_clients(template, n_clients, taken):
    teams = template.get("teams") or ["corp"]
    clients = []
    counter = 0
    for i in range(n_clients):
        team = teams[i % len(teams)].lower()
        while True:
            counter += 1
            hostname = f"ws-{team}-{counter:02d}"
            if hostname not in taken:
                break
        taken.add(hostname)
        clients.append({"hostname": hostname, "team": team})
    return clients


def render_compose(flock, template, net, hosts, clients, types):
    """Build the docker-compose dict + the manifest host/client records."""
    services = {}
    host_records = []
    role_to_host = {h["role"]: h for h in hosts}   # first instance of a role
    edges = template.get("edges", [])

    for h in hosts:
        hostname = h["hostname"]
        t = types[h["type"]]
        secret = _gen_secret()
        svc = {
            "container_name": hostname,
            "hostname": hostname,
            "restart": "unless-stopped",
            "labels": {LABEL_FLOCK: flock, LABEL_TYPE: h["type"],
                       LABEL_ROLE: h["role"], LABEL_KIND: "npc"},
            "networks": {net.compose_name: {"aliases": [hostname]}},
        }
        if "build" in t:
            svc["build"] = {"context": os.path.join(LIBRARY, h["type"], t["build"])}
        else:
            svc["image"] = t["image"]
        if "command" in t:
            svc["command"] = t["command"]

        env = _resolve_env(t.get("env"), secret)
        # East-west deps: this host's edges -> the dependency's hostname in the
        # env var its type declares (depends_env), so the app resolves its
        # backends by their real in-flock DNS names.
        depends_env = t.get("depends_env") or {}
        for edge in edges:
            if edge.get("from") == h["role"]:
                dep = role_to_host.get(edge.get("to"))
                if dep and dep["type"] in depends_env:
                    env[depends_env[dep["type"]]] = dep["hostname"]
        if env:
            svc["environment"] = env

        volumes = []
        for cf in t.get("config_files", []):
            volumes.append(f"{os.path.join(LIBRARY, h['type'], cf['src'])}:{cf['dst']}:ro")
        for cf in t.get("init_files", []):
            volumes.append(f"{os.path.join(LIBRARY, h['type'], cf['src'])}:{cf['dst']}:ro")
        if volumes:
            svc["volumes"] = volumes

        services[hostname] = svc

        asset = t.get("asset", {})
        cmdb = (asset.get("cmdb_desc", "{hostname}")
                .replace("{hostname}", hostname)
                .replace("{team}", h.get("team", "")))
        host_records.append({
            "hostname": hostname, "type": h["type"], "role": h["role"],
            "team": h.get("team", ""), "ip": None,
            "services": asset.get("services", []),
            "log": {"file": os.path.join("logs", "fleet", hostname + ".log"),
                    "prefix": t.get("log", {}).get("prefix", "syslog"),
                    "program": t.get("log", {}).get("program", hostname),
                    "origin": t.get("log", {}).get("origin", "stdout")},
            "asset_desc": cmdb,
            "asset_role": asset.get("role", ""),
        })

    # Workstation clients (profile-gated; started only by `traffic start`).
    client_records = []
    server_hostnames = [h["hostname"] for h in hosts]
    for c in clients:
        hostname = c["hostname"]
        behaviors = sorted({b for h in hosts
                            for b in types[h["type"]].get("traffic", {}).get("client_behaviors", [])})
        targets = [{"hostname": h["hostname"], "type": h["type"],
                    "behaviors": types[h["type"]].get("traffic", {}).get("client_behaviors", [])}
                   for h in hosts]
        services[hostname] = {
            "build": {"context": TRAFFIC_DIR},
            "container_name": hostname,
            "hostname": hostname,
            "restart": "unless-stopped",
            "profiles": ["traffic"],
            "labels": {LABEL_FLOCK: flock, LABEL_KIND: "client"},
            "environment": {"CLIENT_HOSTNAME": hostname},
            "volumes": [f"{os.path.join(flock_dir(flock), 'manifest.json')}:/manifest.json:ro"],
            "networks": {net.compose_name: {"aliases": [hostname]}},
        }
        client_records.append({"hostname": hostname, "team": c["team"],
                               "behaviors": behaviors, "targets": server_hostnames})

    doc = {"services": services,
           "networks": {net.compose_name: {"external": True}}}
    return doc, host_records, client_records


# --------------------------------------------------------------------------
# docker helpers
# --------------------------------------------------------------------------
def compose_base(flock):
    return ["docker", "compose", "-p", PROJECT_PREFIX + flock,
            "-f", os.path.join(flock_dir(flock), "compose.yml"),
            "--project-directory", HERE]


def inspect_ips(flock, net, hostnames):
    """container_name -> IP on this flock's network."""
    out = {}
    for name in hostnames:
        r = run(["docker", "inspect", "-f",
                 "{{ (index .NetworkSettings.Networks \"" + net.compose_name + "\").IPAddress }}",
                 name])
        ip = r.stdout.strip()
        out[name] = ip or None
    return out


# --------------------------------------------------------------------------
# Tailers (log leg) -- mirrors dealer-range/wire.py:spawn_tailer/teardown
# --------------------------------------------------------------------------
def tailers_path(flock):
    return os.path.join(flock_dir(flock), "tailers.json")


def spawn_tailers(flock, host_records):
    os.makedirs(FLEET_LOGDIR, exist_ok=True)
    recorded = []
    for h in host_records:
        hostname = h["hostname"]
        sink = os.path.join(FLEET_LOGDIR, hostname + ".log")
        p = subprocess.Popen(
            [sys.executable, os.path.abspath(__file__), "_tail",
             hostname, h["log"]["program"], h["log"]["prefix"], sink, hostname],
            stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL, start_new_session=True)
        recorded.append({"pid": p.pid, "container": hostname, "hostname": hostname,
                         "file": sink})
        log(f"tailer pid={p.pid}: {hostname} -> logs/fleet/{hostname}.log ({h['log']['prefix']})")
    with open(tailers_path(flock), "w") as f:
        json.dump(recorded, f, indent=2)
    return recorded


def cmd_tail(hostname, program, prefix, sink, cid):
    """Detached child: tail one container's stdout, optionally syslog-prefix each
    line, append to the per-host fleet file wazuh globs. Runs until killed."""
    proc = subprocess.Popen(["docker", "logs", "-f", "--tail", "0", cid],
                            stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                            text=True, bufsize=1)

    def _bye(*_):
        try:
            proc.terminate()
        except Exception:
            pass
        sys.exit(0)
    signal.signal(signal.SIGTERM, _bye)

    with open(sink, "a") as f:
        for line in proc.stdout:
            line = line.rstrip("\n")
            if prefix == "syslog":
                ts = time.strftime("%b %e %H:%M:%S")
                out = f"{ts} {hostname} {program}: {line}"
            else:
                out = line
            f.write(out + "\n")
            f.flush()


def teardown_tailers(flock):
    path = tailers_path(flock)
    if not os.path.isfile(path):
        return
    with open(path) as f:
        recorded = json.load(f)
    for t in recorded:
        pid = t.get("pid")
        if not pid:
            continue
        try:
            os.killpg(os.getpgid(pid), signal.SIGTERM)
        except Exception:
            try:
                os.kill(pid, signal.SIGTERM)
            except Exception:
                pass
    # Remove the per-host fleet files so the flock leaves no telemetry residue.
    for t in recorded:
        try:
            os.remove(t["file"])
        except OSError:
            pass


# --------------------------------------------------------------------------
# assets table (defender inventory). Infrastructure-asserted; CMDB-style,
# NO decoy marker. Defensive CREATE so npcctl works even against a soc.db that
# hasn't had triage/schema.sql applied yet (Phase 3 adds the canonical DDL).
# --------------------------------------------------------------------------
ASSETS_DDL = """
CREATE TABLE IF NOT EXISTS assets (
  id          INTEGER PRIMARY KEY AUTOINCREMENT,
  ip          TEXT,
  hostname    TEXT NOT NULL,
  role        TEXT,
  services    TEXT,
  owner_team  TEXT,
  flock       TEXT,
  network     TEXT,
  updated     TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_assets_ip ON assets(ip);
CREATE INDEX IF NOT EXISTS idx_assets_hostname ON assets(hostname);
"""


def _db():
    import sqlite3
    conn = sqlite3.connect(SOC_DB)
    conn.executescript(ASSETS_DDL)
    return conn


def write_assets(manifest):
    if not os.path.isfile(SOC_DB):
        log("soc.db not found -- skipping asset inventory (run the pipeline first)")
        return
    conn = _db()
    try:
        flock = manifest["flock"]
        net = manifest["network"]["compose_name"]
        now = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
        conn.execute("DELETE FROM assets WHERE flock=?", (flock,))
        for h in manifest["hosts"]:
            conn.execute(
                "INSERT INTO assets (ip, hostname, role, services, owner_team, flock, network, updated) "
                "VALUES (?,?,?,?,?,?,?,?)",
                (h.get("ip"), h["hostname"], h.get("asset_role") or h.get("asset_desc"),
                 json.dumps(h.get("services", [])), h.get("team"), flock, net, now))
        conn.commit()
        log(f"wrote {len(manifest['hosts'])} asset rows for {flock}")
    finally:
        conn.close()


def delete_assets(flock):
    if not os.path.isfile(SOC_DB):
        return
    conn = _db()
    try:
        conn.execute("DELETE FROM assets WHERE flock=?", (flock,))
        conn.commit()
    finally:
        conn.close()


# --------------------------------------------------------------------------
# flags-present marker (operator->harness; count only, never location)
# --------------------------------------------------------------------------
def rewrite_flags_present():
    """Aggregate planted-flag counts by network across all flocks -> the
    count-only marker the red-team prompt reads. Never contains hosts/paths."""
    counts = {}
    for m in all_manifests():
        n = m["network"]["compose_name"]
        fdir = flock_dir(m["flock"])
        fp = os.path.join(fdir, "flags.json")
        if os.path.isfile(fp):
            with open(fp) as f:
                flags = json.load(f)
            counts[n] = counts.get(n, 0) + len(flags)
    os.makedirs(RUN, exist_ok=True)
    with open(FLAGS_PRESENT, "w") as f:
        json.dump(counts, f, indent=2)


# --------------------------------------------------------------------------
# Commands
# --------------------------------------------------------------------------
def cmd_types(_args):
    types = load_all_types()
    if not types:
        print("(no types in library/)")
        return
    for name, t in types.items():
        img = t.get("image") or ("build:" + t.get("build", "?"))
        print(f"{name:22} {t.get('weight',''):7} {img}")


def cmd_templates(_args):
    for name, tpl in load_all_templates().items():
        insts = tpl.get("instances", [])
        n = sum(int(i.get("count", 1)) for i in insts)
        print(f"{name:18} {n:2d} hosts, {tpl.get('default_clients',0)} clients "
              f"[{tpl.get('network_default','?')}]  -- {tpl.get('description','')}")


def _parse_scale(pairs):
    scale = {}
    for p in pairs or []:
        if "=" not in p:
            die(f"--scale expects type=N, got {p!r}")
        k, v = p.split("=", 1)
        scale[k] = int(v)
    return scale


def cmd_up(args):
    template = load_template(args.template)
    types = load_all_types()
    for inst in template.get("instances", []):
        if inst["type"] not in types:
            die(f"template {args.template} references unknown type {inst['type']!r}")

    net = resolve_network(args.network or template.get("network_default"))
    flock = args.name or f"{args.template}-{secrets.token_hex(2)}"
    if load_manifest(flock):
        die(f"flock {flock!r} already exists (down it first, or pass --name)")

    scale = _parse_scale(args.scale)
    n_clients = args.clients if args.clients is not None else int(template.get("default_clients", 0))

    taken = used_hostnames()
    hosts = allocate_hostnames(template, scale, taken)
    clients = allocate_clients(template, n_clients, taken)

    fdir = flock_dir(flock)
    os.makedirs(fdir, exist_ok=True)
    doc, host_records, client_records = render_compose(flock, template, net, hosts, clients, types)

    with open(os.path.join(fdir, "compose.yml"), "w") as f:
        yaml.safe_dump(doc, f, sort_keys=False)

    manifest = {
        "flock": flock, "template": args.template,
        "network": {"mode": net.mode, "compose_name": net.compose_name,
                    "subnet": str(net.subnet)},
        "created": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "hosts": host_records, "clients": client_records,
        "edges": template.get("edges", []),
    }
    with open(os.path.join(fdir, "manifest.json"), "w") as f:
        json.dump(manifest, f, indent=2)

    log(f"bringing up flock {flock!r} ({len(hosts)} NPCs) on {net.compose_name} ...")
    run(net_topology_bootstrap_cmd(), check=False)  # ensure the bridge exists
    r = run(compose_base(flock) + ["up", "-d", "--build"], timeout=600)
    if r.returncode != 0:
        die(f"docker compose up failed:\n{r.stdout}\n{r.stderr}")

    ips = inspect_ips(flock, net, [h["hostname"] for h in host_records])
    for h in manifest["hosts"]:
        h["ip"] = ips.get(h["hostname"])
    with open(os.path.join(fdir, "manifest.json"), "w") as f:
        json.dump(manifest, f, indent=2)

    spawn_tailers(flock, host_records)
    write_assets(manifest)

    if args.flags:
        plant_flags(flock, manifest, types, args.flags)
    rewrite_flags_present()

    _warn_if_sensors_down()
    log(f"flock {flock!r} up. Hosts:")
    for h in manifest["hosts"]:
        print(f"    {h['hostname']:20} {h['type']:18} {h['ip'] or '?'}")
    if client_records:
        log(f"{len(client_records)} workstation client(s) defined; start traffic with: "
            f"npcctl traffic start {flock}")


def cmd_down(args):
    flocks = [m["flock"] for m in all_manifests()] if args.all else [args.flock]
    if not flocks or flocks == [None]:
        die("down: pass a flock name or --all")
    for flock in flocks:
        m = load_manifest(flock)
        if not m:
            log(f"no such flock {flock!r}, skipping")
            continue
        log(f"tearing down {flock!r} ...")
        teardown_tailers(flock)
        run(compose_base(flock) + ["--profile", "traffic", "down", "-v"], timeout=300)
        delete_assets(flock)
        import shutil
        shutil.rmtree(flock_dir(flock), ignore_errors=True)
        log(f"{flock!r} down.")
    rewrite_flags_present()


def cmd_status(_args):
    reconcile_all()
    manifests = all_manifests()
    if not manifests:
        print("(no flocks up)")
        return
    for m in manifests:
        flock = m["flock"]
        net = m["network"]["compose_name"]
        r = run(["docker", "ps", "--filter", f"label={LABEL_FLOCK}={flock}",
                 "--format", "{{.Names}}\t{{.Status}}"])
        running = [ln for ln in r.stdout.splitlines() if ln.strip()]
        print(f"== {flock}  (template={m['template']}, net={net}, "
              f"{len(m['hosts'])} NPCs, {len(m.get('clients', []))} clients) ==")
        for ln in running:
            print("   " + ln.replace("\t", "  "))
        if not running:
            print("   (no containers running -- `up` again or check docker)")


def cmd_reconcile(_args):
    reconcile_all()
    log("assets reconciled from manifests")


def reconcile_all():
    """Re-assert asset rows from every manifest (they're recreated empty by
    reset.sh --db, so this is how they survive a DB wipe) and refresh the
    flags-present marker."""
    for m in all_manifests():
        write_assets(m)
    rewrite_flags_present()


# --------------------------------------------------------------------------
# Flag planting (Phase 6 fleshes out placements; core here)
# --------------------------------------------------------------------------
def plant_flags(flock, manifest, types, flag_specs):
    """flag_specs: list of "type" or "type:placement_index". Plants one flag per
    spec on the FIRST host of that type, recording host+path operator-side in
    flags.json (never surfaced to the agent)."""
    planted = []
    by_type = {}
    for h in manifest["hosts"]:
        by_type.setdefault(h["type"], []).append(h)
    for spec in flag_specs:
        typ = spec.split(":", 1)[0]
        idx = int(spec.split(":", 1)[1]) if ":" in spec else 0
        t = types.get(typ)
        if not t or not t.get("flag", {}).get("supported"):
            log(f"type {typ!r} does not support flags, skipping")
            continue
        hosts = by_type.get(typ)
        if not hosts:
            log(f"no {typ!r} host in this flock, skipping flag")
            continue
        placements = t["flag"].get("placements", [])
        if idx >= len(placements):
            log(f"{typ!r} has no placement #{idx}, skipping")
            continue
        host = hosts[0]
        placement = placements[idx]
        value = FLAG_FMT.format(secrets.token_hex(8))
        ok = _apply_flag(host["hostname"], placement, value)
        if ok:
            planted.append({"flag": value, "hostname": host["hostname"],
                            "type": typ, "placement": placement})
            log(f"planted flag on {host['hostname']} ({placement.get('kind')})")
    with open(os.path.join(flock_dir(flock), "flags.json"), "w") as f:
        json.dump(planted, f, indent=2)
    return planted


def _apply_flag(container, placement, value):
    kind = placement.get("kind")
    if kind == "file":
        dst = placement["dst"]
        parent = os.path.dirname(dst)
        run(["docker", "exec", container, "sh", "-c", f"mkdir -p {parent}"])
        return _exec_stdin(container, ["sh", "-c", f"cat > {dst}"], value + "\n")
    if kind == "pg_row":
        table = placement.get("table", "config_secrets")
        col = placement.get("column", "value")
        keycol = placement.get("keycol", "key")
        keyval = placement.get("keyval", "backup_key")
        sql = (f"INSERT INTO config_secrets ({keycol},{col}) VALUES "
               f"('{keyval}','{value}') ON CONFLICT ({keycol}) DO UPDATE SET {col}=EXCLUDED.{col};")
        r = run(["docker", "exec", container, "psql", "-U", "appro", "-d", "appdb",
                 "-c", sql], timeout=30)
        return r.returncode == 0
    if kind == "redis_key":
        key = placement.get("key", "app:secret")
        r = run(["docker", "exec", container, "redis-cli", "SET", key, value], timeout=30)
        return r.returncode == 0
    log(f"unknown flag placement kind {kind!r}")
    return False


def _exec_stdin(container, argv, data):
    try:
        p = subprocess.run(["docker", "exec", "-i", container] + argv,
                           input=data, text=True, capture_output=True, timeout=30)
        return p.returncode == 0
    except (subprocess.TimeoutExpired, OSError):
        return False


def cmd_flags(args):
    m = load_manifest(args.flock)
    if not m:
        die(f"no such flock {args.flock!r}")
    fp = os.path.join(flock_dir(args.flock), "flags.json")
    if not os.path.isfile(fp):
        print("(no flags planted in this flock)")
        return
    with open(fp) as f:
        flags = json.load(f)
    for fl in flags:
        print(f"{fl['flag']}  on {fl['hostname']} ({fl['type']}, {fl['placement'].get('kind')})")


def cmd_traffic(args):
    m = load_manifest(args.flock)
    if not m:
        die(f"no such flock {args.flock!r}")
    if args.action == "start":
        if not m.get("clients"):
            die(f"flock {args.flock!r} has no workstation clients (up with --clients N)")
        log(f"starting traffic for {args.flock!r} ({len(m['clients'])} clients) ...")
        r = run(compose_base(args.flock) + ["--profile", "traffic", "up", "-d", "--build"],
                timeout=600)
        if r.returncode != 0:
            die(f"traffic start failed:\n{r.stdout}\n{r.stderr}")
        log("traffic running.")
    else:
        log(f"stopping traffic for {args.flock!r} ...")
        run(compose_base(args.flock) + ["--profile", "traffic", "rm", "-sf"], timeout=300)
        log("traffic stopped.")


def cmd_pull(_args):
    """Refresh every library image to its current stable tag -- 'fully patched'."""
    images = sorted({t["image"] for t in load_all_types().values() if t.get("image")})
    for img in images:
        log(f"pull {img}")
        run(["docker", "pull", img], timeout=600)
    log(f"pulled {len(images)} image(s). Rebuild custom images with: npcctl build")


def cmd_build(_args):
    """Build the custom images (types with a `build:` context) + the traffic
    client image, so they exist before a flock/traffic comes up."""
    for name, t in load_all_types().items():
        if "build" in t:
            ctx = os.path.join(LIBRARY, name, t["build"])
            log(f"build {name} ({ctx})")
            run(["docker", "build", "-t", f"npc-{name}", ctx], timeout=600)
    log(f"build traffic client ({TRAFFIC_DIR})")
    run(["docker", "build", "-t", "npc-traffic", TRAFFIC_DIR], timeout=600)
    log("build complete.")


# --------------------------------------------------------------------------
# misc helpers
# --------------------------------------------------------------------------
def net_topology_bootstrap_cmd():
    return [sys.executable, os.path.join(REPO, "pipeline", "net_topology.py"), "--bootstrap"]


def _warn_if_sensors_down():
    r = run(["docker", "ps", "--format", "{{.Names}}"])
    names = set(r.stdout.split())
    for svc in ("soc-wazuh", "soc-suricata"):
        if svc not in names:
            log(f"WARNING: {svc} is not running -- the defender will be blind to this flock "
                f"until sensors are up (see CLAUDE.md; lab-mode.sh does not start them).")


# --------------------------------------------------------------------------
def main():
    ap = argparse.ArgumentParser(prog="npcctl", description="manage NPC flocks")
    sub = ap.add_subparsers(dest="cmd", required=True)

    sub.add_parser("types").set_defaults(func=cmd_types)
    sub.add_parser("templates").set_defaults(func=cmd_templates)

    up = sub.add_parser("up")
    up.add_argument("template")
    up.add_argument("--name")
    up.add_argument("--network")
    up.add_argument("--scale", action="append", help="type=N (repeatable)")
    up.add_argument("--clients", type=int)
    up.add_argument("--flags", action="append",
                    help="type[:placement_index] to plant a flag on (repeatable)")
    up.set_defaults(func=cmd_up)

    dn = sub.add_parser("down")
    dn.add_argument("flock", nargs="?")
    dn.add_argument("--all", action="store_true")
    dn.set_defaults(func=cmd_down)

    sub.add_parser("status").set_defaults(func=cmd_status)
    sub.add_parser("reconcile").set_defaults(func=cmd_reconcile)

    fl = sub.add_parser("flags")
    fl.add_argument("flock")
    fl.set_defaults(func=cmd_flags)

    tr = sub.add_parser("traffic")
    tr.add_argument("action", choices=["start", "stop"])
    tr.add_argument("flock")
    tr.set_defaults(func=cmd_traffic)

    sub.add_parser("pull").set_defaults(func=cmd_pull)
    sub.add_parser("build").set_defaults(func=cmd_build)

    # internal: the detached per-container tailer child
    ta = sub.add_parser("_tail")
    ta.add_argument("hostname")
    ta.add_argument("program")
    ta.add_argument("prefix")
    ta.add_argument("sink")
    ta.add_argument("cid")
    ta.set_defaults(func=lambda a: cmd_tail(a.hostname, a.program, a.prefix, a.sink, a.cid))

    args = ap.parse_args()
    args.func(args)


if __name__ == "__main__":
    main()
