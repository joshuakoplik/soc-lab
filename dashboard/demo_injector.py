#!/usr/bin/env python3
"""Scripted attack/defense demo injector for the live dashboard + Attack Map.

Why this exists
---------------
The Attack Map (and the rest of the dashboard) is driven entirely by rows landing
in ``soc.db``: ``dashboard/server.py`` polls the tables in ``TABLES`` and pushes new
rows over one WebSocket; ``dashboard/static/map.js`` turns each row into an
animation (``window.mapConsume(table, row)``). Crucially the map keys its
animations on **which table a row is in plus a few fields** (``pending_actions.tool``/
``target``, ``wins.evidence_tier``, ``chat_actions.kind``, ...) -- it never checks
that any IP matches a real node. So a full attacker+defender story can be told by
*writing rows*, with no agents running and **zero tokens burned**.

This script does exactly that: it seeds the parent rows (a red-team session, a hunt
session, a chat session), then walks a fixed narrative -- recon sweep -> web probes
-> detection -> brute/inject -> exploit -> escalating compromise -> incident -> page
-> block-and-sever -- inserting the row(s) each beat needs, pacing between beats by a
runtime ``--speed`` multiplier. It also drops a *demo topology overlay* that
``orchestrate.map_topology()`` prefers, so the map renders a named target + flock
decoys + subnet (and, in remote posture, a firewall) with **nothing running** -- the
demo is independent of the current lab mode/targets, as intended.

Nothing here touches real infrastructure: ``block_ip_calls`` rows are written with
``executed=0`` (no iptables rule is placed; the enforcer is never called), and every
row carries a marker so ``--clear`` can remove the whole demo cleanly.

Usage
-----
    python3 dashboard/demo_injector.py                 # run the scripted story once
    python3 dashboard/demo_injector.py --speed 3       # 3x faster
    python3 dashboard/demo_injector.py --speed 0.5     # half speed (slow, cinematic)
    python3 dashboard/demo_injector.py --loop          # repeat until Ctrl-C
    python3 dashboard/demo_injector.py --posture insider   # no firewall node
    python3 dashboard/demo_injector.py --clear         # remove all demo rows + overlay
    python3 dashboard/demo_injector.py --list          # print the beat list and exit

Point it at the same DB the dashboard reads (default ./soc.db, or $SOC_DASHBOARD_DB).
Open the dashboard's "Attack Map" tab and run it. Clean up afterwards with --clear
(or a normal ``./reset.sh --db``).
"""

import argparse
import json
import os
import sqlite3
import sys
import time
from datetime import datetime, timezone

# ---- markers so --clear can find exactly what we wrote (and nothing else) ----
DEMO_PROVIDER = "demo-injector"          # redteam/hunt/chat sessions
DEMO_MODEL = "scripted-demo"
DEMO_HOST = "demo-injector"              # events.host
DEMO_DEDUPE_PREFIX = "demo:"             # candidates.dedupe_key

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DEFAULT_DB = os.environ.get("SOC_DASHBOARD_DB") or os.path.join(REPO_ROOT, "soc.db")
OVERLAY_PATH = os.path.join(REPO_ROOT, ".labctl", "map_demo.json")


def now_iso():
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def connect(db_path):
    conn = sqlite3.connect(db_path, timeout=30)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA busy_timeout=30000")
    return conn


# --------------------------------------------------------------------------- #
# Demo topology overlay (read by orchestrate.map_topology when unexpired)      #
# --------------------------------------------------------------------------- #
def demo_topology(subnet, attacker_ip, target_name, target_ip, label, posture, flocks):
    return {
        "mode": "dealer",
        "posture": posture,
        "subnet": subnet,
        "attacker": {"name": "soc-attacker", "ip": attacker_ip},
        "targets": [{"name": target_name, "ip": target_ip, "label": label, "mode": "dealer"}],
        "flocks": flocks,
        "siem": True,
        "firewall": posture == "remote",
        "_demo": True,
    }


def write_overlay(topo, ttl_seconds):
    os.makedirs(os.path.dirname(OVERLAY_PATH), exist_ok=True)
    tmp = OVERLAY_PATH + ".tmp"
    with open(tmp, "w") as f:
        json.dump({"until": time.time() + ttl_seconds, "topology": topo}, f)
    os.replace(tmp, OVERLAY_PATH)


def clear_overlay():
    try:
        os.remove(OVERLAY_PATH)
    except OSError:
        pass


# --------------------------------------------------------------------------- #
# Parent-row seeding                                                           #
# --------------------------------------------------------------------------- #
def seed_sessions(conn, attacker_ip):
    """Create the red-team / hunt / chat parent rows the child rows reference,
    all tagged with the demo markers. Returns (redteam_id, hunt_id, chat_id)."""
    ts = now_iso()
    cur = conn.cursor()
    rt = cur.execute(
        "INSERT INTO redteam_sessions (started, provider, model, attacker_ip, stage, status, created) "
        "VALUES (?,?,?,?,?,?,?)",
        (ts, DEMO_PROVIDER, DEMO_MODEL, attacker_ip, "recon", "running", ts),
    ).lastrowid
    hunt = cur.execute(
        "INSERT INTO hunt_sessions (started, provider, model, lab_mode, status, created, updated) "
        "VALUES (?,?,?,?,?,?,?)",
        (ts, DEMO_PROVIDER, DEMO_MODEL, "dealer", "running", ts, ts),
    ).lastrowid
    chat = cur.execute(
        "INSERT INTO chat_sessions (started, provider, model, lab_mode, status, title, hunt_id, created, updated) "
        "VALUES (?,?,?,?,?,?,?,?,?)",
        (ts, DEMO_PROVIDER, DEMO_MODEL, "dealer", "active", "Demo incident response", hunt, ts, ts),
    ).lastrowid
    conn.commit()
    return rt, hunt, chat


# --------------------------------------------------------------------------- #
# Row emitters -- one per animation the map understands                        #
# --------------------------------------------------------------------------- #
class Emitter:
    def __init__(self, conn, ctx):
        self.conn = conn
        self.c = ctx  # dict: rt/hunt/chat ids, ips, names
        self._seq = 0  # monotonic, for globally-unique candidate dedupe keys

    def _commit(self):
        self.conn.commit()

    def event(self, source, event_type, **cols):
        ts = now_iso()
        base = {"ts": ts, "source": source, "host": DEMO_HOST, "event_type": event_type}
        base.update(cols)
        base["raw"] = json.dumps({"_demo": True, "source": source, "event_type": event_type, **cols})
        keys = ",".join(base)
        qs = ",".join("?" * len(base))
        self.conn.execute(f"INSERT INTO events ({keys}) VALUES ({qs})", tuple(base.values()))
        self._commit()

    def attacker_action(self, tool, target, command=""):
        ts = now_iso()
        self.conn.execute(
            "INSERT INTO pending_actions (session_id, tool, target, input_json, rationale, "
            "approved, approved_by, executed, created) VALUES (?,?,?,?,?,?,?,?,?)",
            (self.c["rt"], tool, target, json.dumps({"command": command} if command else {}),
             "demo", 1, "auto-whitelist", 1, ts),
        )
        self._commit()

    def recon_finding(self, target, finding_type, detail, tool="nmap_scan"):
        ts = now_iso()
        self.conn.execute(
            "INSERT INTO recon_findings (session_id, target, finding_type, detail, source_tool, created) "
            "VALUES (?,?,?,?,?,?)",
            (self.c["rt"], target, finding_type, json.dumps(detail), tool, ts),
        )
        self._commit()

    def win(self, description, tier):
        ts = now_iso()
        score = {"unconfirmed": 0.1, "vuln_identified": 0.4,
                 "exploit_confirmed": 0.7, "shell_or_creds": 1.0}.get(tier, 0.0)
        self.conn.execute(
            "INSERT INTO wins (session_id, description, evidence_tier, evidence_score, created) "
            "VALUES (?,?,?,?,?)",
            (self.c["rt"], description, tier, score, ts),
        )
        self._commit()

    def candidate(self, key_suffix, rule, severity, evidence, detail=None):
        ts = now_iso()
        # candidates.dedupe_key is UNIQUE -- make it globally unique per insert
        # (session id + monotonic seq) so re-runs and --loop passes don't collide
        # (a fixed "demo:portscan" crashes on the 2nd pass). Still LIKE 'demo:%'
        # so --clear finds it.
        self._seq += 1
        dedupe_key = f"{DEMO_DEDUPE_PREFIX}{key_suffix}:{self.c['rt']}:{self._seq}"
        cur = self.conn.execute(
            "INSERT INTO candidates (dedupe_key, rule, severity, src_ip, first_seen, last_seen, "
            "event_count, evidence, detail, status, created, updated) "
            "VALUES (?,?,?,?,?,?,?,?,?,?,?,?)",
            (dedupe_key, rule, severity, self.c["attacker_ip"], ts, ts,
             1, evidence, json.dumps(detail or {}), "new", ts, ts),
        )
        self._commit()
        return cur.lastrowid

    def incident(self, title, severity, hypothesis, summary):
        ts = now_iso()
        cur = self.conn.execute(
            "INSERT INTO incidents (hunt_id, title, status, severity, entity, hypothesis, summary, "
            "opened_at, updated_at) VALUES (?,?,?,?,?,?,?,?,?)",
            (self.c["hunt"], title, "open", severity, self.c["attacker_ip"], hypothesis, summary, ts, ts),
        )
        self._commit()
        return cur.lastrowid

    def set_incident_status(self, incident_id, status):
        ts = now_iso()
        closed = ts if status in ("contained", "closed", "false_positive") else None
        self.conn.execute(
            "UPDATE incidents SET status=?, updated_at=?, closed_at=COALESCE(?, closed_at) WHERE id=?",
            (status, ts, closed, incident_id),
        )
        self._commit()

    def chat_action(self, kind, src_ip=None, reason="", incident_id=None):
        ts = now_iso()
        self.conn.execute(
            "INSERT INTO chat_actions (session_id, incident_id, kind, src_ip, reason, executed, created) "
            "VALUES (?,?,?,?,?,?,?)",
            (self.c["chat"], incident_id, kind, src_ip, reason, 0, ts),
        )
        self._commit()

    def block_ip_call(self, candidate_id, src_ip, reason, incident_id=None):
        # executed=0: this is a *demo* row -- no iptables rule is placed, the
        # enforcer is never invoked. The map animates on the row regardless.
        ts = now_iso()
        self.conn.execute(
            "INSERT INTO block_ip_calls (candidate_id, src_ip, reason, executed, "
            "result_json, incident_id, created) VALUES (?,?,?,?,?,?,?)",
            (candidate_id, src_ip, reason, 0,
             json.dumps({"demo": True, "note": "no real rule placed"}), incident_id, ts),
        )
        self._commit()

    def human_page(self, candidate_id, reason, incident_id=None):
        ts = now_iso()
        self.conn.execute(
            "INSERT INTO human_pages (candidate_id, reason, incident_id, created) VALUES (?,?,?,?)",
            (candidate_id, reason, incident_id, ts),
        )
        self._commit()

    def set_stage(self, stage):
        self.conn.execute("UPDATE redteam_sessions SET stage=? WHERE id=?", (stage, self.c["rt"]))
        self._commit()


# --------------------------------------------------------------------------- #
# The scripted narrative                                                       #
# --------------------------------------------------------------------------- #
# Each beat: (gap_seconds_before, label, fn(emitter)). gap is scaled by 1/speed.
def build_script(ctx):
    tgt = ctx["target_name"]
    subnet = ctx["subnet"]
    atk = ctx["attacker_ip"]
    state = {}  # carries ids created mid-story (candidate/incident) across beats

    def reset(e):
        # loop support: drop compromise back to 0 and clear the caption
        e.win("resetting scene", "unconfirmed")

    def nmap(e):
        e.attacker_action("nmap_scan", subnet + "/24")
        e.event("suricata", "ids_alert", src_ip=atk,
                ids_signature="ET SCAN Nmap Scripting Engine", ids_category="Attempted Recon", ids_severity=2)

    def ports(e):
        for p, svc in ((22, "ssh"), (80, "http"), (8080, "http-alt")):
            e.recon_finding(tgt, "port_open", {"port": p, "service": svc})

    def scan_detected(e):
        state["c_scan"] = e.candidate("portscan", "portscan.horizontal", "low",
                                      f"{atk} scanned {subnet}/24 -- 40+ ports in 3s")

    def web1(e):
        e.attacker_action("http_probe", tgt, "GET /")
        e.event("nginx", "http_request", src_ip=atk, http_method="GET", url_path="/", http_status=200)

    def web2(e):
        e.attacker_action("http_probe", tgt, "GET /admin")
        e.event("nginx", "http_request", src_ip=atk, http_method="GET", url_path="/admin", http_status=401)

    def assess(e):
        e.set_stage("assess")
        e.win("identified exposed admin API on target", "vuln_identified")

    def brute(e):
        e.attacker_action("hydra_bruteforce", tgt, "hydra -l admin -P rockyou.txt")
        for u, p in (("admin", "admin"), ("admin", "password"), ("admin", "admin123")):
            e.event("cowrie", "login_attempt", src_ip=atk, username=u, password=p)

    def brute_detected(e):
        state["c_brute"] = e.candidate("bruteforce", "auth.bruteforce", "medium",
                                       f"{atk} -- 200+ failed logins, then success as admin")

    def inject(e):
        e.attacker_action("sqlmap_scan", tgt, "sqlmap -u /api/v1/pages --dump")

    def exploit(e):
        e.attacker_action("shell_exec", tgt, "id")
        e.win("RCE confirmed -- command execution as www-data", "exploit_confirmed")
        e.event("wazuh", "siem_alert", src_ip=atk, siem_rule_id="100210",
                ids_signature="Web shell command execution")

    def exploit_detected(e):
        state["c_rce"] = e.candidate("rce", "exploit.rce", "high",
                                     f"{atk} achieved command execution on {tgt}")

    def incident_open(e):
        state["inc"] = e.incident(
            f"Active intrusion -- {tgt}", "high",
            f"{atk} chained recon -> credential brute -> RCE against {tgt}",
            "Attacker has code execution; escalation in progress. Recommend immediate containment.")

    def escalate(e):
        e.attacker_action("shell_exec", tgt, "cat /etc/shadow")
        e.win("credential theft -- /etc/shadow exfiltrated", "shell_or_creds")

    def alert(e):
        e.chat_action("alert", src_ip=atk, reason="Confirmed intrusion on target",
                      incident_id=state.get("inc"))

    def page(e):
        e.chat_action("page_oncall", src_ip=atk, reason="High-sev active intrusion",
                      incident_id=state.get("inc"))
        cid = state.get("c_rce") or state.get("c_brute") or state.get("c_scan")
        if cid:
            e.human_page(cid, "Active intrusion -- analyst paged", incident_id=state.get("inc"))

    def block(e):
        e.chat_action("block_ip", src_ip=atk, reason=f"Contain {atk}", incident_id=state.get("inc"))
        cid = state.get("c_rce") or state.get("c_brute") or state.get("c_scan")
        if cid:
            e.block_ip_call(cid, atk, f"Contain confirmed intrusion from {atk}",
                            incident_id=state.get("inc"))

    def contained(e):
        if state.get("inc"):
            e.set_incident_status(state["inc"], "contained")

    return [
        (0.0, "recon: nmap sweep", nmap),
        (1.6, "recon: ports discovered", ports),
        (1.4, "detect: scan flagged", scan_detected),
        (2.0, "recon: probe /", web1),
        (1.6, "recon: probe /admin", web2),
        (2.0, "assess: vuln identified", assess),
        (2.2, "exploit: credential brute-force", brute),
        (1.6, "detect: brute-force flagged", brute_detected),
        (2.0, "exploit: SQL injection", inject),
        (2.2, "exploit: RCE confirmed", exploit),
        (1.4, "detect: RCE flagged", exploit_detected),
        (1.6, "hunter: incident opened", incident_open),
        (2.4, "exploit: credential theft", escalate),
        (2.0, "respond: analyst alert", alert),
        (1.8, "respond: page on-call", page),
        (2.0, "respond: block + sever", block),
        (1.6, "respond: incident contained", contained),
    ], reset


# --------------------------------------------------------------------------- #
# --clear                                                                      #
# --------------------------------------------------------------------------- #
def clear_demo(conn):
    cur = conn.cursor()
    rt = [r[0] for r in cur.execute(
        "SELECT id FROM redteam_sessions WHERE provider=?", (DEMO_PROVIDER,))]
    hunt = [r[0] for r in cur.execute(
        "SELECT id FROM hunt_sessions WHERE provider=?", (DEMO_PROVIDER,))]
    chat = [r[0] for r in cur.execute(
        "SELECT id FROM chat_sessions WHERE provider=?", (DEMO_PROVIDER,))]
    cands = [r[0] for r in cur.execute(
        "SELECT id FROM candidates WHERE dedupe_key LIKE ?", (DEMO_DEDUPE_PREFIX + "%",))]

    def inq(ids):
        return "(" + ",".join("?" * len(ids)) + ")", ids

    n = 0

    def wipe(sql, ids):
        nonlocal n
        if not ids:
            return
        ph, vals = inq(ids)
        n += cur.execute(sql.format(ph), vals).rowcount

    wipe("DELETE FROM pending_actions WHERE session_id IN {}", rt)
    wipe("DELETE FROM wins WHERE session_id IN {}", rt)
    wipe("DELETE FROM recon_findings WHERE session_id IN {}", rt)
    wipe("DELETE FROM vuln_findings WHERE session_id IN {}", rt)
    wipe("DELETE FROM incidents WHERE hunt_id IN {}", hunt)
    wipe("DELETE FROM chat_actions WHERE session_id IN {}", chat)
    wipe("DELETE FROM block_ip_calls WHERE candidate_id IN {}", cands)
    wipe("DELETE FROM human_pages WHERE candidate_id IN {}", cands)
    wipe("DELETE FROM candidates WHERE id IN {}", cands)
    wipe("DELETE FROM redteam_sessions WHERE id IN {}", rt)
    wipe("DELETE FROM hunt_sessions WHERE id IN {}", hunt)
    wipe("DELETE FROM chat_sessions WHERE id IN {}", chat)
    n += cur.execute("DELETE FROM events WHERE host=?", (DEMO_HOST,)).rowcount
    conn.commit()
    clear_overlay()
    return n


# --------------------------------------------------------------------------- #
def run(args):
    ctx = {
        "subnet": args.subnet,
        "attacker_ip": args.attacker_ip,
        "target_name": args.target,
        "target_ip": args.target_ip,
        "label": args.label,
        "posture": args.posture,
        "flocks": [{"name": n, "ip": ip} for n, ip in
                   (("edge-proxy-7", args.subnet.rsplit(".", 1)[0] + ".20"),
                    ("cache-node-2", args.subnet.rsplit(".", 1)[0] + ".21"),
                    ("mail-relay-1", args.subnet.rsplit(".", 1)[0] + ".22"),
                    ("git-mirror-4", args.subnet.rsplit(".", 1)[0] + ".23"))],
    }

    conn = connect(args.db)
    try:
        script, reset_fn = build_script(ctx)
    finally:
        pass

    if args.list:
        print(f"{len(script)} beats (base timing; scaled by 1/speed):")
        t = 0.0
        for gap, label, _ in script:
            t += gap
            print(f"  +{t:5.1f}s  {label}")
        return

    # topology overlay so the map is self-contained (named target + flocks + subnet)
    if not args.no_topology:
        topo = demo_topology(ctx["subnet"], ctx["attacker_ip"], ctx["target_name"],
                             ctx["target_ip"], ctx["label"], ctx["posture"], ctx["flocks"])
        # generous TTL so a slow/looping demo never expires mid-run
        write_overlay(topo, ttl_seconds=max(600, int(600 / max(args.speed, 0.05))))
        print(f"topology overlay -> {OVERLAY_PATH} "
              f"(posture={ctx['posture']}, target={ctx['target_name']}, {len(ctx['flocks'])} flocks)")

    rt, hunt, chat = seed_sessions(conn, ctx["attacker_ip"])
    ctx["rt"], ctx["hunt"], ctx["chat"] = rt, hunt, chat
    emit = Emitter(conn, ctx)
    print(f"seeded demo sessions: redteam={rt} hunt={hunt} chat={chat}")
    print(f"running {len(script)} beats at speed x{args.speed} "
          f"(~{sum(g for g, _, _ in script) / args.speed:.0f}s per pass)"
          + (" [looping]" if args.loop else ""))

    def one_pass(first):
        if not first:
            reset_fn(emit)
            time.sleep(1.0 / args.speed)
        for gap, label, fn in script:
            if gap:
                time.sleep(gap / args.speed)
            fn(emit)
            print(f"  · {label}", flush=True)

    try:
        first = True
        while True:
            one_pass(first)
            first = False
            if not args.loop:
                break
            print("  (loop -- Ctrl-C to stop)")
            time.sleep(3.0 / args.speed)
    except KeyboardInterrupt:
        print("\ninterrupted.")
    finally:
        conn.close()

    print("done. Open the dashboard 'Attack Map' tab to watch (or replay with --loop).")
    if not args.keep_topology and not args.no_topology:
        print("note: topology overlay left in place so the map keeps the demo nodes; "
              "run --clear to remove demo rows + overlay.")


def main(argv=None):
    ap = argparse.ArgumentParser(description="Scripted attack/defense demo injector for the Attack Map.")
    ap.add_argument("--db", default=DEFAULT_DB, help=f"SQLite DB (default: {DEFAULT_DB})")
    ap.add_argument("--speed", type=float, default=1.0,
                    help="pace multiplier: >1 faster, <1 slower (default 1.0)")
    ap.add_argument("--loop", action="store_true", help="repeat the story until Ctrl-C")
    ap.add_argument("--posture", choices=["remote", "insider"], default="remote",
                    help="remote adds a firewall node + block-sever choreography (default remote)")
    ap.add_argument("--subnet", default="10.211.40.0/24", help="demo subnet CIDR")
    ap.add_argument("--attacker-ip", default="10.211.40.3", help="demo attacker IP")
    ap.add_argument("--target", default="k3f9a2xq", help="demo target hostname (opaque, recon-from-zero)")
    ap.add_argument("--target-ip", default="10.211.40.2", help="demo target IP")
    ap.add_argument("--label", default="", help="optional target label shown on the map")
    ap.add_argument("--no-topology", action="store_true",
                    help="don't write the demo topology overlay (use whatever's actually running)")
    ap.add_argument("--keep-topology", action="store_true",
                    help="(reserved) leave overlay after run -- overlay is left in place by default")
    ap.add_argument("--list", action="store_true", help="print the beat list and exit")
    ap.add_argument("--clear", action="store_true",
                    help="remove all demo rows + the topology overlay, then exit")
    args = ap.parse_args(argv)

    if not os.path.exists(args.db):
        print(f"error: DB not found: {args.db}", file=sys.stderr)
        return 2

    if args.clear:
        conn = connect(args.db)
        try:
            n = clear_demo(conn)
        finally:
            conn.close()
        print(f"cleared {n} demo rows + overlay.")
        return 0

    run(args)
    return 0


if __name__ == "__main__":
    sys.exit(main())
