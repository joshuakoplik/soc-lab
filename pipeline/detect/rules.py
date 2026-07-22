#!/usr/bin/env python3
"""
Deterministic detection. Cheap, repeatable, no model involved.

    python3 pipeline/rules.py            # run rules over new events
    python3 pipeline/rules.py --all      # re-run over the whole DB
    python3 pipeline/rules.py --stats    # show the volume cut

Every rule is a pure function of the events table. Same input, same output,
every time — which is exactly the property the LLM tier will NOT have, and the
reason detection lives here instead of there.
"""

import argparse
import json
import os
import re
import sqlite3
import sys
from collections import defaultdict
from datetime import datetime, timezone

HERE = os.path.dirname(os.path.abspath(__file__))       # pipeline/detect
ROOT = os.path.dirname(os.path.dirname(HERE))              # soc-lab root
DB_PATH = os.path.join(ROOT, "soc.db")

# ---------------------------------------------------------------------------
# Tunables. Every one of these is a false-positive/false-negative tradeoff you
# should be able to defend out loud. They are here, together, on purpose.
# ---------------------------------------------------------------------------
BRUTE_WINDOW_S      = 60    # burst window for failed SSH logins
BRUTE_THRESHOLD     = 5     # failures within window -> candidate
HTTP_RATE_WINDOW_S  = 30
HTTP_RATE_THRESHOLD = 50    # requests from one IP within window
HTTP_ERR_WINDOW_S   = 60
HTTP_ERR_THRESHOLD  = 15    # 4xx/5xx from one IP within window
CORRELATE_WINDOW_S  = 300   # same IP hitting both SSH and HTTP
LOOKBACK_S          = 600   # overlap re-scanned each run

# ---------------------------------------------------------------------------
# Signatures. Deliberately boring regex. Note we match on attacker-controlled
# text WITHOUT interpreting it — a regex cannot be talked into anything. That
# immunity is precisely what the model gives up in step 4.
# ---------------------------------------------------------------------------




# Post-compromise shell behaviour. Cowrie only sees these after a login lands.

SEVERITY_ORDER = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}


def now_iso():
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def _match_any(text, patterns):
    """Return list of (label,) for every pattern hitting text."""
    if not text:
        return []
    return [label for pat, label in patterns if re.search(pat, text)]


def _bucket(epoch, window):
    return int(epoch) // window


# ---------------------------------------------------------------------------
# Rules. Each returns a list of candidate dicts.
# ---------------------------------------------------------------------------







def rule_http_rate_anomaly(conn, since_epoch):
    """Raw request volume. Blunt, protocol-agnostic, catches what signatures miss."""
    rows = conn.execute(
        "SELECT id, src_ip, ts, CAST(strftime('%s', ts) AS INTEGER) e FROM events "
        "WHERE event_type='http.request' AND src_ip IS NOT NULL "
        "AND CAST(strftime('%s', ts) AS INTEGER) >= ? ORDER BY ts", (since_epoch,)
    ).fetchall()

    groups = defaultdict(list)
    for r in rows:
        groups[(r["src_ip"], _bucket(r["e"], HTTP_RATE_WINDOW_S))].append(r)

    out = []
    for (ip, bucket), evs in groups.items():
        if len(evs) < HTTP_RATE_THRESHOLD:
            continue
        out.append({
            "dedupe_key": f"http_rate:{ip}:{bucket}",
            "rule": "http_rate_anomaly",
            "severity": "low",
            "src_ip": ip,
            "first_seen": evs[0]["ts"],
            "last_seen": evs[-1]["ts"],
            "event_count": len(evs),
            "evidence": [e["id"] for e in evs][:20],
            "detail": {"requests": len(evs), "window_s": HTTP_RATE_WINDOW_S,
                       "rate_per_s": round(len(evs) / HTTP_RATE_WINDOW_S, 2)},
        })
    return out


def rule_cross_source_correlation(conn, since_epoch):
    """The rule that justifies two log sources.

    One IP touching BOTH the honeypot and the web app inside a short window is
    not background noise — it's someone working a target list across protocols.
    Neither log shows this alone. This is the highest-signal, lowest-volume rule
    in the file, and it's the one worth talking about in an interview."""
    rows = conn.execute(
        "SELECT id, src_ip, ts, source, event_type, CAST(strftime('%s', ts) AS INTEGER) e "
        "FROM events WHERE src_ip IS NOT NULL AND CAST(strftime('%s', ts) AS INTEGER) >= ? "
        "ORDER BY ts", (since_epoch,)
    ).fetchall()

    by_ip = defaultdict(list)
    for r in rows:
        by_ip[r["src_ip"]].append(r)

    out = []
    for ip, evs in by_ip.items():
        sources = {e["source"] for e in evs}
        if len(sources) < 2:
            continue
        bucket = _bucket(evs[0]["e"], CORRELATE_WINDOW_S)
        span = evs[-1]["e"] - evs[0]["e"]
        if span > CORRELATE_WINDOW_S:
            continue
        types = defaultdict(int)
        for e in evs:
            types[e["event_type"]] += 1
        out.append({
            "dedupe_key": f"cross_source:{ip}:{bucket}",
            "rule": "cross_source_activity",
            "severity": "high",
            "src_ip": ip,
            "first_seen": evs[0]["ts"],
            "last_seen": evs[-1]["ts"],
            "event_count": len(evs),
            "evidence": [e["id"] for e in evs][:50],
            "detail": {
                "sources": sorted(sources),
                "event_types": dict(types),
                "span_s": span,
                "note": "same origin across SSH and HTTP within correlation window",
            },
        })
    return out


def rule_ids_alert(conn, since_epoch):
    """Promote Suricata alerts into candidates.

    Suricata already did the detection — a rule fired — so this rule's job is
    aggregation, not detection: group by (src_ip, signature_id, window) so a
    sqlmap run that trips the same SID 800 times becomes ONE candidate. Severity
    maps from Suricata's 1..3 (1=most severe) onto our scale.

    This is where the 'give the defender a fighting chance' payoff lands: ET Open
    brings ~40k signatures that no hand-written regex tier would match, and they
    arrive here already shaped as candidates the agent can reason over."""
    rows = conn.execute(
        "SELECT id, src_ip, ts, ids_signature, ids_category, ids_severity, "
        "ids_signature_id, url_path, url_query, user_agent, dst_port, "
        "CAST(strftime('%s', ts) AS INTEGER) e FROM events "
        "WHERE source='suricata' AND event_type='ids.alert' "
        "AND CAST(strftime('%s', ts) AS INTEGER) >= ? ORDER BY ts", (since_epoch,)
    ).fetchall()

    sev_map = {1: "high", 2: "medium", 3: "low"}
    # ET's own classifications for traffic that is benign by definition. Our job
    # is to not let raw hit count override the vendor saying "not suspicious".
    BENIGN_CATS = {"Not Suspicious Traffic", "Misc activity",
                   "Generic Protocol Command Decode"}
    groups = defaultdict(lambda: {"evs": [], "cats": set(), "paths": set()})
    for r in rows:
        key = (r["src_ip"], r["ids_signature_id"], _bucket(r["e"], HTTP_RATE_WINDOW_S))
        g = groups[key]
        g["evs"].append(r)
        if r["ids_category"]:
            g["cats"].add(r["ids_category"])
        if r["url_path"]:
            g["paths"].add(r["url_path"])
        g["sig"] = r["ids_signature"]
        g["sid"] = r["ids_signature_id"]
        g["sev"] = r["ids_severity"]

    out = []
    for (ip, sid, bucket), g in groups.items():
        evs = g["evs"]
        base = sev_map.get(g.get("sev"), "medium")
        # volume != severity, the lesson from the first real run: 548 apt
        # requests outranked a root login. Benign categories pin low and ignore
        # volume; only non-benign signatures escalate on hit count.
        if g["cats"] and g["cats"] <= BENIGN_CATS:
            sev = "low"
        elif len(evs) > 20:
            sev = "high"
        else:
            sev = base
        out.append({
            "dedupe_key": f"ids_alert:{ip}:{sid}:{bucket}",
            "rule": "ids_alert",
            "severity": sev,
            "src_ip": ip,
            "first_seen": evs[0]["ts"],
            "last_seen": evs[-1]["ts"],
            "event_count": len(evs),
            "evidence": [e["id"] for e in evs][:50],
            "detail": {
                "signature": g.get("sig"),
                "signature_id": sid,
                "categories": sorted(g["cats"]),
                "hits": len(evs),
                "sample_paths": sorted(g["paths"])[:5],
                "source": "suricata/et-open",
            },
        })
    return out


def rule_wazuh_alert(conn, since_epoch):
    """Promote Wazuh alerts into candidates.

    Wazuh already did the detection — its rule fired, its correlation engine
    counted the frequency. Our job is aggregation into the candidate shape the
    agent consumes: group by (src_ip, siem_rule_id, window) so a brute force
    that trips rule 100110 two hundred times is ONE candidate.

    Wazuh level (0-15) maps onto our five-point scale. Level 12+ is Wazuh's own
    'notify a human' threshold, so that's where we start calling things critical.
    """
    rows = conn.execute(
        "SELECT id, src_ip, ts, siem_rule_id, siem_level, siem_description, "
        "siem_groups, username, command, url_path, "
        "CAST(strftime('%s', ts) AS INTEGER) e FROM events "
        "WHERE source='wazuh' AND event_type='siem.alert' "
        "AND CAST(strftime('%s', ts) AS INTEGER) >= ? ORDER BY ts", (since_epoch,)
    ).fetchall()

    def sev(level):
        if level is None:      return "low"
        if level >= 12:        return "critical"
        if level >= 10:        return "high"
        if level >= 6:         return "medium"
        if level >= 3:         return "low"
        return "info"

    groups = defaultdict(lambda: {"evs": [], "tags": set()})
    for r in rows:
        # Wazuh's own housekeeping alerts (server started, etc.) are noise here.
        if r["siem_rule_id"] in ("502", "503", "504"):
            continue
        key = (r["src_ip"], r["siem_rule_id"], _bucket(r["e"], HTTP_RATE_WINDOW_S))
        g = groups[key]
        g["evs"].append(r)
        try:
            g["tags"].update(json.loads(r["siem_groups"] or "[]"))
        except (json.JSONDecodeError, TypeError):
            pass

    out = []
    for (ip, sid, bucket), g in groups.items():
        evs = g["evs"]
        lvl = max((e["siem_level"] or 0) for e in evs)
        out.append({
            "dedupe_key": f"wazuh_alert:{ip}:{sid}:{bucket}",
            "rule": "wazuh_alert",
            "severity": sev(lvl),
            "src_ip": ip,
            "first_seen": evs[0]["ts"],
            "last_seen": evs[-1]["ts"],
            "event_count": len(evs),
            "evidence": [e["id"] for e in evs][:50],
            "detail": {
                "wazuh_rule_id": sid,
                "wazuh_level": lvl,
                "description": evs[-1]["siem_description"],
                "groups": sorted(g["tags"]),
                "hits": len(evs),
                "usernames": sorted({e["username"] for e in evs if e["username"]})[:10],
                "commands": [e["command"] for e in evs if e["command"]][:5],
                "source": "wazuh/siem",
            },
        })
    return out


RULES = [
    rule_ids_alert,
    rule_wazuh_alert,
    rule_http_rate_anomaly,
    rule_cross_source_correlation,
]


# ---------------------------------------------------------------------------
def connect(db_path=None):
    """db_path lets a caller (e.g. harness/injector.py) run rules against an
    isolated database instead of the lab's real soc.db. Defaults to DB_PATH,
    so every existing caller is unaffected."""
    conn = sqlite3.connect(db_path or DB_PATH)
    conn.row_factory = sqlite3.Row
    with open(os.path.join(HERE, "schema.sql")) as f:
        conn.executescript(f.read())
    return conn


def upsert(conn, c):
    ts = now_iso()
    conn.execute(
        "INSERT INTO candidates (dedupe_key, rule, severity, src_ip, first_seen, last_seen,"
        " event_count, evidence, detail, created, updated) VALUES (?,?,?,?,?,?,?,?,?,?,?) "
        "ON CONFLICT(dedupe_key) DO UPDATE SET last_seen=excluded.last_seen,"
        " event_count=excluded.event_count, evidence=excluded.evidence,"
        " detail=excluded.detail, severity=excluded.severity, updated=excluded.updated",
        (c["dedupe_key"], c["rule"], c["severity"], c["src_ip"], c["first_seen"],
         c["last_seen"], c["event_count"], json.dumps(c["evidence"]),
         json.dumps(c["detail"]), ts, ts),
    )


def get_watermark(conn):
    r = conn.execute("SELECT v FROM rule_state WHERE k='watermark_epoch'").fetchone()
    return int(r["v"]) if r else 0


def set_watermark(conn, epoch):
    conn.execute(
        "INSERT INTO rule_state (k,v,updated) VALUES ('watermark_epoch',?,?) "
        "ON CONFLICT(k) DO UPDATE SET v=excluded.v, updated=excluded.updated",
        (str(epoch), now_iso()),
    )


def stats(conn):
    ev = conn.execute("SELECT COUNT(*) n FROM events").fetchone()["n"]
    cd = conn.execute("SELECT COUNT(*) n FROM candidates").fetchone()["n"]
    print("\n=== candidates by rule ===")
    for r in conn.execute(
        "SELECT rule, severity, COUNT(*) n FROM candidates GROUP BY rule, severity "
        "ORDER BY n DESC"
    ):
        print(f"  {r['rule']:<26} {r['severity']:<9} {r['n']:>5}")

    print("\n=== the volume cut ===")
    print(f"  raw events:            {ev:>7}")
    print(f"  candidates for triage: {cd:>7}")
    if ev:
        pct = 100 * (1 - cd / ev)
        print(f"  reduction:             {pct:>6.1f}%")
        print(f"\n  Every candidate costs tokens. Every event would have.")
        print(f"  That ratio is your argument for why the LLM sits on top of")
        print(f"  detection rather than replacing it.")


def run_rules(conn, since_epoch=0, verbose=True):
    """Run every rule in RULES over events at/after since_epoch, upsert the
    resulting candidates, and advance the watermark. Factored out of main()
    so harness/injector.py can run the real deterministic tier over forged
    events the same way `rules.py --all` would, instead of reimplementing
    any of this. Returns the total candidate count emitted/updated."""
    total = 0
    for fn in RULES:
        cands = fn(conn, since_epoch)
        for c in cands:
            upsert(conn, c)
        total += len(cands)
        if cands and verbose:
            print(f"  {fn.__name__:<34} {len(cands):>4} candidate(s)")

    latest = conn.execute("SELECT MAX(CAST(strftime('%s', ts) AS INTEGER)) e FROM events").fetchone()["e"]
    if latest:
        set_watermark(conn, latest)
    conn.commit()
    return total


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--all", action="store_true", help="re-run over all events")
    ap.add_argument("--stats", action="store_true", help="just show stats")
    args = ap.parse_args()

    conn = connect()

    if args.stats:
        stats(conn)
        return

    since = 0 if args.all else max(0, get_watermark(conn) - LOOKBACK_S)
    total = run_rules(conn, since)

    print(f"\n[*] {total} candidate(s) emitted/updated")
    stats(conn)


if __name__ == "__main__":
    main()
