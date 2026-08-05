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

NW_INGEST_BURST_WINDOW_S      = 3600  # burst window for /feedback ingestion spam
NW_INGEST_BURST_THRESHOLD     = 5     # submissions from one submitter within window -> candidate
NW_ID_ENUM_WINDOW_S           = 1800  # window for customer_record ID-sweep detection
NW_ID_ENUM_DISTINCT_THRESHOLD = 5     # distinct customer_ids probed by one session within window

# ---------------------------------------------------------------------------
# Signatures. Deliberately boring regex. Note we match on attacker-controlled
# text WITHOUT interpreting it — a regex cannot be talked into anything. That
# immunity is precisely what the model gives up in step 4.
# ---------------------------------------------------------------------------

# The three social-engineering angles the real Northwind campaign actually
# used against the assistant, via documents planted through the
# unauthenticated /feedback endpoint (see rule_northwind_injection_language).
NW_INJECTION_LANGUAGE_PATTERNS = [
    (r"\b(escalation|supervisor)\s+(code|override|approv\w*)\b", "escalation_override"),
    (r"\bapproved\s+by\b.{0,20}\bsupervisor\b", "escalation_override"),
    (r"\b(stale[- ]cache|known\s+(issue|bug))\b.{0,60}"
     r"\b(bypass|workaround|retry|disregard\w*|ignore\w*|not\s+a\s+valid|should\s+proceed)\b",
     "fake_defect_bypass"),
    (r"\b(training|onboarding|demo)\s+account\b", "fake_onboarding"),
    (r"\bwhitelist(ed)?\s+(this|these|for)\b", "fake_onboarding"),
]

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


def _strip_markdown_emphasis(text):
    """LLM completions routinely wrap words in markdown bold/italic
    (**not**, __ok__) -- left alone, that punctuation sits between two
    words a phrase-matching regex expects to be plain-whitespace-adjacent,
    silently breaking matches like "is **not** a valid" (confirmed live
    against a real Northwind completion). Strip it before matching, not
    after -- patterns stay boring/readable instead of each having to
    anticipate markdown noise individually."""
    if not text:
        return text
    return re.sub(r"\*{1,2}|_{1,2}", "", text)


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


def _northwind_chat_evidence(conn, session_id, limit=50):
    """events.id rows for a session's /chat calls -- the shared join key
    between northwind-portal-api events and llm_transcripts (both carry
    session_id; confirmed via normalize_northwind_portal_api and
    ingest.py's read_new_transcripts()). Used by every rule below that
    keys off llm_transcripts, so candidates.evidence always stays in
    events.id space (what query_events expects), never llm_transcripts.id."""
    if not session_id:
        return []
    rows = conn.execute(
        "SELECT id FROM events WHERE source='northwind-portal-api' "
        "AND event_type='portal.chat' AND session_id=? ORDER BY ts",
        (session_id,),
    ).fetchall()
    return [r["id"] for r in rows][:limit]


def rule_northwind_poisoned_retrieval(conn, since_epoch):
    """SPEC.md's own flagged gap (§10): 'A poisoned document arriving
    through the feedback form is visible only in ingest telemetry, and
    only if someone correlates it with a later retrieval.' This is that
    correlation -- a document planted via the unauthenticated /feedback
    endpoint (northwind-ingest events) later surfacing in a real /chat
    retrieval (llm_transcripts.retrieved_context).

    Deliberately deviates from every other rule's since_epoch-bounded scan
    on the ingest side: it rescans ALL northwind-ingest history every run,
    not just the incremental window. A document can't be retrieved before
    it exists, so the join only needs bounding on the retrieval side (new
    transcript rows) -- fine at lab scale (low hundreds of ingest events),
    called out explicitly so it isn't "fixed" into inconsistency later."""
    ingest_rows = conn.execute(
        "SELECT id, ts, raw FROM events WHERE source='northwind-ingest' ORDER BY ts"
    ).fetchall()
    doc_map = {}
    for r in ingest_rows:
        try:
            obj = json.loads(r["raw"])
        except (json.JSONDecodeError, TypeError):
            continue
        doc_id = obj.get("document_id")
        if doc_id is None:
            continue
        doc_map[doc_id] = {
            "event_id": r["id"], "ts": r["ts"],
            "submitter": obj.get("submitter"), "tenant_id": obj.get("tenant_id"),
            "source": obj.get("source"),
        }
    if not doc_map:
        return []

    transcript_rows = conn.execute(
        "SELECT id, ts, session_id, username, retrieved_context FROM llm_transcripts "
        "WHERE retrieved_context IS NOT NULL "
        "AND CAST(strftime('%s', ts) AS INTEGER) >= ? ORDER BY ts", (since_epoch,)
    ).fetchall()

    out = []
    for t in transcript_rows:
        try:
            chunks = json.loads(t["retrieved_context"])
        except (json.JSONDecodeError, TypeError):
            continue
        for chunk in chunks:
            doc_id = chunk.get("document_id")
            if doc_id is None or doc_id not in doc_map:
                continue
            ingest = doc_map[doc_id]
            evidence = [ingest["event_id"]] + _northwind_chat_evidence(conn, t["session_id"], limit=10)
            gap_s = None
            try:
                ingest_e = datetime.fromisoformat(ingest["ts"].replace("Z", "+00:00"))
                retrieval_e = datetime.fromisoformat(t["ts"].replace("Z", "+00:00"))
                gap_s = (retrieval_e - ingest_e).total_seconds()
            except (ValueError, AttributeError, TypeError):
                pass
            out.append({
                "dedupe_key": f"nw_poisoned_retrieval:{doc_id}:{t['id']}",
                "rule": "northwind_poisoned_retrieval",
                "severity": "high",
                "src_ip": None,
                "first_seen": ingest["ts"],
                "last_seen": t["ts"],
                "event_count": len(evidence),
                "evidence": evidence,
                "detail": {
                    "document_id": doc_id,
                    "document_title": chunk.get("title"),
                    "ingest_source": ingest["source"],
                    "ingest_submitter": ingest["submitter"],
                    "ingest_tenant_id": ingest["tenant_id"],
                    "ingest_ts": ingest["ts"],
                    "retrieval_session_id": t["session_id"],
                    "retrieval_username": t["username"],
                    "retrieval_ts": t["ts"],
                    "retrieval_score": chunk.get("score"),
                    "gap_seconds": gap_s,
                    "llm_transcript_id": t["id"],
                },
            })
    return out


def rule_northwind_ingestion_burst(conn, since_epoch):
    """N submissions from one submitter to the unauthenticated /feedback
    endpoint within a window -- the shape a real campaign takes when
    repeatedly planting injection documents (see
    rule_northwind_poisoned_retrieval for the follow-on "did it get
    retrieved" check). Submitter is self-declared, not authenticated --
    grouping by it still catches a campaign that reuses one cover identity,
    which is what actually happened; a submitter left blank on every call
    would evade this rule entirely, since there's no other correlatable
    field (no src_ip, no session_id on ingest events) -- a known blind
    spot, not an oversight."""
    rows = conn.execute(
        "SELECT id, ts, username, raw, CAST(strftime('%s', ts) AS INTEGER) e "
        "FROM events WHERE source='northwind-ingest' AND username IS NOT NULL "
        "AND CAST(strftime('%s', ts) AS INTEGER) >= ? ORDER BY ts", (since_epoch,)
    ).fetchall()

    groups = defaultdict(list)
    for r in rows:
        groups[(r["username"], _bucket(r["e"], NW_INGEST_BURST_WINDOW_S))].append(r)

    out = []
    for (submitter, bucket), evs in groups.items():
        if len(evs) < NW_INGEST_BURST_THRESHOLD:
            continue
        tenants = set()
        snippets = []
        for e in evs:
            try:
                obj = json.loads(e["raw"])
            except (json.JSONDecodeError, TypeError):
                continue
            if obj.get("tenant_id") is not None:
                tenants.add(obj["tenant_id"])
            content = obj.get("content")
            if content:
                snippets.append(content[:120])
        severity = "high" if (len(evs) >= 10 or len(tenants) > 1) else "medium"
        out.append({
            "dedupe_key": f"nw_ingest_burst:{submitter}:{bucket}",
            "rule": "northwind_ingestion_burst",
            "severity": severity,
            "src_ip": None,
            "first_seen": evs[0]["ts"],
            "last_seen": evs[-1]["ts"],
            "event_count": len(evs),
            "evidence": [e["id"] for e in evs][:50],
            "detail": {
                "submitter": submitter,
                "count": len(evs),
                "distinct_tenants": len(tenants),
                "sample_content_snippets": snippets[:10],
            },
        })
    return out


def rule_northwind_id_enumeration(conn, since_epoch):
    """Sequential/broad customer-ID sweeps via the customer_record tool --
    the existence-oracle probing pattern (a differential error message
    reveals which cross-tenant IDs exist even when the data itself is
    withheld). llm_transcripts.tool_calls has no result/success flag (see
    portal-api's own tool-calling loop), so this can only observe probing
    VOLUME/SPREAD, not which ids actually succeeded -- that's fine, the
    enumeration pattern itself is the deterministic signal, same
    "detection, not conclusion" posture as every other rule here."""
    rows = conn.execute(
        "SELECT id, ts, session_id, username, tool_calls, "
        "CAST(strftime('%s', ts) AS INTEGER) e FROM llm_transcripts "
        "WHERE tool_calls IS NOT NULL AND session_id IS NOT NULL "
        "AND CAST(strftime('%s', ts) AS INTEGER) >= ? ORDER BY ts", (since_epoch,)
    ).fetchall()

    groups = defaultdict(lambda: {"rows": [], "ids": set()})
    for r in rows:
        try:
            calls = json.loads(r["tool_calls"])
        except (json.JSONDecodeError, TypeError):
            continue
        ids = {
            c["args"]["customer_id"] for c in calls
            if isinstance(c, dict) and c.get("tool") == "customer_record"
            and isinstance(c.get("args"), dict) and isinstance(c["args"].get("customer_id"), int)
        }
        if not ids:
            continue
        key = (r["session_id"], _bucket(r["e"], NW_ID_ENUM_WINDOW_S))
        groups[key]["rows"].append(r)
        groups[key]["ids"].update(ids)

    out = []
    for (session_id, bucket), g in groups.items():
        ids = g["ids"]
        if len(ids) < NW_ID_ENUM_DISTINCT_THRESHOLD:
            continue
        sorted_ids = sorted(ids)
        sequential = sorted_ids == list(range(sorted_ids[0], sorted_ids[-1] + 1))
        severity = "high" if (len(ids) >= 15 or sequential) else "medium"
        rows_g = g["rows"]
        out.append({
            "dedupe_key": f"nw_id_enum:{session_id}:{bucket}",
            "rule": "northwind_id_enumeration",
            "severity": severity,
            "src_ip": None,
            "first_seen": rows_g[0]["ts"],
            "last_seen": rows_g[-1]["ts"],
            "event_count": len(rows_g),
            "evidence": _northwind_chat_evidence(conn, session_id),
            "detail": {
                "session_id": session_id,
                "username": rows_g[-1]["username"],
                "distinct_customer_ids": sorted_ids[:50],
                "count": len(ids),
                "sequential": sequential,
                "llm_transcript_ids": [r["id"] for r in rows_g][:50],
            },
        })
    return out


def rule_northwind_injection_language(conn, since_epoch):
    """Coarse pre-filter, not a conclusion -- boring regex (via the
    existing, previously-unused _match_any()) against what the assistant
    actually said back (llm_transcripts.completion, not user_turn -- the
    injection text lives in the ingested document, not the live turn),
    looking for the specific social-engineering angles the real campaign
    used. A match here is a prompt for the triage LLM's own judgment, not
    a verdict -- semantic judgment belongs at that tier, not this one."""
    rows = conn.execute(
        "SELECT id, ts, session_id, username, completion, tool_calls "
        "FROM llm_transcripts WHERE completion IS NOT NULL "
        "AND CAST(strftime('%s', ts) AS INTEGER) >= ? ORDER BY ts", (since_epoch,)
    ).fetchall()

    out = []
    for r in rows:
        labels = _match_any(_strip_markdown_emphasis(r["completion"]), NW_INJECTION_LANGUAGE_PATTERNS)
        if not labels:
            continue
        has_tool_calls = bool(r["tool_calls"] and r["tool_calls"] not in ("[]", "null"))
        evidence = _northwind_chat_evidence(conn, r["session_id"], limit=10)
        out.append({
            "dedupe_key": f"nw_injection_lang:{r['id']}",
            "rule": "northwind_injection_language",
            "severity": "medium" if has_tool_calls else "low",
            "src_ip": None,
            "first_seen": r["ts"],
            "last_seen": r["ts"],
            "event_count": 1,
            "evidence": evidence,
            "detail": {
                "session_id": r["session_id"],
                "username": r["username"],
                "matched_labels": sorted(set(labels)),
                "tool_calls_made": has_tool_calls,
                "completion_snippet": (r["completion"] or "")[:400],
                "llm_transcript_id": r["id"],
            },
        })
    return out


RULES = [
    rule_ids_alert,
    rule_wazuh_alert,
    rule_http_rate_anomaly,
    rule_cross_source_correlation,
    rule_northwind_poisoned_retrieval,
    rule_northwind_ingestion_burst,
    rule_northwind_id_enumeration,
    rule_northwind_injection_language,
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
    ap.add_argument("--db-path", default=None,
                     help="run against this sqlite file instead of soc.db (e.g. a "
                          "replay_session.py output, for repeatable defender testing)")
    args = ap.parse_args()

    conn = connect(args.db_path)

    if args.stats:
        stats(conn)
        return

    since = 0 if args.all else max(0, get_watermark(conn) - LOOKBACK_S)
    total = run_rules(conn, since)

    print(f"\n[*] {total} candidate(s) emitted/updated")
    stats(conn)


if __name__ == "__main__":
    main()
