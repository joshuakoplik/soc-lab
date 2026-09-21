#!/usr/bin/env python3
"""Recent-CVE discovery for the agentic target designer.

Pulls freshly-published CVEs from the NVD 2.0 API and buckets them by the role
they can play in a lab chain -- a `foothold` (remote code execution / injection
/ deserialization that gets an attacker onto the box) or a `privesc` (local
privilege escalation that takes that foothold to root). This is the *input*
stage of the designer: it surfaces real, published, recent vulnerabilities (so
they postdate model training data -- the whole point) that the design stage then
composes into a target scenario.

Deliberately stdlib-only (urllib), same posture as pipeline/ingest.py, so the
designer never needs the venv for discovery.

Scope note: this reads PUBLISHED CVE metadata only. It does not fetch, generate,
or run exploit code -- the designer builds the vulnerable *environment* from
public advisories; exploitation is the lab attacker's job. See README.md.
"""

from __future__ import annotations

import argparse
import json
import time
import urllib.parse
import urllib.request

NVD_ENDPOINT = "https://services.nvd.nist.gov/rest/json/cves/2.0"
USER_AGENT = "soc-lab-target-designer/0.1"

# CWE -> role. A CVE's weakness IDs are the most reliable signal; the keyword
# fallback below only fires when the CWE set is empty or NVD-unmapped.
FOOTHOLD_CWES = {
    "CWE-94",   # code injection
    "CWE-95",   # eval injection
    "CWE-77", "CWE-78",  # command injection / OS command injection
    "CWE-502",  # deserialization of untrusted data
    "CWE-434",  # unrestricted upload of dangerous file type
    "CWE-917",  # expression language injection
    "CWE-98",   # PHP remote file inclusion
    "CWE-74",   # injection (generic)
    "CWE-1336", # server-side template injection
}
PRIVESC_CWES = {
    "CWE-269",  # improper privilege management
    "CWE-250",  # execution with unnecessary privileges
    "CWE-266", "CWE-268", "CWE-271", "CWE-272", "CWE-273",  # privilege family
    "CWE-367",  # TOCTOU race (classic LPE)
    "CWE-59",   # link following (LPE primitive)
}
FOOTHOLD_KEYWORDS = (
    "remote code execution", "arbitrary code", "command injection",
    "deserializ", "unauthenticated", "arbitrary command", "rce",
    "template injection", "arbitrary file upload",
)
PRIVESC_KEYWORDS = (
    "privilege escalation", "elevation of privilege", "gain root",
    "local privilege", "escalate privileges", "root privileges",
    "setuid", "sudo",
)


def _get(url: str, timeout: int = 30) -> dict:
    req = urllib.request.Request(url, headers={"User-Agent": USER_AGENT,
                                               "Accept": "application/json"})
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        return json.load(resp)


def _cvss(cve: dict) -> tuple[float | None, str | None, str | None]:
    """Return (baseScore, baseSeverity, vectorString) from the best available
    CVSS metric (v3.1 > v3.0 > v4.0), or (None, None, None)."""
    metrics = cve.get("metrics", {})
    for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV40"):
        arr = metrics.get(key)
        if arr:
            data = arr[0].get("cvssData", {})
            return (data.get("baseScore"), data.get("baseSeverity"),
                    data.get("vectorString"))
    return (None, None, None)


def _cwes(cve: dict) -> list[str]:
    out = []
    for weak in cve.get("weaknesses", []):
        for d in weak.get("description", []):
            val = d.get("value", "")
            if val.startswith("CWE-"):
                out.append(val)
    return sorted(set(out))


def _description(cve: dict) -> str:
    for d in cve.get("descriptions", []):
        if d.get("lang") == "en":
            return d.get("value", "")
    return ""


def _products(cve: dict, cap: int = 12) -> list[str]:
    """Distinct 'vendor:product:version' triples from the CPE match nodes --
    what the design/build stage needs to know which software to stand up."""
    seen = []
    for conf in cve.get("configurations", []):
        for node in conf.get("nodes", []):
            for m in node.get("cpeMatch", []):
                # cpe:2.3:a:vendor:product:version:...
                parts = m.get("criteria", "").split(":")
                if len(parts) >= 6:
                    vendor, product, version = parts[3], parts[4], parts[5]
                    triple = f"{vendor}:{product}:{version}"
                    if triple not in seen:
                        seen.append(triple)
                if len(seen) >= cap:
                    return seen
    return seen


def classify(cve: dict) -> str:
    cwes = set(_cwes(cve))
    if cwes & FOOTHOLD_CWES:
        return "foothold"
    if cwes & PRIVESC_CWES:
        return "privesc"
    desc = _description(cve).lower()
    if any(k in desc for k in PRIVESC_KEYWORDS):
        return "privesc"
    if any(k in desc for k in FOOTHOLD_KEYWORDS):
        return "foothold"
    return "other"


def fetch_recent_cves(days_back: int = 45, min_cvss: float = 8.0,
                      max_results: int = 200, page_pause_s: float = 6.0) -> list[dict]:
    """Recent CVEs at or above `min_cvss`, newest first, as normalized dicts.

    NVD caps a published-date window at 120 days and paginates at up to 2000
    results/page. Without an API key the rate limit is 5 req/30s, so we pause
    between pages. Returns [] on an API hiccup rather than raising (the designer
    can retry or narrow the window)."""
    days_back = min(days_back, 120)
    end = time.time()
    start = end - days_back * 86400
    fmt = "%Y-%m-%dT%H:%M:%S.000"
    params = {
        "pubStartDate": time.strftime(fmt, time.gmtime(start)),
        "pubEndDate": time.strftime(fmt, time.gmtime(end)),
        "resultsPerPage": 2000,
        "startIndex": 0,
    }
    out: list[dict] = []
    while True:
        url = f"{NVD_ENDPOINT}?{urllib.parse.urlencode(params)}"
        try:
            data = _get(url)
        except Exception as e:  # noqa: BLE001 -- discovery is best-effort
            print(f"[cve_feed] NVD query failed at startIndex={params['startIndex']}: {e}")
            break
        vulns = data.get("vulnerabilities", [])
        for entry in vulns:
            cve = entry.get("cve", {})
            score, severity, vector = _cvss(cve)
            if score is None or score < min_cvss:
                continue
            out.append({
                "id": cve.get("id"),
                "published": cve.get("published"),
                "cvss": score,
                "severity": severity,
                "vector": vector,
                "cwes": _cwes(cve),
                "role": classify(cve),
                "products": _products(cve),
                "description": _description(cve),
            })
            if len(out) >= max_results:
                break
        total = data.get("totalResults", 0)
        params["startIndex"] += len(vulns)
        if len(out) >= max_results or params["startIndex"] >= total or not vulns:
            break
        time.sleep(page_pause_s)  # respect the keyless rate limit
    out.sort(key=lambda c: (c["published"] or ""), reverse=True)
    return out


def main() -> None:
    ap = argparse.ArgumentParser(description="Discover recent CVEs for the target designer.")
    ap.add_argument("--days", type=int, default=45, help="look-back window (max 120)")
    ap.add_argument("--min-cvss", type=float, default=8.0)
    ap.add_argument("--role", choices=["foothold", "privesc", "any"], default="any")
    ap.add_argument("--limit", type=int, default=25)
    ap.add_argument("--product", default=None, help="case-insensitive substring filter on products")
    ap.add_argument("--json", action="store_true", help="emit JSON instead of a table")
    args = ap.parse_args()

    cves = fetch_recent_cves(days_back=args.days, min_cvss=args.min_cvss,
                             max_results=max(args.limit * 4, 100))
    if args.role != "any":
        cves = [c for c in cves if c["role"] == args.role]
    if args.product:
        needle = args.product.lower()
        cves = [c for c in cves if any(needle in p.lower() for p in c["products"])]
    cves = cves[:args.limit]

    if args.json:
        print(json.dumps(cves, indent=2))
        return
    print(f"{'CVE':<18} {'CVSS':>4} {'ROLE':<9} {'PUBLISHED':<11} PRODUCTS / SUMMARY")
    print("-" * 100)
    for c in cves:
        prods = ", ".join(c["products"][:2]) or "(no CPE)"
        summary = (c["description"][:70] + "…") if len(c["description"]) > 70 else c["description"]
        print(f"{c['id']:<18} {c['cvss']:>4} {c['role']:<9} {(c['published'] or '')[:10]:<11} {prods}")
        print(f"{'':>18} {'':>4} {'':<9} {'':<11} {summary}")


if __name__ == "__main__":
    main()
