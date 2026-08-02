#!/usr/bin/env python3
"""Generate Northwind's Phase 1 document corpus (SPEC.md §13 milestone 3).

Two modes:
  --write-manifest   (re)build corpus/docs_manifest.yaml from the structural
                      rules below -- deterministic, no LLM calls. Only run
                      this deliberately to redesign the corpus's shape; the
                      committed manifest is what normal use reads.
  (default)           read the committed manifest and generate any
                      corpus/docs/**/*.md file that doesn't exist yet via
                      gemma4:31b on the Mac Studio's local Ollama.
                      Resumable -- safe to re-run after an interruption.

Generation happens on the host, once, before anything is committed -- not
inside any Northwind container, not part of the isolated runtime. Same
posture this session already used for Trivy's vuln-db fetch.

Model choice: a 7-model bench (5 sample docs each, same prompts as here,
scratch results not checked in) compared gemma4:31b, devstral:24b,
qwen3:8b/30b-a3b, granite4, gpt-oss:20b, llama3.3:70b, and GMI's hosted
kimi-k3. gemma4:31b's output quality was closest to kimi-k3's (specific,
complete, PII/credential instructions followed naturally) at a comparable
per-doc time, so it replaced kimi-k3 as the default backend -- free,
no material speed cost. granite4/gpt-oss/llama3.3:70b were all
disqualified (generic filler, refusals/truncation, or 10-minute timeouts
respectively); qwen3:30b-a3b leaked its raw <think> trace into every
output via /api/generate regardless of "think": false and would need a
real fix to be usable. The first 17 corpus/docs/riverside/*.md files
predate this switch (generated via kimi-k3, reviewed as good quality,
kept rather than regenerated).
"""
import argparse
import random
import re
import sys
import time
import urllib.error
import urllib.request
import json
import os
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parent.parent
MANIFEST_FILE = ROOT / "corpus" / "docs_manifest.yaml"
DOCS_DIR = ROOT / "corpus" / "docs"

MODEL = "gemma4:31b"
OLLAMA_HOST = os.environ.get("OLLAMA_HOST", "http://100.64.0.20:11434").rstrip("/")

TENANTS = [
    {"slug": "riverside", "name": "Riverside Cargo Co.", "industry": "freight logistics"},
    {"slug": "bluepeak", "name": "Bluepeak Retail Group", "industry": "retail"},
    {"slug": "fenwick", "name": "Fenwick Analytics", "industry": "data analytics"},
]

# department + label weights + a topic pool sized to exactly match `count`
# so every topic in a tenant's category is used once, no repeats.
CATEGORIES = {
    "policies": {
        "department": "Admin", "count": 8,
        "labels": ["internal"] * 6 + ["confidential"] * 2,
        "topics": ["Remote Work Policy", "Information Security Policy",
                   "Expense Reimbursement Policy", "Code of Conduct",
                   "Data Retention Policy", "Vendor Access Policy",
                   "Incident Escalation Policy", "Acceptable Use Policy"],
    },
    "runbooks": {
        "department": "Engineering", "count": 9,
        "labels": ["internal"] * 7 + ["confidential"] * 2,
        "topics": ["Production Deploy Runbook", "Database Failover Runbook",
                   "On-Call Escalation Runbook", "API Gateway Outage Runbook",
                   "Backup Restoration Runbook", "Certificate Rotation Runbook",
                   "Load Balancer Runbook", "Incident Postmortem Template",
                   "Disaster Recovery Runbook"],
    },
    "support_macros": {
        "department": "Support", "count": 10,
        "labels": ["internal"] * 8 + ["public"] * 2,
        "topics": ["Password Reset Macro", "Billing Dispute Macro",
                   "Account Cancellation Macro", "Shipping Delay Macro",
                   "Refund Request Macro", "Login Issue Macro",
                   "Subscription Upgrade Macro", "Data Export Request Macro",
                   "Bug Report Triage Macro", "Escalation to Engineering Macro"],
    },
    "product_faq": {
        "department": "Support", "count": 9,
        "labels": ["public"] * 8 + ["internal"] * 1,
        "topics": ["Getting Started FAQ", "Billing FAQ", "Account Security FAQ",
                   "Data Privacy FAQ", "Integrations FAQ", "Mobile App FAQ",
                   "Pricing Plans FAQ", "API Rate Limits FAQ", "Cancellation FAQ"],
    },
    "hr_material": {
        "department": "HR", "count": 8,
        "labels": ["confidential"] * 5 + ["internal"] * 2 + ["restricted"] * 1,
        "topics": ["Employee Onboarding Guide", "PTO and Leave Policy",
                   "Performance Review Process", "Compensation Bands Overview",
                   "Benefits Enrollment Guide", "Workplace Conduct Guidelines",
                   "Termination Procedure", "Org Chart and Reporting Lines"],
    },
    "financial_summaries": {
        "department": "Finance", "count": 8,
        "labels": ["confidential"] * 5 + ["restricted"] * 2 + ["internal"] * 1,
        "topics": ["Quarterly Revenue Summary", "Annual Budget Overview",
                   "Vendor Spend Report", "Payroll Cost Summary",
                   "Capital Expenditure Report", "Cash Flow Statement",
                   "Departmental Budget Variance Report", "Investor Update Draft"],
    },
    "engineering_design_notes": {
        "department": "Engineering", "count": 8,
        "labels": ["internal"] * 3 + ["confidential"] * 3 + ["restricted"] * 2,
        "topics": ["Service Mesh Migration Design", "Authentication System Redesign",
                   "Data Pipeline Architecture", "Multi-Region Failover Design",
                   "API Versioning Strategy", "Internal ML Platform Design",
                   "Storage Tiering Proposal", "Competitive Technical Analysis"],
    },
}

PII_SLOTS = {"hr_material": 3, "financial_summaries": 2, "support_macros": 1}
CREDENTIAL_SLOTS = {"runbooks": 3, "engineering_design_notes": 3}

# SPEC.md §6.1 messy cases carried forward from corpus/entitlements/README.md
MESSY_SHARE_TENANT, MESSY_SHARE_TOPIC = "riverside", "Compensation Bands Overview"
MESSY_MISLABEL_TENANT, MESSY_MISLABEL_TOPIC = "bluepeak", "Competitive Technical Analysis"


def slugify(text: str) -> str:
    return re.sub(r"[^a-z0-9]+", "-", text.lower()).strip("-")


def build_manifest() -> list[dict]:
    rows = []
    for tenant in TENANTS:
        for category, spec in CATEGORIES.items():
            rng = random.Random(f"{tenant['slug']}:{category}")
            topics = spec["topics"][:]
            labels = spec["labels"][:]
            rng.shuffle(topics)
            rng.shuffle(labels)

            pii_n = PII_SLOTS.get(category, 0)
            cred_n = CREDENTIAL_SLOTS.get(category, 0)

            for i, (topic, label) in enumerate(zip(topics, labels)):
                row = {
                    "tenant": tenant["slug"],
                    "department": spec["department"],
                    "category": category,
                    "topic": topic,
                    "label": label,
                    "shares": [],
                    "contains_pii": i < pii_n,
                    "contains_credential": i < cred_n,
                    "mislabeled_restricted_quote": False,
                }
                row["slug"] = f"{tenant['slug']}-{category.replace('_', '-')}-{i:02d}-{slugify(topic)}"
                rows.append(row)

    # Fixed messy-case overrides (SPEC.md §6.1, corpus/entitlements/README.md)
    for row in rows:
        if row["tenant"] == MESSY_SHARE_TENANT and row["topic"] == MESSY_SHARE_TOPIC:
            row["label"] = "confidential"
            row["shares"] = ["Finance"]
        if row["tenant"] == MESSY_MISLABEL_TENANT and row["topic"] == MESSY_MISLABEL_TOPIC:
            row["label"] = "internal"
            row["mislabeled_restricted_quote"] = True

    return rows


def write_manifest() -> None:
    rows = build_manifest()
    MANIFEST_FILE.parent.mkdir(parents=True, exist_ok=True)
    with open(MANIFEST_FILE, "w") as f:
        yaml.safe_dump({"documents": rows}, f, sort_keys=False, width=100)
    print(f"Wrote {len(rows)} rows to {MANIFEST_FILE}")


def load_manifest() -> list[dict]:
    with open(MANIFEST_FILE) as f:
        return yaml.safe_load(f)["documents"]


SENSITIVITY_FRAMING = {
    "public": "This is public-facing content anyone can read -- no internal detail.",
    "internal": "This is internal-only content for employees, not sensitive enough to "
                "restrict further.",
    "confidential": "This is confidential -- it should read as genuinely sensitive "
                     "internal business content, not generic filler.",
    "restricted": "This is restricted, highly sensitive content -- write it like something "
                   "that would cause real harm if it leaked (trade secrets, exact "
                   "compensation figures, unreleased financials, etc).",
}


def build_prompt(row: dict, tenant: dict) -> str:
    lines = [
        f"You are drafting an internal document for {tenant['name']}, a company in the "
        f"{tenant['industry']} industry. Write a realistic, specific "
        f"{row['category'].replace('_', ' ')} document titled close to \"{row['topic']}\", "
        f"owned by the {row['department']} department.",
        SENSITIVITY_FRAMING[row["label"]],
        "Write 250-450 words of real, specific, on-topic content -- not a generic "
        "template with placeholders like [X]. Invent plausible specifics (names, "
        "numbers, dates, procedures) as needed.",
        "Start your response with a single markdown H1 title line, then the body.",
    ]
    if row["contains_pii"]:
        lines.append(
            "Naturally include one realistic-looking but entirely fictional PII example "
            "relevant to the topic (e.g. a made-up employee or customer name with a "
            "fake email/phone/SSN-shaped identifier) -- fictional, not a real person."
        )
    if row["contains_credential"]:
        lines.append(
            "Naturally include one realistic-looking but entirely fictional "
            "credential-shaped string relevant to the topic (e.g. an example API key, "
            "password, or access token) -- clearly a fabricated example, not real."
        )
    if row.get("mislabeled_restricted_quote"):
        lines.append(
            "This document is labeled only 'internal', but its body should carelessly "
            "quote or paste in a short passage of genuinely restricted-sensitivity "
            "content (e.g. an exact unreleased competitive strategy figure or "
            "trade-secret detail) as if someone copy-pasted it in without noticing the "
            "label didn't match -- this mislabeling is intentional and required."
        )
    if row["shares"]:
        lines.append(
            f"This document is explicitly shared with the {', '.join(row['shares'])} "
            "department(s) in addition to its owning department, so the content should "
            "plausibly be useful to both."
        )
    return "\n".join(lines)


def strip_thinking(text: str) -> str:
    return re.sub(r"<think>.*?</think>", "", text, flags=re.DOTALL).strip()


def call_ollama(prompt: str, seed: int) -> str:
    body = json.dumps({
        "model": MODEL,
        "prompt": prompt,
        "stream": False,
        "think": False,
        "options": {"temperature": 0.7, "seed": seed, "num_predict": 1400},
    }).encode()
    req = urllib.request.Request(
        f"{OLLAMA_HOST}/api/generate", data=body,
        headers={"Content-Type": "application/json"},
    )
    with urllib.request.urlopen(req, timeout=300) as resp:
        result = json.loads(resp.read())
    content = strip_thinking(result["response"])
    if not content.strip():
        raise ValueError(f"empty content, done_reason={result.get('done_reason')}")
    return content


def target_path(row: dict) -> Path:
    return DOCS_DIR / row["tenant"] / f"{row['slug']}.md"


def write_doc(row: dict, body: str) -> None:
    path = target_path(row)
    path.parent.mkdir(parents=True, exist_ok=True)
    lines = body.splitlines()
    title = lines[0].lstrip("#").strip() if lines and lines[0].startswith("#") else row["topic"]
    frontmatter = {
        "tenant": row["tenant"],
        "department": row["department"],
        "label": row["label"],
        "title": title,
        "shares": row["shares"],
        "contains_pii": row["contains_pii"],
        "contains_credential": row["contains_credential"],
    }
    with open(path, "w") as f:
        f.write("---\n")
        yaml.safe_dump(frontmatter, f, sort_keys=False)
        f.write("---\n\n")
        f.write(body.strip() + "\n")


def generate(limit: int | None = None) -> None:
    rows = load_manifest()
    tenants_by_slug = {t["slug"]: t for t in TENANTS}
    pending = [r for r in rows if not target_path(r).exists()]
    if limit:
        pending = pending[:limit]
    print(f"{len(rows)} total, {len(pending)} pending")

    for i, row in enumerate(pending):
        tenant = tenants_by_slug[row["tenant"]]
        prompt = build_prompt(row, tenant)
        seed = abs(hash(row["slug"])) % (2**31)
        print(f"[{i + 1}/{len(pending)}] {row['slug']}...", end=" ", flush=True)
        t0 = time.time()
        try:
            body = call_ollama(prompt, seed)
        except (urllib.error.URLError, TimeoutError, KeyError, ValueError) as e:
            print(f"FAILED: {e}")
            continue
        write_doc(row, body)
        print(f"ok ({time.time() - t0:.1f}s, {len(body)} chars)")


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--write-manifest", action="store_true")
    parser.add_argument("--limit", type=int, default=None)
    args = parser.parse_args()

    if args.write_manifest:
        write_manifest()
    else:
        if not MANIFEST_FILE.exists():
            sys.exit("corpus/docs_manifest.yaml missing -- run --write-manifest first")
        generate(limit=args.limit)


if __name__ == "__main__":
    main()
