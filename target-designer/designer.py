#!/usr/bin/env python3
"""Agentic target designer -- turn recent, published CVEs into a chainable,
buildable lab host.

Pipeline stages (run one with --stage, or the lot with --stage all):

  discover  -> pull recent foothold (RCE/injection) + privesc (LPE) CVEs (cve_feed)
  design    -> an LLM composes ONE foothold + ONE privesc into a single-host
               chain scenario and a docker build recipe (a TargetSpec)
  generate  -> assemble the Dockerfile from the spec
  build     -> docker build the vulnerable image
  verify    -> confirm the box stood up (liveness + vulnerable-version presence)
  save      -> persist spec.json + Dockerfile + build log under targets/<id>/

SCOPE / SAFETY (see README.md): this instantiates the vulnerable ENVIRONMENT
from PUBLISHED advisory information and describes the intended chain as
operator-side ground truth referencing CVE IDs. It does NOT discover
unpublished vulnerabilities and does NOT author or run weaponized exploit code
-- exploitation is the lab attacker agent's job, and verification here is
liveness/version presence only, never an exploit. This mirrors the lab's
existing hand-built CVE targets (wordpress/, dealer) and the hard-won rule that
vulnerable services are built from docs, not live-PoC testing.

Stdlib only (urllib), like ingest.py / labctl -- the LLM call hits the same GMI
OpenAI-compatible endpoint pipeline/providers/gmi.py uses. Swap in
pipeline.providers for multi-backend later.
"""

from __future__ import annotations

import argparse
import json
import os
import subprocess
import time
import urllib.request

import cve_feed
from spec import CVERef, TargetSpec, VerificationCheck, new_id

ROOT = os.path.dirname(os.path.abspath(__file__))
TARGETS_DIR = os.path.join(ROOT, "targets")
DEFAULT_MODEL = "moonshotai/kimi-k3"
GMI_DEFAULT_BASE = "https://api.gmi-serving.com/v1"


# --------------------------------------------------------------------------- #
# env + LLM
# --------------------------------------------------------------------------- #

def load_dotenv(path: str) -> None:
    """Minimal .env -> os.environ loader (only sets keys not already present).
    Worktrees don't carry the gitignored .env, so point --env-file at the main
    checkout's .env, or export GMI_API_KEY yourself."""
    if not path or not os.path.exists(path):
        return
    with open(path) as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith("#") or "=" not in line:
                continue
            k, v = line.split("=", 1)
            k, v = k.strip(), v.strip().strip('"').strip("'")
            os.environ.setdefault(k, v)


def llm_complete(system: str, user: str, model: str, temperature: float = 0.7,
                 max_tokens: int = 16000, timeout: int = 600) -> str:
    """One-shot completion via the GMI OpenAI-compatible /chat/completions.

    Reasoning models (kimi-k3) split output into `reasoning_content` (the think
    trace) and `content` (the answer); a big prompt can spend the whole budget
    thinking and leave `content` empty, so max_tokens is generous and we fall
    back to the reasoning field when the answer field carries no JSON. A
    default urllib User-Agent is 403'd by GMI -- set one."""
    api_key = os.environ.get("GMI_API_KEY")
    if not api_key:
        raise SystemExit("[designer] GMI_API_KEY not set (pass --env-file /home/josh/soc-lab/.env)")
    base = os.environ.get("GMI_OPENAPI_HOST", GMI_DEFAULT_BASE).rstrip("/")
    body = json.dumps({
        "model": model,
        "messages": [{"role": "system", "content": system},
                     {"role": "user", "content": user}],
        "temperature": temperature,
        "max_tokens": max_tokens,
    }).encode()
    req = urllib.request.Request(
        f"{base}/chat/completions", data=body,
        headers={"Authorization": f"Bearer {api_key}",
                 "Content-Type": "application/json",
                 "User-Agent": "soc-lab-target-designer/0.1"})
    with urllib.request.urlopen(req, timeout=timeout) as r:
        data = json.load(r)
    msg = data["choices"][0]["message"]
    content = msg.get("content") or ""
    if "{" in content:
        return content
    # answer field starved / empty -> the JSON often lands at the end of the
    # reasoning trace instead.
    return msg.get("reasoning_content") or content


def extract_json(text: str) -> dict:
    """Last balanced JSON object in the text (models often narrate first)."""
    dec = json.JSONDecoder()
    best, idx = None, 0
    while True:
        start = text.find("{", idx)
        if start == -1:
            break
        try:
            obj, end = dec.raw_decode(text, start)
            best, idx = obj, end
        except json.JSONDecodeError:
            idx = start + 1
    if best is None:
        raise ValueError("no JSON object found in model output")
    return best


# --------------------------------------------------------------------------- #
# stages
# --------------------------------------------------------------------------- #

def discover(days: int, min_cvss: float, pool_size: int = 40) -> tuple[list[dict], list[dict]]:
    cves = cve_feed.fetch_recent_cves(days_back=days, min_cvss=min_cvss,
                                      max_results=pool_size * 6)
    foothold = [c for c in cves if c["role"] == "foothold"][:pool_size]
    privesc = [c for c in cves if c["role"] == "privesc"][:pool_size]
    return foothold, privesc


def _candidate_line(c: dict) -> str:
    prods = ", ".join(c["products"][:3]) or "(no CPE listed)"
    return (f"- {c['id']} (CVSS {c['cvss']}, {c.get('published', '')[:10]}, "
            f"CWE {','.join(c['cwes']) or '?'}) products=[{prods}]: {c['description'][:220]}")


DESIGN_SYSTEM = """You are a security lab TARGET DESIGNER. You build intentionally-vulnerable, \
dockerized practice hosts for an AUTHORIZED, network-isolated research range -- the same kind of \
box as Vulhub or a HackTheBox machine. Your job is to compose recent, PUBLISHED CVEs into ONE \
Linux host that an autonomous attacker agent must then compromise on its own.

Hard rules:
- Build the vulnerable ENVIRONMENT only: pick real, published CVEs and describe how to install the \
affected software at the vulnerable version. Reference CVEs by ID.
- Do NOT write working/weaponized exploit code, payloads, or a step-by-step attack script. The \
chain_narrative is operator ground-truth prose (what the intended path IS, at a high level, \
referencing the CVE IDs) -- an answer key, not an exploit.
- Verification checks are NON-exploit only: service liveness, an open port, or a version/banner \
string that proves the vulnerable build is present. Never an exploitation step.
- Prefer a foothold CVE that yields code execution as an unprivileged service user, plus a privesc \
CVE in a component that plausibly coexists on the same host, so the intended path is foothold -> \
local privilege escalation -> root. If a clean pair isn't available, say so in chain_narrative and \
design the best single-stage box you can.
- Favor free/open-source software that actually installs in a Debian/Ubuntu container.

Return ONE JSON object, no prose around it, with EXACTLY these keys:
{
  "title": str,
  "base_image": str,                      // e.g. "debian:12", "ubuntu:22.04"
  "foothold": {"cve","product","version","summary"},
  "privesc":  {"cve","product","version","summary"},  // use "" fields if single-stage
  "chain_narrative": str,                 // operator answer-key, references CVE IDs, no exploit code
  "dockerfile_steps": [str],              // ordered RUN/COPY/ENV/EXPOSE lines (no FROM line)
  "listening": [{"port": int, "service": str, "proto": "tcp"}],
  "verification": [{"name","kind","check","expect"}],  // kind in http|cmd|port
  "difficulty_notes": str
}"""


def design(foothold: list[dict], privesc: list[dict], model: str) -> TargetSpec:
    user = (
        "Compose a chainable target from these recently-published CVEs.\n\n"
        f"FOOTHOLD candidates (RCE / injection / deserialization):\n"
        + "\n".join(_candidate_line(c) for c in foothold[:20])
        + "\n\nPRIVESC candidates (local privilege escalation):\n"
        + ("\n".join(_candidate_line(c) for c in privesc[:20]) or "(none surfaced this window -- design a single-stage box)")
        + "\n\nPick the most buildable, plausible pair and return the JSON spec."
    )
    raw = llm_complete(DESIGN_SYSTEM, user, model=model)
    try:
        d = extract_json(raw)
    except ValueError:
        dbg = os.path.join(TARGETS_DIR, "_last_design_failure.txt")
        os.makedirs(TARGETS_DIR, exist_ok=True)
        with open(dbg, "w") as f:
            f.write(raw)
        raise SystemExit(f"[designer] model returned no parseable JSON; raw saved to {dbg}")
    fh = d.get("foothold", {}) or {}
    pe = d.get("privesc", {}) or {}
    spec = TargetSpec(
        id=new_id(fh.get("cve", ""), pe.get("cve", "")),
        title=d.get("title", "untitled target"),
        base_image=d.get("base_image", "debian:12"),
        foothold=CVERef(cve=fh.get("cve", ""), product=fh.get("product", ""),
                        version=fh.get("version", ""), role="foothold", summary=fh.get("summary", "")),
        privesc=CVERef(cve=pe.get("cve", ""), product=pe.get("product", ""),
                       version=pe.get("version", ""), role="privesc", summary=pe.get("summary", "")),
        chain_narrative=d.get("chain_narrative", ""),
        dockerfile_steps=list(d.get("dockerfile_steps", [])),
        listening=list(d.get("listening", [])),
        verification=[VerificationCheck(**{k: v.get(k, "") for k in ("name", "kind", "check", "expect")})
                      for v in d.get("verification", [])],
        difficulty_notes=d.get("difficulty_notes", ""),
        designed_by=model,
        created_at=time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        extra={},
    )
    return spec, raw


def generate_dockerfile(spec: TargetSpec) -> str:
    lines = [
        f"# Auto-generated by target-designer for {spec.id}",
        f"# Chain: {spec.foothold.cve or '-'} (foothold) -> {spec.privesc.cve or '-'} (privesc)",
        f"# NOTE: intentionally-vulnerable lab target. Isolated range use only.",
        f"FROM {spec.base_image}",
        f'LABEL soc-lab.target-id="{spec.id}"',
        f'LABEL soc-lab.foothold-cve="{spec.foothold.cve}"',
        f'LABEL soc-lab.privesc-cve="{spec.privesc.cve}"',
        "ENV DEBIAN_FRONTEND=noninteractive",
    ]
    lines += list(spec.dockerfile_steps)
    # Only add our own EXPOSE for ports the model didn't already EXPOSE itself.
    already_exposed = {p for s in spec.dockerfile_steps if s.strip().upper().startswith("EXPOSE")
                       for p in s.split()[1:]}
    ports = [str(l.get("port")) for l in spec.listening
             if l.get("port") and str(l.get("port")) not in already_exposed]
    if ports:
        lines.append("EXPOSE " + " ".join(sorted(set(ports))))
    # Drop exact-duplicate ENV/EXPOSE lines (model + generator can overlap),
    # keeping first occurrence and original order.
    seen, deduped = set(), []
    for ln in lines:
        key = ln.strip()
        if key.upper().startswith(("ENV ", "EXPOSE ")) and key in seen:
            continue
        seen.add(key)
        deduped.append(ln)
    return "\n".join(deduped) + "\n"


def build(spec: TargetSpec, target_dir: str, timeout: int = 1800) -> tuple[bool, str]:
    """docker build the vulnerable image. Returns (ok, log tail)."""
    tag = f"soclab-td/{spec.id}:latest"
    proc = subprocess.run(
        ["docker", "build", "-t", tag, "-f", os.path.join(target_dir, "Dockerfile"), target_dir],
        capture_output=True, text=True, timeout=timeout)
    log = proc.stdout + "\n" + proc.stderr
    with open(os.path.join(target_dir, "build.log"), "w") as f:
        f.write(log)
    spec.extra["image_tag"] = tag
    spec.extra["build_ok"] = proc.returncode == 0
    return proc.returncode == 0, log[-2000:]


def save(spec: TargetSpec, dockerfile: str, raw: str | None = None) -> str:
    out = spec.save(TARGETS_DIR)
    with open(os.path.join(out, "Dockerfile"), "w") as f:
        f.write(dockerfile)
    if raw is not None:
        with open(os.path.join(out, "design.raw.txt"), "w") as f:
            f.write(raw)
    return out


# --------------------------------------------------------------------------- #
# CLI
# --------------------------------------------------------------------------- #

def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--stage", choices=["discover", "design", "generate", "build", "all"], default="all")
    ap.add_argument("--days", type=int, default=45)
    ap.add_argument("--min-cvss", type=float, default=8.5)
    ap.add_argument("--model", default=DEFAULT_MODEL)
    ap.add_argument("--env-file", default=os.path.join(os.path.dirname(ROOT), ".env"),
                    help="path to .env with GMI_API_KEY (default: repo-root .env)")
    ap.add_argument("--no-build", action="store_true", help="stop before docker build")
    args = ap.parse_args()
    load_dotenv(args.env_file)

    print(f"[designer] discover: recent CVEs (last {args.days}d, CVSS>={args.min_cvss})")
    foothold, privesc = discover(args.days, args.min_cvss)
    print(f"[designer]   {len(foothold)} foothold, {len(privesc)} privesc candidates")
    if args.stage == "discover":
        print(json.dumps({"foothold": foothold[:10], "privesc": privesc[:10]}, indent=2))
        return
    if not foothold:
        raise SystemExit("[designer] no foothold candidates in this window -- widen --days / lower --min-cvss")

    print(f"[designer] design: composing a chain via {args.model} …")
    spec, raw = design(foothold, privesc, args.model)
    dockerfile = generate_dockerfile(spec)
    out = save(spec, dockerfile, raw)
    print(f"[designer]   spec: {spec.id}")
    print(f"[designer]   {spec.title}")
    print(f"[designer]   foothold {spec.foothold.cve} ({spec.foothold.product} {spec.foothold.version})")
    print(f"[designer]   privesc  {spec.privesc.cve} ({spec.privesc.product} {spec.privesc.version})")
    print(f"[designer]   saved -> {out}")
    if args.stage in ("design", "generate") or args.no_build:
        print(f"[designer] (stopping before build; Dockerfile written to {out}/Dockerfile)")
        return

    print(f"[designer] build: docker build {spec.id} …")
    ok, tail = build(spec, out)
    spec.save(TARGETS_DIR)  # persist build result into spec.json
    print(f"[designer]   build {'OK' if ok else 'FAILED'} (log: {out}/build.log)")
    if not ok:
        print(tail)


if __name__ == "__main__":
    main()
