#!/usr/bin/env python3
"""Agentic target designer -- turn recent, published CVEs into a chainable,
buildable lab host.

Pipeline stages (run one with --stage, or the lot with --stage all):

  discover  -> pull recent foothold (RCE/injection) + privesc (LPE) CVEs (cve_feed)
  design    -> an LLM composes ONE foothold + ONE privesc into a single-host
               chain scenario and a docker build recipe (a TargetSpec)
  generate  -> assemble the Dockerfile from the spec
  build     -> build -> verify -> repair loop: docker build, run the non-exploit
               checks, and feed any build/verify failure back to the model for a
               corrected Dockerfile, up to --max-repair attempts
  verify    -> confirm the box stood up (liveness + vulnerable-version presence)
  deploy    -> (--deploy) wire it into the lab via the dealer range: soclab-dealer
               bridge + Suricata + the permanent Wazuh /lab-logs/dealer buckets
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


# Top-level keys that mark a real design/repair object (a spec, or a repair
# result). Used to pick the RIGHT balanced object rather than blindly the last.
_EXPECTED_KEYS = frozenset({"foothold", "privesc", "dockerfile_steps", "title", "base_image"})


def extract_json(text: str) -> dict:
    """Return the design/repair JSON object from the model's text.

    Scans EVERY balanced object and prefers the largest one carrying an expected
    top-level key (foothold/dockerfile_steps/title/...). This is deliberately NOT
    'the last balanced object': a reasoning model routinely emits the spec and
    then trailing prose (or a malformed/unterminated top-level object), and the
    naive last-object scan grabs a nested fragment -- e.g. a single verification
    check {name,kind,check,expect} -- yielding an empty spec that then builds a
    junk target. If nothing spec-shaped parses (the real object was malformed),
    raise ValueError so the caller fails loudly with the raw saved."""
    dec = json.JSONDecoder()
    candidates, idx = [], 0
    while True:
        start = text.find("{", idx)
        if start == -1:
            break
        try:
            obj, end = dec.raw_decode(text, start)
            if isinstance(obj, dict):
                candidates.append(obj)
            idx = end
        except json.JSONDecodeError:
            idx = start + 1
    spec_like = [o for o in candidates if _EXPECTED_KEYS & o.keys()]
    if spec_like:
        return max(spec_like, key=lambda o: len(json.dumps(o)))
    if candidates:
        raise ValueError("model output had JSON fragments but no spec-shaped object "
                         "(the top-level object was likely malformed/unterminated)")
    raise ValueError("no JSON object found in model output")


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
string that proves the vulnerable build is present. Never an exploitation step. Checks run INSIDE \
the container against loopback, so: an "http" check's `check` is a URL on http://127.0.0.1:<port>/… \
and its `expect` is JUST the numeric status code (e.g. "200" or "401"); a "cmd" check's `expect` is \
a SHORT LITERAL substring that appears verbatim in the command's stdout (e.g. "2.0.12"), not a \
sentence; a "port" check's `check` is the port number and `expect` is "open".
- Prefer a foothold CVE that yields code execution as an unprivileged service user, plus a privesc \
CVE in a component that plausibly coexists on the same host, so the intended path is foothold -> \
local privilege escalation -> root. If a clean pair isn't available, say so in chain_narrative and \
design the best single-stage box you can.
- Favor free/open-source software that actually installs in a Debian/Ubuntu container.
- STRONGLY prefer software with a LIGHT, FAST container build -- a single binary, a Go/PHP/Java/\
Node/small-daemon app, or an apt package -- over heavy Python ML / data-science stacks (torch, \
transformers, large requirements.txt) that take many minutes to install. Install ONLY the packages \
needed to run the vulnerable component, never a project's full dependency tree.
- The box runs on an ISOLATED, NO-EGRESS bridge, so it must be fully self-contained at \
runtime (all deps installed at build time; nothing fetched on first request).
- Every service must LOG TO STDOUT/STDERR (run in the foreground) so the range's telemetry \
wiring captures it into the SIEM. Prefer a foreground entrypoint that starts each service \
without backgrounding its logs to a file only.

Output ONLY the JSON object -- nothing before it, nothing after it, no prose, no
commentary, no code fences. Emit exactly one complete, well-formed JSON object and
STOP. (Trailing explanation after the JSON corrupts the parse.) The object has
EXACTLY these keys:
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


def _fail_design(raw: str, reason: str):
    """Save the raw model output and exit loudly. A failed design must NOT
    silently become a junk target -- surface it (same principle as the reset
    exit-code fix)."""
    dbg = os.path.join(TARGETS_DIR, "_last_design_failure.txt")
    os.makedirs(TARGETS_DIR, exist_ok=True)
    with open(dbg, "w") as f:
        f.write(raw)
    raise SystemExit(f"[designer] DESIGN FAILED: {reason}. Raw output saved to {dbg} "
                     "-- re-run to try again (design is non-deterministic).")


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
    except ValueError as e:
        _fail_design(raw, f"no parseable spec in the model output ({e})")
    fh = d.get("foothold", {}) or {}
    pe = d.get("privesc", {}) or {}
    # Validity guard: a parseable-but-degenerate spec (no CVE, or no build steps)
    # is a FAILED design, not a target. Reject it here rather than let it build a
    # bare image that "verifies" vacuously and lands in the catalog as junk.
    if not (fh.get("cve") or pe.get("cve")):
        _fail_design(raw, "the design named no foothold/privesc CVE")
    if not d.get("dockerfile_steps"):
        _fail_design(raw, "the design has no dockerfile_steps (nothing to build)")
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


def build(spec: TargetSpec, target_dir: str, timeout: int = 600) -> tuple[bool, str]:
    """docker build the vulnerable image. Returns (ok, log tail). A build that
    exceeds `timeout` is a REPAIRABLE failure (return False with an explicit
    timeout note), not a crash -- an over-heavy dependency install is the most
    common one, and repair should slim it rather than wait 30 minutes."""
    tag = f"soclab-td/{spec.id}:latest"
    try:
        proc = subprocess.run(
            ["docker", "build", "-t", tag, "-f", os.path.join(target_dir, "Dockerfile"), target_dir],
            capture_output=True, text=True, timeout=timeout)
        log = (proc.stdout or "") + "\n" + (proc.stderr or "")
        rc = proc.returncode
    except subprocess.TimeoutExpired as e:
        # On timeout, subprocess returns stdout/stderr as BYTES even with
        # text=True -- coerce before concatenating.
        def _s(x):
            if x is None:
                return ""
            return x if isinstance(x, str) else x.decode("utf-8", "replace")
        log = (_s(e.stdout) + "\n" + _s(e.stderr)
               + f"\n[designer] docker build exceeded {timeout}s and was killed -- "
                 "the dependency install is too slow/heavy for a lab target; "
                 "install ONLY the minimal packages needed to run the vulnerable component.")
        rc = 124
    with open(os.path.join(target_dir, "build.log"), "w") as f:
        f.write(log)
    spec.extra["image_tag"] = tag
    spec.extra["build_ok"] = rc == 0
    return rc == 0, log[-2500:]


def _docker(args: list[str], timeout: int = 60) -> subprocess.CompletedProcess:
    return subprocess.run(["docker", *args], capture_output=True, text=True, timeout=timeout)


def run_and_verify(spec: TargetSpec, tag: str, warmup_s: int = 12,
                   retries: int = 3) -> tuple[list[dict], str]:
    """Start the image on a NO-EGRESS throwaway container and run the spec's
    NON-EXPLOIT checks (port open / http status / version-or-config string) via
    docker exec against loopback inside the container. Returns (results, logs).
    Each result: {name, ok, inconclusive, detail}. Never runs an exploit."""
    name = f"td-verify-{spec.id[-12:]}"
    _docker(["rm", "-f", name])
    run = _docker(["run", "-d", "--name", name, "--network", "none", tag])
    if run.returncode != 0:
        return ([{"name": "container-start", "ok": False, "inconclusive": False,
                  "detail": (run.stderr or run.stdout)[-800:]}], "")
    results: list[dict] = []
    try:
        for check in spec.verification:
            ok = inconc = False
            detail = ""
            for _ in range(retries):
                ok, inconc, detail = _run_check(name, check)
                if ok or inconc:
                    break
                time.sleep(warmup_s / retries)
            results.append({"name": check.name, "ok": ok, "inconclusive": inconc, "detail": detail})
        logs = (_docker(["logs", "--tail", "80", name]).stdout or "")[-3000:]
    finally:
        _docker(["rm", "-f", name])
    return results, logs


def _run_check(container: str, check: "VerificationCheck") -> tuple[bool, bool, str]:
    """(ok, inconclusive, detail) for one non-exploit check."""
    import re
    if check.kind == "port":
        m = re.search(r"\d+", check.check)
        if not m:
            return (False, True, "no port in check")
        port = m.group()
        r = _docker(["exec", container, "bash", "-lc",
                     f"timeout 3 bash -c '</dev/tcp/127.0.0.1/{port}' && echo OPEN || echo SHUT"])
        return ("OPEN" in (r.stdout or ""), False, (r.stdout or r.stderr).strip()[:200])
    if check.kind == "http":
        m = re.search(r"https?://\S+", check.check)
        url = m.group() if m else check.check
        # Checks run INSIDE the container against loopback; the spec may address
        # the deploy hostname ("target", the opaque dealer name) which doesn't
        # resolve here -- rewrite the host to 127.0.0.1, keep the :port and path.
        url = re.sub(r"://[^/:]+", "://127.0.0.1", url)
        r = _docker(["exec", container, "bash", "-lc",
                     f"curl -s -o /dev/null -w '%{{http_code}}' {url} 2>/dev/null || "
                     f"python3 -c \"import urllib.request as u;print(u.urlopen('{url}').status)\" 2>/dev/null"])
        code = (r.stdout or "").strip()[:10]
        if not code or code == "000":
            return (False, False, "no http response")
        # expect may be prose ("200 OK; body contains…") -- accept any HTTP
        # status codes it mentions; if it names none, a real response = alive.
        codes = re.findall(r"[1-5]\d\d", check.expect or "")
        if codes:
            return (code in codes, False, f"http {code} (want {'/'.join(codes)})")
        return (True, False, f"http {code} (alive)")
    if check.kind == "cmd":
        r = _docker(["exec", container, "bash", "-lc", check.check])
        out = ((r.stdout or "") + (r.stderr or "")).strip()
        exp = (check.expect or "").strip()
        # A short literal expect is a real substring assertion; a long/prose
        # expect (the model describing what should be true) degrades to "the
        # command ran and produced output" liveness.
        if exp and len(exp) <= 24 and " " not in exp:
            return (exp in out, False, out[:200])
        return (r.returncode == 0 and bool(out), False, out[:200])
    return (False, True, f"unknown check kind {check.kind!r}")


REPAIR_SYSTEM = """You are fixing the Dockerfile for an intentionally-vulnerable LAB TARGET so it \
BUILDS and RUNS. You are given the target spec, the current Dockerfile, and the failure output \
(a docker build error, or a runtime verification failure). Return corrected build steps.

CRITICAL: do NOT 'fix' the vulnerability or change the pinned vulnerable versions/commits -- the \
box is SUPPOSED to be vulnerable. Only change what stops the image building or the services coming \
up (wrong package name, missing dependency, bad path, wrong download URL, entrypoint that exits, a \
service that backgrounds instead of logging to stdout, needing egress at runtime, etc.). Keep every \
service logging to stdout/stderr and fully self-contained (no network at runtime).

Return ONE JSON object, no prose: {"base_image": str, "dockerfile_steps": [str], "notes": str}
(omit base_image to keep it). dockerfile_steps is the FULL corrected list of RUN/COPY/ENV/EXPOSE/CMD \
lines, no FROM line."""


def repair(spec: TargetSpec, dockerfile: str, failure: str, model: str) -> TargetSpec:
    """One LLM repair turn: given the failure, return a spec with corrected
    build steps. Preserves the CVEs/vulnerable versions."""
    user = (
        f"TARGET: {spec.title}\nCVEs: foothold {spec.foothold.cve} ({spec.foothold.product} "
        f"{spec.foothold.version}), privesc {spec.privesc.cve} ({spec.privesc.product} "
        f"{spec.privesc.version})\n\nCURRENT DOCKERFILE:\n{dockerfile}\n\n"
        f"FAILURE OUTPUT:\n{failure[-6000:]}\n\nReturn the corrected JSON."
    )
    raw = llm_complete(REPAIR_SYSTEM, user, model=model)
    d = extract_json(raw)
    if d.get("base_image"):
        spec.base_image = d["base_image"]
    if d.get("dockerfile_steps"):
        spec.dockerfile_steps = list(d["dockerfile_steps"])
    spec.extra.setdefault("repair_notes", []).append(d.get("notes", ""))
    return spec


def run_build_repair(spec: TargetSpec, out: str, model: str, max_attempts: int = 4,
                     do_verify: bool = True, build_timeout: int = 600) -> tuple[bool, int]:
    """build -> (run + verify) -> repair on failure -> retry, up to max_attempts.
    Persists the Dockerfile + build log each attempt and the outcome into
    spec.json. Returns (ok, attempts_used)."""
    for attempt in range(1, max_attempts + 1):
        dockerfile = generate_dockerfile(spec)
        with open(os.path.join(out, "Dockerfile"), "w") as f:
            f.write(dockerfile)
        print(f"[designer]   attempt {attempt}/{max_attempts}: docker build (cap {build_timeout}s) …")
        ok, tail = build(spec, out, timeout=build_timeout)
        if not ok:
            print(f"[designer]   build FAILED (see {out}/build.log)")
            failure = "DOCKER BUILD FAILED:\n" + tail
        elif do_verify:
            print(f"[designer]   build OK; verifying (non-exploit liveness/version) …")
            results, logs = run_and_verify(spec, spec.extra["image_tag"])
            fails = [r for r in results if not r["ok"] and not r["inconclusive"]]
            for r in results:
                mark = "ok" if r["ok"] else ("??" if r["inconclusive"] else "FAIL")
                print(f"[designer]     [{mark}] {r['name']}: {r['detail'][:80]}")
            spec.extra["verification_results"] = results
            if not fails:
                # Zero checks passing is not "verified" -- it's unverified. The
                # design guard should prevent stepless specs reaching here, but
                # don't stamp a hollow success either way.
                spec.extra["status"] = "built+verified" if results else "built (no checks)"
                if not results:
                    print("[designer]   WARNING: spec had no verification checks -- built but UNVERIFIED")
                spec.save(TARGETS_DIR)
                return True, attempt
            failure = ("BUILD OK but VERIFICATION FAILED:\n"
                       + "\n".join(f"- {r['name']}: {r['detail']}" for r in fails)
                       + f"\n\nCONTAINER LOGS:\n{logs}")
        else:
            spec.extra["status"] = "built"
            spec.save(TARGETS_DIR)
            return True, attempt
        if attempt == max_attempts:
            break
        print(f"[designer]   repairing via {model} …")
        spec = repair(spec, dockerfile, failure, model)
        spec.save(TARGETS_DIR)
    spec.extra["status"] = "build-repair-exhausted"
    spec.save(TARGETS_DIR)
    return False, max_attempts


def deploy_via_dealer(tag: str, repo_root: str, do_wire: bool = True) -> bool:
    """Wire a built target into the lab by handing the image to the dealer range
    -- reusing its opaque-hostname standup on the internal soclab-dealer bridge
    and wire.py (Suricata + the permanent Wazuh /lab-logs/dealer buckets). This
    is the SAME path `lab-mode.sh switch dealer <image-ref>` takes, so no
    parallel wiring. NB: this switches the lab's active mode to dealer and tears
    down whatever else is up -- caller confirms.

    cwd pinned to repo_root (nested compose cwd-drift is a known trap)."""
    lab_mode = os.path.join(repo_root, "lab-mode.sh")
    print(f"[designer]   deploy: ./lab-mode.sh switch dealer {tag}")
    p = subprocess.run([lab_mode, "switch", "dealer", tag], cwd=repo_root,
                       capture_output=True, text=True, timeout=900)
    print(p.stdout[-1500:])
    if p.returncode != 0:
        print(f"[designer]   deploy FAILED:\n{p.stderr[-800:]}")
        return False
    # lab-mode.sh's dealer path already runs `make -C dealer-range wire`; keep an
    # explicit wire here as a belt-and-suspenders no-op re-run if requested.
    if do_wire:
        subprocess.run(["make", "-C", os.path.join(repo_root, "dealer-range"), "wire"],
                       cwd=repo_root, capture_output=True, text=True, timeout=600)
    return True


def save(spec: TargetSpec, dockerfile: str, raw: str | None = None) -> str:
    out = spec.save(TARGETS_DIR)
    with open(os.path.join(out, "Dockerfile"), "w") as f:
        f.write(dockerfile)
    if raw is not None:
        with open(os.path.join(out, "design.raw.txt"), "w") as f:
            f.write(raw)
    return out


# --------------------------------------------------------------------------- #
# catalog
# --------------------------------------------------------------------------- #

def catalog_entries() -> list[dict]:
    """Every saved target under targets/<id>/spec.json, newest first, with the
    fields a picker needs: id, title, the CVEs, freshness (created_at + CVE
    dates), and whether the image is built locally right now. This is the
    committed, versioned catalog (spec.json + Dockerfile are tracked; the image
    and build log are not -- rebuild a missing image with --from-spec <id>)."""
    out = []
    if not os.path.isdir(TARGETS_DIR):
        return out
    for tid in sorted(os.listdir(TARGETS_DIR)):
        specp = os.path.join(TARGETS_DIR, tid, "spec.json")
        if not os.path.exists(specp):
            continue
        try:
            with open(specp) as f:
                s = json.load(f)
        except (OSError, json.JSONDecodeError):
            continue
        tag = (s.get("extra") or {}).get("image_tag") or f"soclab-td/{s.get('id', tid)}:latest"
        out.append({
            "id": s.get("id", tid),
            "title": s.get("title", ""),
            "foothold": (s.get("foothold") or {}).get("cve", ""),
            "privesc": (s.get("privesc") or {}).get("cve", ""),
            "created_at": s.get("created_at", ""),
            "image_tag": tag,
            "image_built": _image_built(tag),
            "has_dockerfile": os.path.exists(os.path.join(TARGETS_DIR, tid, "Dockerfile")),
        })
    out.sort(key=lambda e: e["created_at"], reverse=True)
    return out


def _image_built(tag: str) -> bool:
    try:
        r = subprocess.run(["docker", "image", "inspect", tag],
                           stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=15)
        return r.returncode == 0
    except (OSError, subprocess.SubprocessError):
        return False


def print_catalog() -> None:
    entries = catalog_entries()
    if not entries:
        print(f"[designer] catalog empty (no spec.json under {TARGETS_DIR}/). "
              "Mint one with --stage all.")
        return
    print(f"{'ID':<38} {'BUILT':<6} {'FOOTHOLD':<16} {'PRIVESC':<16} TITLE")
    print("-" * 110)
    for e in entries:
        built = "yes" if e["image_built"] else ("recipe" if e["has_dockerfile"] else "NO")
        print(f"{e['id']:<38} {built:<6} {e['foothold']:<16} {e['privesc']:<16} {e['title'][:40]}")
    print(f"\n{len(entries)} target(s). Stand one up: ./lab-mode.sh switch dealer <image_tag>  "
          "(rebuild a missing image first: designer.py --from-spec <id> --no-... )")


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
    ap.add_argument("--max-repair", type=int, default=4,
                    help="max build->verify->repair attempts (default 4)")
    ap.add_argument("--build-timeout", type=int, default=600,
                    help="per-attempt docker build cap in seconds; a timeout is a repairable "
                         "failure (repair slims over-heavy deps), default 600")
    ap.add_argument("--no-verify", action="store_true",
                    help="accept a clean build; skip the runtime non-exploit verification")
    ap.add_argument("--from-spec", default=None,
                    help="skip discover+design: load an existing targets/<id>/spec.json (by id or "
                         "path) and run build->verify->repair on it")
    ap.add_argument("--deploy", action="store_true",
                    help="after a good build, wire the target into the lab via the dealer "
                         "range (soclab-dealer bridge + Suricata + Wazuh). NB: switches the "
                         "active lab mode to dealer.")
    ap.add_argument("--list-catalog", action="store_true",
                    help="list the committed target catalog (targets/<id>/spec.json) and exit")
    args = ap.parse_args()
    load_dotenv(args.env_file)

    if args.list_catalog:
        print_catalog()
        return

    if args.from_spec:
        path = args.from_spec
        if not path.endswith(".json"):
            path = os.path.join(TARGETS_DIR, path, "spec.json")
        from spec import TargetSpec as _TS
        spec = _TS.from_dict(json.load(open(path)))
        out = os.path.dirname(path)
        print(f"[designer] from-spec: {spec.id} ({spec.title})")
        ok, attempts = run_build_repair(spec, out, args.model, max_attempts=args.max_repair, build_timeout=args.build_timeout,
                                        do_verify=not args.no_verify)
        print(f"[designer]   {'BUILT' if ok else 'FAILED'} after {attempts} attempt(s); "
              f"image={spec.extra.get('image_tag', '-')}")
        if ok and args.deploy:
            deploy_via_dealer(spec.extra["image_tag"], os.path.dirname(ROOT))
        return

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

    print(f"[designer] build: build->verify->repair (max {args.max_repair} attempts) …")
    ok, attempts = run_build_repair(spec, out, args.model, max_attempts=args.max_repair, build_timeout=args.build_timeout,
                                    do_verify=not args.no_verify)
    print(f"[designer]   {'BUILT' if ok else 'FAILED'} after {attempts} attempt(s); "
          f"image={spec.extra.get('image_tag', '-')} (log: {out}/build.log)")
    if not ok:
        print(f"[designer]   giving up -- inspect {out}/ and re-run with a higher --max-repair")
        return
    if args.deploy:
        repo_root = os.path.dirname(ROOT)
        print(f"[designer] deploy: wiring {spec.id} into the lab (dealer range) …")
        deploy_via_dealer(spec.extra["image_tag"], repo_root)


if __name__ == "__main__":
    main()
