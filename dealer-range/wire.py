#!/usr/bin/env python3
"""
Make a freshly-stood-up dealer target OBSERVABLE to the defender.

A dealer target is an arbitrary image live-fetched from Vulhub (see up.py): it
has no wazuh agent, its logs live inside the container in unknown places/formats,
and it lands on the `soclab-dealer` bridge AFTER Suricata has already discovered
its interfaces. So out of the box the defender is blind to it on both legs. This
script, run once after the target is healthy (`make wire`, invoked from `make
up`), wires both:

  NETWORK (Suricata) -- deterministic, no model. Suricata self-discovers
    `soclab-*0` bridges only at entrypoint time (suricata/entrypoint.sh), so a
    bridge created later is missed. If the running soc-suricata isn't already
    capturing `soclab-dealer0`, restart it to re-run discovery. HOME_NET already
    covers 10.211.40.0/24 (suricata/overrides.yaml), so no config edit.

  LOGS (Wazuh) -- a deterministic baseline plus one LLM refinement turn.
    wazuh reads only real files under /lab-logs (./logs bind-mounted ro) named by
    a <localfile> stanza, and copies ossec.conf into place only at boot (no live
    reload). So instead of mutating ossec.conf per image (which would force a
    wazuh restart every time), two PERMANENT dealer buckets live in ossec.conf:
        /lab-logs/dealer/dealer.log   (log_format syslog -- web_accesslog decoder
                                       + 31100 web ruleset fire on access lines;
                                       also the catch-all for plain text)
        /lab-logs/dealer/dealer.json  (log_format json)
    All per-image work is then host-side: tail the target's logs into the right
    bucket file under logs/dealer/, and wazuh picks them up (its logcollector
    tolerates a not-yet-existing path and retries).

    Baseline (always, even if the model turn fails): stream every running
    service's stdout/stderr into the syslog bucket -- the defender is never fully
    blind. Refinement (one LLM turn): inspect each service and, additively,
    re-route a JSON-on-stdout service to the json bucket and exec-tail log files
    the app writes to disk rather than stdout. The LLM import is LAZY and wrapped
    so a provider/import failure degrades to the baseline, never to blindness.

Spawned tailers are detached (survive this process) and recorded in
.run/tailers.json so `make down` can kill them and clear logs/dealer/ -- keeping
a dealer target ephemeral ("like it was never there"). The permanent ossec.conf
buckets stay behind, harmless, pointing at now-absent files.
"""
import json
import os
import secrets
import subprocess
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.dirname(HERE)
RUN = os.path.join(HERE, ".run")
COMPOSE = os.path.join(RUN, "compose.yml")
STATE = os.path.join(RUN, "state.json")
FLAG_MARKER = os.path.join(RUN, "flags-present.json")  # count-only, read by the red-team prompt
FLAG_RECORD = os.path.join(RUN, "flag.json")           # operator-only: the planted flag + path
DEALER_NET = "soclab-dealer"
TAILERS = os.path.join(RUN, "tailers.json")
PROJECT_DIR_FILE = os.path.join(RUN, "project_dir")
LOGDIR = os.path.join(REPO, "logs", "dealer")

PROJECT = "dealer-range"
SURICATA = "soc-suricata"
WAZUH = "soc-wazuh"
DEALER_IFACE = "soclab-dealer0"

# The two permanent ossec.conf buckets. A service's stdout (or an in-container
# log file) is routed to exactly one of these; wazuh's shipped decoders do the
# rest. syslog is the default/catch-all (and gets web detections for free on any
# combined-format access lines); json is for apps that log structured JSON.
BUCKET_FILES = {"syslog": "dealer.log", "json": "dealer.json"}
DEFAULT_BUCKET = "syslog"

LOGS_SAMPLE_LINES = 40
LOG_SAMPLE_CHARS = 2000


def log(msg):
    print(f"[wire] {msg}", file=sys.stderr)


def run(cmd, timeout=30):
    try:
        return subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
    except (subprocess.TimeoutExpired, OSError) as e:
        log(f"command failed ({' '.join(cmd[:3])}...): {e}")
        return None


def container_running(name):
    r = run(["docker", "inspect", "-f", "{{.State.Running}}", name], timeout=15)
    return bool(r and r.returncode == 0 and r.stdout.strip() == "true")


# ---- network leg (Suricata) -------------------------------------------------

def ensure_suricata():
    """Make soc-suricata capture the dealer bridge. Restart only if it isn't
    already -- discovery happens once at entrypoint, so a restart is the one
    mechanism to pick up a bridge created after boot."""
    if not container_running(SURICATA):
        log(f"WARNING: {SURICATA} is not running -- the defender will be blind to "
            f"network traffic on {DEALER_IFACE}. Bring the sensors up.")
        return
    r = run(["docker", "exec", SURICATA, "cat", "/proc/1/cmdline"], timeout=15)
    cmdline = (r.stdout if r and r.returncode == 0 else "") or ""
    if DEALER_IFACE in cmdline.replace("\x00", " "):
        log(f"{SURICATA} already sniffing {DEALER_IFACE}; no restart needed.")
        return
    log(f"{SURICATA} not sniffing {DEALER_IFACE} yet; restarting to re-run interface discovery.")
    rr = run(["docker", "restart", SURICATA], timeout=90)
    if rr and rr.returncode == 0:
        log(f"{SURICATA} restarted.")
    else:
        log(f"WARNING: failed to restart {SURICATA}; network leg may stay blind.")


def warn_if_wazuh_down():
    if not container_running(WAZUH):
        log(f"WARNING: {WAZUH} is not running -- logs will land in logs/dealer/ but "
            f"nothing will consume them until the sensors are up.")


# ---- service enumeration ----------------------------------------------------

def project_dir():
    try:
        with open(PROJECT_DIR_FILE) as f:
            return f.read().strip() or HERE
    except OSError:
        return HERE


def list_services():
    """[{'service','name','cid'}] for every RUNNING service in the dealer
    compose project."""
    r = run(["docker", "compose", "-f", COMPOSE, "--project-directory", project_dir(),
             "-p", PROJECT, "ps", "--status", "running", "--format", "json"], timeout=30)
    if not r or r.returncode != 0 or not r.stdout.strip():
        log("could not list dealer services (compose ps failed or nothing running).")
        return []
    out = r.stdout.strip()
    rows = []
    # docker compose emits either one JSON object per line or a single JSON array.
    try:
        parsed = json.loads(out)
        rows = parsed if isinstance(parsed, list) else [parsed]
    except json.JSONDecodeError:
        for line in out.splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                rows.append(json.loads(line))
            except json.JSONDecodeError:
                continue
    svcs = []
    for row in rows:
        cid = row.get("ID") or row.get("Id")
        svc = row.get("Service") or row.get("Name")
        name = row.get("Name") or svc
        if cid and svc:
            svcs.append({"service": svc, "name": name, "cid": cid})
    return svcs


# ---- fact gathering for the LLM turn ---------------------------------------

_LOG_PROBE = (
    "ls -la /var/log /var/log/apache2 /var/log/nginx /var/log/httpd 2>/dev/null; "
    "find /var/log -maxdepth 3 -name '*.log' 2>/dev/null | head -n 20"
)


def gather_facts(svcs):
    blocks = []
    for s in svcs:
        cid, svc = s["cid"], s["service"]
        img = run(["docker", "inspect", "-f", "{{.Config.Image}}", cid], timeout=15)
        image = (img.stdout.strip() if img and img.returncode == 0 else "?")
        logs = run(["docker", "logs", "--tail", str(LOGS_SAMPLE_LINES), cid], timeout=20)
        sample = ""
        if logs:
            sample = ((logs.stdout or "") + (logs.stderr or ""))[:LOG_SAMPLE_CHARS]
        probe = run(["docker", "exec", cid, "sh", "-c", _LOG_PROBE], timeout=20)
        files = (probe.stdout.strip() if probe and probe.returncode == 0 else
                 "(no shell / no readable log dirs)")
        blocks.append(
            f"### service: {svc}\nimage: {image}\n"
            f"stdout/stderr sample (last {LOGS_SAMPLE_LINES} lines):\n{sample or '(empty)'}\n"
            f"in-container log files:\n{files}\n"
        )
    return "\n".join(blocks)


WIRE_SYSTEM = (
    "You are wiring a freshly-deployed, untrusted lab target's logs into a SIEM "
    "(Wazuh) so a defender can observe it. You are given, per docker service: its "
    "image, a sample of its stdout/stderr, and a listing of log files it writes "
    "inside the container. Decide, for each service, how its logs should reach the "
    "SIEM. There are exactly two destination buckets:\n"
    "  - \"syslog\": plain text and HTTP access/error logs (web-server combined "
    "access logs belong here -- the SIEM has web-attack rules that fire on them).\n"
    "  - \"json\": logs emitted as one JSON object per line.\n"
    "A baseline already tails every service's stdout into the syslog bucket, so you "
    "only need to ADD value:\n"
    "  - set stdout_bucket to \"json\" ONLY if that service's stdout is actually "
    "JSON lines (otherwise \"syslog\");\n"
    "  - list any real log FILE the app writes to disk (not stdout) that carries "
    "security-relevant activity (access logs especially), each with the bucket its "
    "format matches.\n"
    "Respond with ONLY a JSON object, no prose, in exactly this shape:\n"
    "{\"services\": {\"<service-name>\": {\"stdout_bucket\": \"syslog\"|\"json\", "
    "\"files\": [{\"path\": \"/abs/path.log\", \"bucket\": \"syslog\"|\"json\"}]}}}\n"
    "Include only services you were given. Use [] for files when there are none."
)


def wire_plan(facts):
    """One LLM turn -> validated {service: {stdout_bucket, files:[{path,bucket}]}}.
    Returns {} (baseline only) on any import/provider/parse failure. The import of
    the provider stack is deliberately lazy and guarded so the log-leg baseline
    never depends on it."""
    try:
        sys.path.insert(0, os.path.join(REPO, "pipeline"))
        sys.path.insert(0, os.path.join(REPO, "pipeline", "redteam"))
        from providers.base import (_extract_json_object, _strip_trailing_comments,
                                     ProviderError)
        import agent as rt  # the red-team module; reused purely for its provider glue
    except Exception as e:  # noqa: BLE001 -- any import trouble degrades to baseline
        log(f"LLM refinement unavailable ({e!r}); using deterministic baseline only.")
        return {}

    name = os.environ.get("WIRE_PROVIDER", "local")
    model = os.environ.get("WIRE_MODEL") or None
    user = (
        "Wire these services' logs into the SIEM. Services:\n\n" + facts +
        "\n\nRespond with ONLY the JSON object described in the instructions."
    )
    try:
        provider = rt.build_provider(name, model)
        result = rt.run_stage_turn(provider, WIRE_SYSTEM, user, [], rt._no_tools_execute, 1)
        text = result.final_text or ""
        obj = _extract_json_object(_strip_trailing_comments(text))
    except (ProviderError, Exception) as e:  # noqa: BLE001
        log(f"LLM refinement turn failed ({e!r}); using deterministic baseline only.")
        return {}
    if not isinstance(obj, dict) or not isinstance(obj.get("services"), dict):
        log("LLM returned no usable wiring plan; using deterministic baseline only.")
        return {}
    log(f"LLM wiring plan received ({name}/{model or 'default'}).")
    return obj["services"]


# ---- applying the plan: spawn detached tailers ------------------------------

def bucket_path(bucket):
    return os.path.join(LOGDIR, BUCKET_FILES.get(bucket, BUCKET_FILES[DEFAULT_BUCKET]))


def spawn_tailer(cmd, bucket, desc, cid, service):
    """Detached tailer appending to a bucket file; survives this process."""
    try:
        sink = open(bucket_path(bucket), "ab")
    except OSError as e:
        log(f"cannot open bucket for {desc}: {e}")
        return None
    try:
        p = subprocess.Popen(cmd, stdout=sink, stderr=subprocess.STDOUT,
                             stdin=subprocess.DEVNULL, start_new_session=True)
    except OSError as e:
        log(f"failed to start tailer {desc}: {e}")
        sink.close()
        return None
    finally:
        sink.close()  # child keeps its own dup'd fd
    log(f"tailer pid={p.pid}: {desc} -> {BUCKET_FILES[bucket]}")
    return {"pid": p.pid, "cid": cid, "service": service, "desc": desc, "bucket": bucket}


def apply_plan(svcs, plan):
    os.makedirs(LOGDIR, exist_ok=True)
    by_name = {s["service"]: s for s in svcs}
    recorded = []

    # Baseline + stdout re-routing: one stdout/stderr tailer per service, to the
    # bucket the plan assigns (default syslog). docker logs -f dies with the
    # container; --tail 0 = only new lines, no history replay.
    for s in svcs:
        svc, cid = s["service"], s["cid"]
        entry = plan.get(svc) if isinstance(plan.get(svc), dict) else {}
        bucket = entry.get("stdout_bucket")
        if bucket not in BUCKET_FILES:
            bucket = DEFAULT_BUCKET
        rec = spawn_tailer(["docker", "logs", "-f", "--tail", "0", cid],
                           bucket, f"{svc} stdout", cid, svc)
        if rec:
            recorded.append(rec)

    # Refinement: exec-tail in-container log FILES the plan named. Validated:
    # known service, bucket in set, absolute-ish path present.
    for svc, entry in (plan.items() if isinstance(plan, dict) else []):
        if svc not in by_name or not isinstance(entry, dict):
            continue
        cid = by_name[svc]["cid"]
        for f in entry.get("files", []) or []:
            if not isinstance(f, dict):
                continue
            path = f.get("path")
            bucket = f.get("bucket")
            if not isinstance(path, str) or not path.startswith("/"):
                continue
            if bucket not in BUCKET_FILES:
                bucket = DEFAULT_BUCKET
            rec = spawn_tailer(["docker", "exec", cid, "tail", "-n0", "-F", path],
                               bucket, f"{svc} file {path}", cid, svc)
            if rec:
                recorded.append(rec)

    with open(TAILERS, "w") as fh:
        json.dump(recorded, fh, indent=2)
    return recorded


def teardown():
    """Kill the tailers wire.py spawned and clear the dealer log buckets, so no
    orphaned `docker logs -f`/`docker exec tail` survives and the next target
    starts from empty files. Called by `make down` before the compose teardown.
    Best-effort and idempotent -- safe to run when nothing was ever wired."""
    import signal
    killed = 0
    try:
        with open(TAILERS) as fh:
            recorded = json.load(fh)
    except (OSError, ValueError):
        recorded = []
    for t in recorded:
        pid = t.get("pid") if isinstance(t, dict) else None
        if not isinstance(pid, int):
            continue
        try:
            os.kill(pid, signal.SIGTERM)
            killed += 1
        except (ProcessLookupError, PermissionError, OSError):
            pass
    for fname in BUCKET_FILES.values():
        try:
            os.remove(os.path.join(LOGDIR, fname))
        except OSError:
            pass
    for fp in (FLAG_MARKER, FLAG_RECORD):
        try:
            os.remove(fp)
        except OSError:
            pass
    log(f"teardown: killed {killed} tailer(s), cleared dealer log buckets.")
    return 0


def plant_flag():
    """Always plant a FLAG{...} on the dealer/vulhub target at a root-only,
    post-foothold path, and mark it present so the red-team prompt gets its
    location-free find-the-flag objective (policy: always flag vulhub boxes).
    Operator-only record in .run/flag.json; capture is automatic (FLAG_RE over
    tool output). Best-effort: if the target fs won't take it, the box just
    stays unflagged."""
    try:
        st = json.load(open(STATE))
    except (OSError, ValueError):
        st = {}
    container = st.get("hostname") or st.get("primary_service")
    if not container:
        log("no target container to plant a flag in; skipping")
        return
    value = "FLAG{" + secrets.token_hex(8) + "}"
    path = "/root/flag.txt"
    r = run(["docker", "exec", "-u", "0", container, "sh", "-c",
             f'mkdir -p /root && printf "%s\\n" "{value}" > {path} && chmod 600 {path}'], timeout=20)
    if not r or r.returncode != 0:
        log(f"flag plant failed on {container} (non-root fs?); target up, just unflagged")
        return
    with open(FLAG_RECORD, "w") as fh:
        json.dump({"flag": value, "container": container, "path": path}, fh, indent=2)
    with open(FLAG_MARKER, "w") as fh:
        json.dump({DEALER_NET: 1}, fh)
    log(f"planted flag on target {container} ({path}, root-only); marked present for {DEALER_NET}")


def main():
    if "--teardown" in sys.argv[1:]:
        return teardown()
    if not os.path.isfile(COMPOSE):
        log("no .run/compose.yml -- nothing to wire (is the target up?).")
        return 0

    ensure_suricata()
    warn_if_wazuh_down()

    svcs = list_services()
    if not svcs:
        log("no running dealer services found; network leg wired, log leg skipped.")
        with open(TAILERS, "w") as fh:
            json.dump([], fh)
        return 0

    log(f"dealer services: {', '.join(s['service'] for s in svcs)}")
    facts = gather_facts(svcs)
    plan = wire_plan(facts)
    recorded = apply_plan(svcs, plan)
    log(f"wired {len(recorded)} log tailer(s) into logs/dealer/. Defender can see the target.")
    plant_flag()
    return 0


if __name__ == "__main__":
    sys.exit(main())
