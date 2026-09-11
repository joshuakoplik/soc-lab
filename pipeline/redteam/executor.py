"""
Runs commands inside the soc-attacker Kali container via `docker exec`.

The one execution primitive redteam_agent.py's tools are built on. Deliberately
NOT a subpackage like pipeline/providers/ -- there's exactly one backend here
(docker exec into one named container), nothing to swap, no Protocol to
justify the extra structure.

Scope fencing lives here, not just in tool schemas: validate_target() is the
check redteam_agent.py's dispatch_tool() calls BEFORE run() is ever reached
-- a JSON-schema "enum" on a tool's target parameter is advisory (models
don't always respect schema outside a grammar-locked call, see
providers/local.py), this is not. The allowed set itself is NOT a static
constant here -- it comes from lab_modes.active_config()["targets"], which
depends on lab_mode.json (see lab_modes.py). Easy mode allows cowrie/nginx/
metasploitable; hard mode allows nginx only, because cowrie and
metasploitable aren't even running in that mode. Re-read on every call
rather than cached at import time, so a mode switch mid-process (unlikely,
but --continue-assess resumes an old session) can't leave this checking
against a stale allowlist.

ALLOWED_NETWORKS is a separate, narrower question: not "can this name be
touched at all" but "is it fully inside our own lab, such that a gated
action against it is safe to run without a human approval round trip".
in_whitelisted_network() resolves the target the same way soc-attacker's
own DNS would and checks the result against ALLOWED_NETWORKS -- see
redteam_agent.py's tool_propose_action() and execute_pending_action() for
where that answer changes behavior.

soc-attacker is multi-homed onto every mode's network at once (see
compose.yaml / pipeline/net_topology.py) -- a DIFFERENT address on each --
so most functions below take an optional `mode` (defaulting to
lab_modes.current_mode()) to know WHICH of soc-attacker's several
interfaces/addresses a given call actually means. This only matters
because more than one mode can be up simultaneously now; a fresh clone
running a single mode at a time behaves exactly as before.
"""

import ipaddress
import os
import random
import shlex
import subprocess
import sys
import time
from dataclasses import dataclass

HERE = os.path.dirname(os.path.abspath(__file__))
PIPELINE = os.path.dirname(HERE)
if HERE not in sys.path:
    sys.path.insert(0, HERE)
if PIPELINE not in sys.path:
    sys.path.insert(0, PIPELINE)
import lab_modes  # noqa: E402
import net_topology  # noqa: E402

CONTAINER = "soc-attacker"

# Every mode's subnet -- what lets a gated action against an in-lab target
# skip the human approval gate entirely: it's contained and reversible by
# construction, regardless of difficulty mode. Was a single-element list
# (one shared bridge); now one entry per net_topology.LAB_NETWORKS, since
# soc-attacker's targets are no longer all on the same subnet.
ALLOWED_NETWORKS = [net.subnet for net in net_topology.LAB_NETWORKS]

DEFAULT_TIMEOUT_S = 120
DEFAULT_MAX_OUTPUT_CHARS = 16000

# /loot inside soc-attacker IS ROOT/attacker/loot on the host (compose.yaml).
# The monitored run() path streams a tool's output to a host file under here
# and, to actually STOP the remote process on an idle kill, reads back a
# pidfile the in-container wrapper writes under the same mount -- so it needs
# to translate a host loot path into its container view. Same two-views-of-one
# directory that agent.py's _loot_paths() deals in; duplicated (not imported)
# because executor.py is deliberately import-light and agent.py imports IT,
# not the other way round.
ROOT = os.path.dirname(PIPELINE)
LOOT_HOST_DIR = os.path.join(ROOT, "attacker", "loot")
LOOT_CONTAINER_DIR = "/loot"


def _to_container_path(host_path):
    """Host loot path -> its view inside soc-attacker. Returns None if the
    path isn't under the loot mount (so the caller falls back to a non-pidfile
    kill rather than pointing the container at a path it can't see)."""
    ap = os.path.abspath(host_path)
    if ap.startswith(LOOT_HOST_DIR + os.sep):
        return LOOT_CONTAINER_DIR + "/" + os.path.relpath(ap, LOOT_HOST_DIR).replace(os.sep, "/")
    return None


# Non-progress ("idle") detection policy for long-running tool calls. Time is
# NOT a scarce resource in this lab -- a thorough scan is worth waiting for --
# so the monitored run() path (see run(stream_path=...)) never kills a call
# for elapsed wall-clock alone; it kills only a call that has produced no new
# output for idle_timeout_s (a wedge that will never return), and the
# in-container `timeout` is a generous BACKSTOP for the one case idle can't
# catch: a retry loop that logs steadily forever (progresses by this metric).
#   - idle_timeout_s: no output growth this long -> non-progress -> kill.
#     Well above a "one line every 30s" cadence so honest slow-drip tools
#     aren't killed; generous enough to absorb output-buffering jitter.
#   - max_wall_s: absolute backstop, a backstop not a budget -- the one knob
#     to raise if a legitimately thorough scan ever approaches it.
#   - poll_interval_s: how often the host monitor samples output size.
# CPU consumption is deliberately NOT a liveness signal: an infinite loop
# burns CPU while producing nothing, so treating CPU as progress would let
# exactly the wedge we care about walk straight through.
#
# VERSIONED: cross-session comparison is meaningless if a threshold silently
# changed between runs, so every red-team session records the version it ran
# under (redteam_sessions.hang_policy_version). Bump HANG_POLICY_VERSION on
# ANY change to the values below.
HANG_POLICY_VERSION = 1
HANG_POLICY = {
    "idle_timeout_s": int(os.environ.get("REDTEAM_IDLE_TIMEOUT_S", "120")),
    "max_wall_s": int(os.environ.get("REDTEAM_MAX_WALL_S", "1800")),
    "poll_interval_s": int(os.environ.get("REDTEAM_POLL_INTERVAL_S", "5")),
}


def hang_policy_snapshot():
    """The resolved policy a session is about to run under, for recording on
    the session row (see agent.start_session)."""
    return {"version": HANG_POLICY_VERSION, **HANG_POLICY}


class ScopeError(Exception):
    """Raised when a tool call names a target outside the active mode's
    allowed targets. Never reaches run() -- the whole point is that
    redteam_exec.run() only ever sees argv that already passed this check."""


def validate_target(target):
    allowed = lab_modes.active_config()["targets"]
    if target not in allowed:
        raise ScopeError(
            f"{target!r} is not an allowed target in {lab_modes.current_mode()!r} "
            f"mode (allowed: {sorted(allowed)})"
        )


def resolve_target_ip(target, mode=None):
    """The host's resolver doesn't know soclab's service names -- ask
    soc-attacker, which is on the same bridge(s) and shares Docker's
    embedded DNS. Resolves the NETWORK-QUALIFIED name (e.g.
    "nginx.soclab-easy") rather than a bare hostname: soc-attacker is
    multi-homed across every mode's network at once, so a bare "nginx"
    is ambiguous the moment more than one mode is up and each has its own
    container answering to that alias (see compose.yaml). Returns None on
    any resolution failure rather than raising: an unresolvable target
    just means "not whitelisted", not a hard error."""
    net = net_topology.by_mode(mode or lab_modes.current_mode())
    qualified = f"{target}.{net.compose_name}"
    result = run(["getent", "hosts", qualified], timeout_s=10)
    if result.exit_code != 0 or not result.stdout.strip():
        return None
    return result.stdout.split()[0]


def in_whitelisted_network(target, mode=None):
    """True if `target` resolves to an address inside ALLOWED_NETWORKS.
    Distinct from ALLOWED_TARGETS/validate_target(): that's a name allowlist
    gating whether redteam_exec touches something at all; this is an IP-range
    check gating whether a gated action against it may skip human approval
    and run at full intensity."""
    ip_str = resolve_target_ip(target, mode)
    if not ip_str:
        return False
    try:
        ip = ipaddress.ip_address(ip_str)
    except ValueError:
        return False
    return any(ip in net for net in ALLOWED_NETWORKS)


def in_single_scope_action(adapter_cfg, tool):
    """True if `tool` is one of an adapter-backed mode's single-scope actions
    (one chat turn, one ingestion write) and may auto-approve. The
    adapter-mode analogue of in_whitelisted_network() above: that function
    answers "is this target's IP inside our own lab subnet"; there is no IP
    to check for an HTTP application reached through a target adapter rather
    than a Docker-container address, so this checks tool scope instead.
    Only called when the active mode's "adapter" is set (see lab_modes.py)
    -- container-target modes keep using in_whitelisted_network() unchanged."""
    return tool in adapter_cfg.get("single_scope_tools", ())


@dataclass
class ExecResult:
    argv: list
    exit_code: "int | None"
    timed_out: bool
    stdout: str
    stderr: str
    truncated: bool
    elapsed_s: float
    # Why a monitored call stopped: 'idle' (no output for idle_timeout_s),
    # 'wall' (hit the absolute backstop), or None (ran to completion, or the
    # simple unmonitored path). Purely observability -- callers still key off
    # timed_out/exit_code the same as before.
    kill_reason: "str | None" = None


def _cap(text, max_chars):
    if len(text) <= max_chars:
        return text, False
    return text[:max_chars] + f"\n...[truncated, {len(text) - max_chars} more chars]", True


def run(argv, timeout_s=DEFAULT_TIMEOUT_S, max_output_chars=DEFAULT_MAX_OUTPUT_CHARS,
        stream_path=None, own_output_path=None,
        idle_timeout_s=None, max_wall_s=None):
    """Run argv inside soc-attacker. Never raises for a nonzero exit or a
    timeout -- always returns an ExecResult, same "never raises, let the
    caller decide is_error" contract as agent.py's dispatch_tool(). Only
    raises for things that are the CALLER's bug: an out-of-scope target
    should be caught by validate_target() before this is ever called.

    Two execution modes:

    - SIMPLE (stream_path is None): the historical path, unchanged. Used by
      every short internal helper here (getent / ip addr / awk, timeout_s<=10)
      and anything that doesn't need progress monitoring. `timeout` wraps the
      command INSIDE the container (not just the local subprocess) -- killing
      the local `docker exec` client process does not reliably stop the remote
      process otherwise. Confirmed present in the provisioned Kali image:
      `docker exec soc-attacker which timeout`.

    - MONITORED (stream_path set, a HOST path under the loot mount): for the
      long-running attack tools (nmap/hydra/sqlmap/msf/ssh/shell). Output is
      STREAMED to stream_path as bytes arrive rather than buffered in memory
      and returned at the end -- so a killed call still leaves everything it
      wrote in loot instead of nothing. The call is killed only for
      NON-PROGRESS (no output growth for idle_timeout_s), never for elapsed
      wall-clock alone; max_wall_s is an in-container backstop for the one
      wedge idle can't see (a retry loop that logs steadily forever). stdin is
      closed (DEVNULL) so nothing can block waiting on a prompt. See
      HANG_POLICY. `own_output_path` is an optional second host file the tool
      writes directly (e.g. nmap -oN): its growth also counts as progress, in
      case the tool block-buffers its stdout under a non-tty docker exec.
    """
    if stream_path is None:
        full_argv = ["docker", "exec", CONTAINER, "timeout", f"{timeout_s}s", *argv]
        t0 = time.monotonic()
        try:
            proc = subprocess.run(
                full_argv, capture_output=True, text=True, timeout=timeout_s + 10
            )
            elapsed_s = time.monotonic() - t0
            stdout, out_trunc = _cap(proc.stdout, max_output_chars)
            stderr, err_trunc = _cap(proc.stderr, max_output_chars)
            return ExecResult(
                argv=argv,
                exit_code=proc.returncode,
                timed_out=False,
                stdout=stdout,
                stderr=stderr,
                truncated=out_trunc or err_trunc,
                elapsed_s=elapsed_s,
            )
        except subprocess.TimeoutExpired as e:
            elapsed_s = time.monotonic() - t0
            stdout, out_trunc = _cap(e.stdout.decode("utf-8", "replace") if e.stdout else "", max_output_chars)
            stderr, err_trunc = _cap(e.stderr.decode("utf-8", "replace") if e.stderr else "", max_output_chars)
            return ExecResult(
                argv=argv,
                exit_code=None,
                timed_out=True,
                stdout=stdout,
                stderr=stderr,
                truncated=out_trunc or err_trunc,
                elapsed_s=elapsed_s,
            )

    return _run_monitored(argv, max_output_chars, stream_path, own_output_path,
                          idle_timeout_s if idle_timeout_s is not None else HANG_POLICY["idle_timeout_s"],
                          max_wall_s if max_wall_s is not None else HANG_POLICY["max_wall_s"])


def _observed_bytes(*paths):
    """Total bytes across the streamed-output file and any tool-written file.
    Growth in EITHER is progress -- summed (not maxed) so a tool that writes
    only to its own -oN file while its stdout stays quiet still registers."""
    total = 0
    for p in paths:
        if not p:
            continue
        try:
            total += os.path.getsize(p)
        except OSError:
            pass
    return total


def _kill_remote(ctr_pidfile):
    """Best-effort stop of the in-container process tree via the pidfile the
    wrapper wrote (see _run_monitored). Killing the local `docker exec` client
    does NOT reliably reach the remote process, so an idle kill has to reach in
    and signal it; the in-container `timeout -s KILL` is the guaranteed backstop
    if this misses (e.g. the pidfile hasn't been written yet)."""
    if not ctr_pidfile:
        return
    script = (
        f"p=$(cat {shlex.quote(ctr_pidfile)} 2>/dev/null); "
        f'[ -n "$p" ] && {{ kill -TERM "$p" 2>/dev/null; sleep 2; kill -KILL "$p" 2>/dev/null; }}; :'
    )
    try:
        subprocess.run(["docker", "exec", CONTAINER, "sh", "-c", script],
                       capture_output=True, text=True, timeout=20)
    except (subprocess.SubprocessError, OSError):
        pass


def _run_monitored(argv, max_output_chars, stream_path, own_output_path,
                   idle_timeout_s, max_wall_s):
    os.makedirs(os.path.dirname(stream_path), exist_ok=True)
    ctr_pidfile = _to_container_path(stream_path)
    ctr_pidfile = ctr_pidfile + ".pid" if ctr_pidfile else None

    # In-container wrapper: record the wrapper's own PID (which `exec` then
    # hands to `timeout`, so it's the right thing to signal on an idle kill),
    # then self-limit at the wall backstop with a hard KILL and force
    # line-buffered output so a live tool's stdout can't sit block-buffered
    # long enough to look idle. shlex.quote each argv element -- argv can be
    # arbitrary (shell_exec passes ["bash","-c",<command>]).
    inner = " ".join(shlex.quote(a) for a in argv)
    # mkdir -p the pidfile's dir first: if the write silently failed (the dir
    # not existing in the container is the easy way for that to happen), the
    # pidfile would be empty and an idle kill couldn't reach the remote
    # process -- it would run on until the in-container `timeout` wall
    # backstop, defeating idle-detection for exactly the wedge case it exists
    # to stop.
    if ctr_pidfile:
        pid_stmt = (f"mkdir -p {shlex.quote(os.path.dirname(ctr_pidfile))} 2>/dev/null; "
                    f"echo $$ > {shlex.quote(ctr_pidfile)}; ")
    else:
        pid_stmt = ""
    wrapper = f"{pid_stmt}exec timeout -s KILL {int(max_wall_s)}s stdbuf -oL -eL {inner}"
    full_argv = ["docker", "exec", CONTAINER, "sh", "-c", wrapper]

    poll = max(1, HANG_POLICY["poll_interval_s"])
    t0 = time.monotonic()
    kill_reason = None
    ret = None
    with open(stream_path, "wb") as out:
        proc = subprocess.Popen(
            full_argv, stdin=subprocess.DEVNULL, stdout=out, stderr=subprocess.STDOUT
        )
        last_bytes = _observed_bytes(stream_path, own_output_path)
        last_progress = t0
        while True:
            try:
                ret = proc.wait(timeout=poll)
                break
            except subprocess.TimeoutExpired:
                pass
            now = time.monotonic()
            seen = _observed_bytes(stream_path, own_output_path)
            if seen != last_bytes:
                last_bytes = seen
                last_progress = now
            if idle_timeout_s and (now - last_progress) >= idle_timeout_s:
                kill_reason = "idle"
                break
            # Host-side backstop only -- the in-container `timeout` should have
            # already fired at max_wall_s; this catches the case where it
            # didn't (missing binary, wedged docker exec client).
            if max_wall_s and (now - t0) >= max_wall_s + 15:
                kill_reason = "wall"
                break
        if kill_reason:
            _kill_remote(ctr_pidfile)
            try:
                proc.kill()
                ret = proc.wait(timeout=10)
            except (subprocess.SubprocessError, OSError):
                ret = None

    elapsed_s = time.monotonic() - t0
    try:
        with open(stream_path, "r", encoding="utf-8", errors="replace") as f:
            raw = f.read()
    except OSError:
        raw = ""
    stdout, out_trunc = _cap(raw, max_output_chars)

    # GNU `timeout` reports 124 on a plain timeout and 128+9=137 when it had to
    # SIGKILL; docker exec propagates that. Treat those (and our own kills) as
    # timed_out regardless of exact code, and label the in-container-timeout
    # case 'wall' so it reads the same as our host-side backstop.
    if kill_reason is None and ret in (124, 137):
        kill_reason = "wall"
    timed_out = kill_reason is not None
    return ExecResult(
        argv=argv,
        exit_code=None if timed_out else ret,
        timed_out=timed_out,
        stdout=stdout,
        stderr="",  # stdout/stderr are merged into the single streamed log
        truncated=out_trunc,
        elapsed_s=elapsed_s,
        kill_reason=kill_reason,
    )


def _iface_for_network(net):
    """The interface inside soc-attacker whose address falls inside
    net.subnet -- found by matching addresses against the subnet, not by
    guessing an interface name. soc-attacker now has one non-loopback
    interface PER mode network (eth0/eth1/eth2, in whatever order Docker
    happened to attach them -- not a contract worth relying on), so "the
    first non-lo interface" (the old single-network approach) is no longer
    well-defined; matching by address against a known subnet is."""
    result = run(["ip", "-o", "-4", "addr", "show"], timeout_s=10)
    for line in result.stdout.splitlines():
        parts = line.split()
        if len(parts) < 4:
            continue
        iface, cidr = parts[1], parts[3]
        try:
            addr = ipaddress.ip_interface(cidr)
        except ValueError:
            continue
        if addr.ip in net.subnet:
            return iface
    return None


def attacker_ip(mode=None):
    """soc-attacker's own bridge IP on the given (or current) mode's
    network right now -- the join key that lets a later query correlate
    candidates.src_ip against this session, and what MSF's LHOST needs to
    be for a reverse shell to land back on the right segment. Reads the
    live interface address (ip -4 addr show), deliberately NOT
    `hostname -i`: confirmed live, Docker's own /etc/hosts entry for the
    container's hostname reflects whatever IP it was assigned at container
    creation and does NOT update when rotate_ip() changes an interface's
    actual address -- hostname -i silently goes stale after a rotation,
    which is exactly the case this function most needs to get right. Also
    ambiguous today regardless (soc-attacker has three addresses, not
    one), which is the whole reason this takes `mode` now."""
    net = net_topology.by_mode(mode or lab_modes.current_mode())
    iface = _iface_for_network(net)
    if not iface:
        return None
    result = run(["sh", "-c", f"ip -o -4 addr show dev {iface} | awk '{{print $4}}'"], timeout_s=10)
    addr = result.stdout.strip()
    return addr.split("/")[0] if addr else None


class RotateIPError(Exception):
    """rotate_ip() failed. Never leaves soc-attacker without a working
    address on the network it was rotating -- see rotate_ip()'s
    rollback-on-failure."""


def _used_ips(net):
    """Every IP currently assigned to a container on net's bridge, via
    `docker network inspect` (run on the HOST, not through soc-attacker --
    this is the one function in this module that doesn't go through run()).
    rotate_ip() uses this to avoid colliding with a real container, not
    just guessing an address and hoping. Scoped to the ONE network being
    rotated (not a union of all three) -- a fresh IP only needs to avoid
    collisions on the segment it's actually joining."""
    proc = subprocess.run(
        ["docker", "network", "inspect", net.compose_name,
         "-f", "{{range .Containers}}{{.IPv4Address}} {{end}}"],
        capture_output=True, text=True, timeout=10,
    )
    if proc.returncode != 0:
        raise RotateIPError(f"docker network inspect failed: {proc.stderr.strip()}")
    ips = set()
    for tok in proc.stdout.split():
        addr = tok.split("/")[0]
        try:
            ips.add(ipaddress.ip_address(addr))
        except ValueError:
            pass
    return ips


def rotate_ip(mode=None):
    """Give soc-attacker a fresh IP on the given (or current) mode's
    network, abandoning its current one there -- an evasion tactic against
    IP-based detection/blocking (see triage/agent.py's block_ip). Only
    ever touches the ONE interface belonging to this mode's network; the
    other two (soc-attacker's addresses on the other modes' networks, if
    those are also up) are left completely alone. Never draws a candidate
    outside this mode's own subnet: checked against docker's own live
    container list (_used_ips) so it can't collide with a real target, and
    the swap runs entirely inside soc-attacker's own network namespace via
    `ip addr` (it already has NET_ADMIN -- see compose.yaml) -- nothing
    here reaches outside the container it's rotating.

    Returns {"old_ip", "new_ip"} on success. Raises RotateIPError on any
    failure, and rolls back to the original address first if the swap left
    the container in a half-changed state, so a failed rotation never
    leaves soc-attacker unreachable on that network."""
    net = net_topology.by_mode(mode or lab_modes.current_mode())
    subnet = net.subnet
    old_ip = attacker_ip(mode=net.mode)
    if not old_ip:
        raise RotateIPError(f"could not determine soc-attacker's current IP on {net.compose_name}")

    reserved = _used_ips(net)
    reserved.add(subnet.network_address)
    reserved.add(subnet.broadcast_address)
    reserved.add(net.gateway)

    candidates = [h for h in subnet.hosts() if h not in reserved]
    if not candidates:
        raise RotateIPError(f"no free address left in {subnet}")
    new_ip = str(random.choice(candidates))

    iface = _iface_for_network(net)
    if not iface:
        raise RotateIPError(f"could not determine soc-attacker's interface on {net.compose_name}")

    prefixlen = subnet.prefixlen
    del_result = run(["ip", "addr", "del", f"{old_ip}/{prefixlen}", "dev", iface], timeout_s=10)
    if del_result.exit_code != 0:
        raise RotateIPError(
            f"failed to remove old address {old_ip}: {del_result.stderr.strip()} "
            "-- left unchanged, still on the original IP"
        )

    add_result = run(["ip", "addr", "add", f"{new_ip}/{prefixlen}", "dev", iface], timeout_s=10)
    if add_result.exit_code != 0:
        # Roll back rather than leave the container with no address at all.
        restore = run(["ip", "addr", "add", f"{old_ip}/{prefixlen}", "dev", iface], timeout_s=10)
        if restore.exit_code != 0:
            raise RotateIPError(
                f"failed to assign {new_ip} ({add_result.stderr.strip()}) AND "
                f"failed to restore {old_ip} ({restore.stderr.strip()}) -- "
                "soc-attacker may be unreachable on this network, needs manual recovery"
            )
        raise RotateIPError(
            f"failed to assign {new_ip}: {add_result.stderr.strip()} "
            f"-- rolled back to {old_ip}"
        )

    confirm = attacker_ip(mode=net.mode)
    if confirm != new_ip:
        raise RotateIPError(
            f"assigned {new_ip} but soc-attacker now reports {confirm!r} on {net.compose_name} -- "
            "verify manually, reset.sh does not cover this"
        )
    return {"old_ip": old_ip, "new_ip": new_ip}
