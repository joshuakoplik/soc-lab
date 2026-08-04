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


def _cap(text, max_chars):
    if len(text) <= max_chars:
        return text, False
    return text[:max_chars] + f"\n...[truncated, {len(text) - max_chars} more chars]", True


def run(argv, timeout_s=DEFAULT_TIMEOUT_S, max_output_chars=DEFAULT_MAX_OUTPUT_CHARS):
    """Run argv inside soc-attacker. Never raises for a nonzero exit or a
    timeout -- always returns an ExecResult, same "never raises, let the
    caller decide is_error" contract as agent.py's dispatch_tool(). Only
    raises for things that are the CALLER's bug: an out-of-scope target
    should be caught by validate_target() before this is ever called.

    `timeout` wraps the command INSIDE the container (not just the local
    subprocess) -- killing the local `docker exec` client process does not
    reliably stop the remote process otherwise. Confirmed present in the
    provisioned Kali image: `docker exec soc-attacker which timeout`.
    """
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
