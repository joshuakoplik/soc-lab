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
where that answer changes behavior. Unlike the target allowlist, this one
IS static across modes: it's the physical lab subnet, not a function of
which containers happen to be up.
"""

import ipaddress
import os
import random
import subprocess
import sys
import time
from dataclasses import dataclass

HERE = os.path.dirname(os.path.abspath(__file__))
if HERE not in sys.path:
    sys.path.insert(0, HERE)
import lab_modes  # noqa: E402

CONTAINER = "soc-attacker"

# The soclab bridge's subnet (confirmed via `docker network inspect
# soc-lab_soclab`; Docker assigns it, there's no static IPAM config in
# compose.yaml, so re-check if this ever looks stale). Every target reachable
# at all is already inside it -- the mode-specific target allowlist (see
# lab_modes.py) is always a subset of what's reachable here -- so this
# whitelist is what lets a gated action against a lab-internal target skip
# the human approval gate entirely: it's contained and reversible by
# construction, regardless of difficulty mode.
ALLOWED_NETWORKS = [ipaddress.ip_network("10.211.0.0/24")]

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


def resolve_target_ip(target):
    """The host's resolver doesn't know soclab's service names -- ask
    soc-attacker, which is on the same bridge and shares Docker's embedded
    DNS. Returns None on any resolution failure rather than raising: an
    unresolvable target just means "not whitelisted", not a hard error."""
    result = run(["getent", "hosts", target], timeout_s=10)
    if result.exit_code != 0 or not result.stdout.strip():
        return None
    return result.stdout.split()[0]


def in_whitelisted_network(target):
    """True if `target` resolves to an address inside ALLOWED_NETWORKS.
    Distinct from ALLOWED_TARGETS/validate_target(): that's a name allowlist
    gating whether redteam_exec touches something at all; this is an IP-range
    check gating whether a gated action against it may skip human approval
    and run at full intensity."""
    ip_str = resolve_target_ip(target)
    if not ip_str:
        return False
    try:
        ip = ipaddress.ip_address(ip_str)
    except ValueError:
        return False
    return any(ip in net for net in ALLOWED_NETWORKS)


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


def _primary_iface():
    """soc-attacker's one non-loopback interface name (eth0, normally --
    not hardcoded, since that's one guess away from silently doing nothing
    on a differently-named interface)."""
    result = run(
        ["sh", "-c", "ip -o -4 addr show | awk '$2!=\"lo\"{print $2; exit}'"],
        timeout_s=10,
    )
    return result.stdout.strip() or None


def attacker_ip():
    """soc-attacker's own bridge IP right now -- the join key that lets a
    later query correlate candidates.src_ip against this session. Reads
    the live interface address (ip -4 addr show), deliberately NOT
    `hostname -i`: confirmed live, Docker's own /etc/hosts entry for the
    container's hostname reflects whatever IP it was assigned at container
    creation and does NOT update when rotate_ip() changes the interface's
    actual address -- hostname -i silently goes stale after a rotation,
    which is exactly the case this function most needs to get right."""
    iface = _primary_iface()
    if not iface:
        return None
    result = run(["sh", "-c", f"ip -o -4 addr show dev {iface} | awk '{{print $4}}'"], timeout_s=10)
    addr = result.stdout.strip()
    return addr.split("/")[0] if addr else None


DOCKER_NETWORK = "soc-lab_soclab"


class RotateIPError(Exception):
    """rotate_ip() failed. Never leaves soc-attacker without a working
    address -- see rotate_ip()'s rollback-on-failure."""


def _used_ips():
    """Every IP currently assigned to a container on the soclab bridge, via
    `docker network inspect` (run on the HOST, not through soc-attacker --
    this is the one function in this module that doesn't go through run()).
    rotate_ip() uses this to avoid colliding with a real container, not
    just guessing an address and hoping."""
    proc = subprocess.run(
        ["docker", "network", "inspect", DOCKER_NETWORK,
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


def rotate_ip():
    """Give soc-attacker a fresh IP within the lab subnet, abandoning its
    current one -- an evasion tactic against IP-based detection/blocking
    (see triage/agent.py's block_ip). Never touches anything outside
    ALLOWED_NETWORKS: the new address is always drawn from that subnet,
    checked against docker's own live container list (_used_ips) so it
    can't collide with a real target, and the swap runs entirely inside
    soc-attacker's own network namespace via `ip addr` (it already has
    NET_ADMIN -- see compose.yaml) -- nothing here reaches outside the
    container it's rotating.

    Returns {"old_ip", "new_ip"} on success. Raises RotateIPError on any
    failure, and rolls back to the original address first if the swap left
    the container in a half-changed state, so a failed rotation never
    leaves soc-attacker unreachable."""
    subnet = ALLOWED_NETWORKS[0]
    old_ip = attacker_ip()
    if not old_ip:
        raise RotateIPError("could not determine soc-attacker's current IP")

    reserved = _used_ips()
    reserved.add(subnet.network_address)
    reserved.add(subnet.broadcast_address)
    reserved.add(ipaddress.ip_address(int(subnet.network_address) + 1))  # gateway, .1

    candidates = [h for h in subnet.hosts() if h not in reserved]
    if not candidates:
        raise RotateIPError(f"no free address left in {subnet}")
    new_ip = str(random.choice(candidates))

    iface = _primary_iface()
    if not iface:
        raise RotateIPError("could not determine soc-attacker's network interface")

    del_result = run(["ip", "addr", "del", f"{old_ip}/24", "dev", iface], timeout_s=10)
    if del_result.exit_code != 0:
        raise RotateIPError(
            f"failed to remove old address {old_ip}: {del_result.stderr.strip()} "
            "-- left unchanged, still on the original IP"
        )

    add_result = run(["ip", "addr", "add", f"{new_ip}/24", "dev", iface], timeout_s=10)
    if add_result.exit_code != 0:
        # Roll back rather than leave the container with no address at all.
        restore = run(["ip", "addr", "add", f"{old_ip}/24", "dev", iface], timeout_s=10)
        if restore.exit_code != 0:
            raise RotateIPError(
                f"failed to assign {new_ip} ({add_result.stderr.strip()}) AND "
                f"failed to restore {old_ip} ({restore.stderr.strip()}) -- "
                "soc-attacker may be unreachable, needs manual recovery"
            )
        raise RotateIPError(
            f"failed to assign {new_ip}: {add_result.stderr.strip()} "
            f"-- rolled back to {old_ip}"
        )

    confirm = attacker_ip()
    if confirm != new_ip:
        raise RotateIPError(
            f"assigned {new_ip} but soc-attacker now reports {confirm!r} -- "
            "verify manually, reset.sh does not cover this"
        )
    return {"old_ip": old_ip, "new_ip": new_ip}
