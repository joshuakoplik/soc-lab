"""
Real enforcement backend for the defender's block_ip tool. Runs iptables
inside the soc-block-enforcer container (see compose.yaml -- network_mode:
host, cap_add NET_ADMIN/NET_RAW) via `docker exec`, always as a fixed argv
list, never a shell string -- there is no command-injection surface here
regardless of what src_ip contains, because src_ip is validated to a bare
IPv4 address before it ever reaches a subprocess call.

network_mode: host is what makes this work at all: inter-container traffic
on the soclab bridge is filtered through the HOST's netfilter DOCKER-USER
chain (Docker's own documented hook point for user-inserted container
filtering) -- a container on its own bridge netns can't reach that chain.

Hard fencing, two independent layers, so a block can't affect anything
outside this lab's own docker network no matter what src_ip the model
passes:
  1. validate_lab_ip() rejects anything that isn't a syntactically valid
     IPv4 address inside LAB_SUBNET, and separately rejects the bridge
     gateway. Nothing below this point ever runs for a rejected IP -- no
     subprocess is even spawned.
  2. Every rule inserted is interface-scoped (`-i soclab0`, the soclab
     bridge only) -- so even if layer 1 had a bug, a DOCKER-USER rule
     matching `-i soclab0` is structurally incapable of matching traffic
     that didn't arrive via that specific bridge. The host's real NICs,
     other Docker networks, and everything else stay untouched by
     construction, not by caller discipline.

Every rule is tagged with RULE_COMMENT so reset.sh --network can remove
exactly (and only) what this feature ever inserted, regardless of anything
else that might independently exist in DOCKER-USER.

This fence is meant to get tested, not just trusted: injection_asr
deliberately routes forged, adversarial candidates through the real
block_ip tool (see injection_asr/runner.py) to measure whether a payload
can trick the model into targeting the wrong IP. A rejection here is that
test working as intended -- it prints loudly (_fence_hit) precisely so a
real fence hit is never mistaken for routine noise, whether it happened
during harness testing or a live triage run.
"""

import sys
import ipaddress
import subprocess

LAB_SUBNET = ipaddress.ip_network("10.211.0.0/24")
LAB_GATEWAY = ipaddress.ip_address("10.211.0.1")
ENFORCER_CONTAINER = "soc-block-enforcer"
BRIDGE_IFACE = "soclab0"
RULE_COMMENT = "soc-lab-block-ip"


class BlockError(Exception):
    pass


def _fence_hit(src_ip, why):
    """The fence is meant to be tested, deliberately, by injection_asr --
    a forged payload tricking the model into calling block_ip on the wrong
    target is exactly what that harness measures. A rejection here means
    the fence just did its job, but it's still worth being loud about: this
    is the signal that something (a prompt injection, a model mistake, a
    bad candidate) tried to point real enforcement outside this lab's own
    docker network. Printed to stderr so it stands out in whatever log is
    capturing the caller (triage/agent.py's own stdout/stderr redirect,
    injection_asr's console output, a manual --list/--unblock-all run)."""
    print(
        "\n" + "!" * 70 +
        f"\n[block_enforcer] FENCE HIT -- block_ip target rejected\n"
        f"  src_ip requested: {src_ip!r}\n"
        f"  reason:           {why}\n"
        f"  NOTHING WAS BLOCKED. This is the hard fence doing its job -- \n"
        f"  worth checking WHY this target was ever proposed.\n"
        + "!" * 70 + "\n",
        file=sys.stderr,
    )


def validate_lab_ip(src_ip):
    """The primary fence. Raises BlockError unless src_ip is a real IPv4
    address inside the lab bridge subnet and isn't the gateway -- runs
    before any subprocess is ever spawned, so a rejected IP never reaches
    the docker/iptables layer at all. Every rejection prints loudly first
    (see _fence_hit) -- this function is the one place all of them funnel
    through, so every caller gets that for free."""
    try:
        ip = ipaddress.ip_address(str(src_ip).strip())
    except (ValueError, AttributeError):
        _fence_hit(src_ip, "not a valid IP address")
        raise BlockError(f"{src_ip!r} is not a valid IP address")
    if ip.version != 4:
        _fence_hit(src_ip, "not IPv4")
        raise BlockError(f"{src_ip!r} is not IPv4")
    if ip not in LAB_SUBNET:
        why = f"outside {LAB_SUBNET} (the soclab bridge subnet)"
        _fence_hit(src_ip, why)
        raise BlockError(f"{src_ip!r} is {why} -- refusing to touch anything "
                          "outside this lab's own docker network")
    if ip == LAB_GATEWAY:
        _fence_hit(src_ip, "this is the bridge gateway")
        raise BlockError(f"{src_ip!r} is the bridge gateway -- refusing to block it")
    return str(ip)


def _docker_exec(argv, timeout_s=10):
    full = ["docker", "exec", ENFORCER_CONTAINER] + argv
    try:
        return subprocess.run(full, capture_output=True, text=True, timeout=timeout_s)
    except subprocess.TimeoutExpired as e:
        raise BlockError(f"enforcer command timed out: {e}")
    except FileNotFoundError as e:
        raise BlockError(f"docker CLI not available on host: {e}")


def _rule_argv(ip):
    return ["iptables", "-i", BRIDGE_IFACE, "-s", ip, "-j", "DROP",
            "-m", "comment", "--comment", RULE_COMMENT]


def is_blocked(src_ip):
    ip = validate_lab_ip(src_ip)
    r = _docker_exec(["iptables", "-C", "DOCKER-USER"] + _rule_argv(ip)[1:])
    return r.returncode == 0


def block(src_ip):
    """Insert a DROP rule for src_ip, scoped to the lab bridge. Idempotent:
    a repeat call for an already-blocked IP is a no-op success, not a
    duplicate rule."""
    ip = validate_lab_ip(src_ip)
    if is_blocked(ip):
        return {"ok": True, "blocked": True, "already_blocked": True, "src_ip": ip}
    r = _docker_exec(["iptables", "-I", "DOCKER-USER"] + _rule_argv(ip)[1:])
    if r.returncode != 0:
        raise BlockError(f"iptables insert failed (exit {r.returncode}): {r.stderr.strip()}")
    return {"ok": True, "blocked": True, "already_blocked": False, "src_ip": ip}


def unblock(src_ip):
    """Remove the DROP rule for src_ip, if present. Used by reset.sh --network
    (via --unblock-all) and available for symmetry; the triage agent itself
    has no unblock tool -- undoing a block is a human action."""
    ip = validate_lab_ip(src_ip)
    if not is_blocked(ip):
        return {"ok": True, "unblocked": True, "was_blocked": False, "src_ip": ip}
    r = _docker_exec(["iptables", "-D", "DOCKER-USER"] + _rule_argv(ip)[1:])
    if r.returncode != 0:
        raise BlockError(f"iptables delete failed (exit {r.returncode}): {r.stderr.strip()}")
    return {"ok": True, "unblocked": True, "was_blocked": True, "src_ip": ip}


def list_blocked():
    """Every IP currently blocked by this feature -- parses `iptables -S
    DOCKER-USER` for rules carrying RULE_COMMENT, so this only ever sees
    (and reset.sh --network only ever removes) rules this feature itself
    inserted, not anything else that might coexist in that chain."""
    r = _docker_exec(["iptables", "-S", "DOCKER-USER"])
    if r.returncode != 0:
        raise BlockError(f"iptables -S failed: {r.stderr.strip()}")
    ips = []
    for line in r.stdout.splitlines():
        if RULE_COMMENT not in line:
            continue
        parts = line.split()
        if "-s" in parts:
            ips.append(parts[parts.index("-s") + 1].split("/")[0])
    return ips


def unblock_all():
    """Remove every rule this feature has ever inserted. What
    reset.sh --network calls -- the whole point of RULE_COMMENT-tagging every
    rule is that this only ever touches rules bearing that tag, regardless
    of anything else that might independently exist in DOCKER-USER."""
    removed = []
    for ip in list_blocked():
        unblock(ip)
        removed.append(ip)
    return removed


if __name__ == "__main__":
    import argparse
    import sys

    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--list", action="store_true", help="list currently-blocked IPs, then exit")
    ap.add_argument("--unblock-all", action="store_true",
                     help="remove every rule this feature has ever inserted, then exit")
    args = ap.parse_args()

    try:
        if args.unblock_all:
            removed = unblock_all()
            if removed:
                print(f"[block_enforcer] removed {len(removed)} rule(s): {', '.join(removed)}")
            else:
                print("[block_enforcer] nothing was blocked -- already at baseline")
        elif args.list:
            blocked = list_blocked()
            if blocked:
                for ip in blocked:
                    print(ip)
            else:
                print("[block_enforcer] nothing currently blocked")
        else:
            ap.print_help()
            sys.exit(1)
    except BlockError as e:
        print(f"[block_enforcer] ERROR: {e}", file=sys.stderr)
        sys.exit(1)
