"""
Real enforcement backend for the defender's block_ip tool. Runs iptables
inside the soc-block-enforcer container (see compose.yaml -- network_mode:
host, cap_add NET_ADMIN/NET_RAW) via `docker exec`, always as a fixed argv
list, never a shell string -- there is no command-injection surface here
regardless of what src_ip contains, because src_ip is validated to a bare
IPv4 address before it ever reaches a subprocess call.

network_mode: host is what makes this work at all: inter-container traffic
on any soclab-* bridge is filtered through the HOST's netfilter DOCKER-USER
chain (Docker's own documented hook point for user-inserted container
filtering) -- a container on its own bridge netns can't reach that chain.

Hard fencing, two independent layers, so a block can't affect anything
outside this lab's own docker networks no matter what src_ip the model
passes:
  1. validate_lab_ip() rejects anything that isn't a syntactically valid
     IPv4 address inside one of net_topology.LAB_NETWORKS, and separately
     rejects each network's own bridge gateway. Nothing below this point
     ever runs for a rejected IP -- no subprocess is even spawned.
  2. Every rule inserted is interface-scoped (`-i <bridge>`, that
     specific mode's bridge only) -- so even if layer 1 had a bug, a
     DOCKER-USER rule matching one bridge interface is structurally
     incapable of matching traffic that didn't arrive via that specific
     bridge. The host's real NICs, other Docker networks, and everything
     else stay untouched by construction, not by caller discipline.

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

Multi-homed attacker, one real-world wrinkle: soc-attacker sits on all
three lab networks at once (see pipeline/net_topology.py) with a
DIFFERENT address on each. A source IP found in one alert is only ever
one of its three current identities -- blocking just that one leaves the
other two completely free, since a real blacklist rule matches an
address, not an entity. block() special-cases this: if the IP being
blocked is currently one of soc-attacker's own addresses, every one of
its current addresses gets a rule, not just the one an alert happened to
name. Nothing else in the lab is multi-homed, so this stays a targeted
special case rather than a general N-addresses-per-IP mechanism.
"""

import ipaddress
import os
import subprocess
import sys

HERE = os.path.dirname(os.path.abspath(__file__))       # pipeline/triage
PIPELINE = os.path.dirname(HERE)                          # pipeline
if PIPELINE not in sys.path:
    sys.path.insert(0, PIPELINE)
import net_topology  # noqa: E402

ENFORCER_CONTAINER = "soc-block-enforcer"
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
    address inside one of this lab's subnets and isn't that subnet's own
    gateway -- runs before any subprocess is ever spawned, so a rejected IP
    never reaches the docker/iptables layer at all. Every rejection prints
    loudly first (see _fence_hit) -- this function is the one place all of
    them funnel through, so every caller gets that for free.

    Returns (ip_str, bridge_iface) -- the multi-subnet-aware replacement
    for the old single LAB_SUBNET/BRIDGE_IFACE constants: which lab
    network an IP belongs to determines which bridge interface a rule
    against it has to be scoped to."""
    try:
        ip = ipaddress.ip_address(str(src_ip).strip())
    except (ValueError, AttributeError):
        _fence_hit(src_ip, "not a valid IP address")
        raise BlockError(f"{src_ip!r} is not a valid IP address")
    if ip.version != 4:
        _fence_hit(src_ip, "not IPv4")
        raise BlockError(f"{src_ip!r} is not IPv4")
    net = net_topology.network_for_ip(ip)
    if net is None:
        subnets = ", ".join(str(n.subnet) for n in net_topology.LAB_NETWORKS)
        why = f"outside every known lab subnet ({subnets})"
        _fence_hit(src_ip, why)
        raise BlockError(f"{src_ip!r} is {why} -- refusing to touch anything "
                          "outside this lab's own docker networks")
    if ip == net.gateway:
        _fence_hit(src_ip, f"this is the {net.compose_name} bridge gateway")
        raise BlockError(f"{src_ip!r} is the {net.compose_name} bridge gateway -- refusing to block it")
    return str(ip), net.bridge_iface


def _docker_exec(argv, timeout_s=10):
    full = ["docker", "exec", ENFORCER_CONTAINER] + argv
    try:
        return subprocess.run(full, capture_output=True, text=True, timeout=timeout_s)
    except subprocess.TimeoutExpired as e:
        raise BlockError(f"enforcer command timed out: {e}")
    except FileNotFoundError as e:
        raise BlockError(f"docker CLI not available on host: {e}")


def _rule_argv(ip, iface):
    return ["iptables", "-i", iface, "-s", ip, "-j", "DROP",
            "-m", "comment", "--comment", RULE_COMMENT]


def _attacker_addresses():
    """soc-attacker's address on each lab network it's currently attached
    to, live -- {compose_name: ip_str}. Not cached/static: rotate_ip()
    (executor.py) changes these at runtime, same reason validate_lab_ip()
    re-derives everything from net_topology rather than a snapshot. Runs
    on the HOST (not through soc-block-enforcer -- this is plain `docker
    inspect`, no iptables involved), returns {} on any failure rather than
    raising, since this is only ever used to decide whether to fan a block
    out further, never to gate whether blocking is allowed at all."""
    result = subprocess.run(
        ["docker", "inspect", net_topology.ATTACKER_CONTAINER,
         "--format", "{{range $net, $cfg := .NetworkSettings.Networks}}{{$net}}={{$cfg.IPAddress}}\n{{end}}"],
        capture_output=True, text=True, timeout=10,
    )
    if result.returncode != 0:
        return {}
    addrs = {}
    for line in result.stdout.splitlines():
        if "=" not in line:
            continue
        net_name, ip = line.split("=", 1)
        if ip:
            addrs[net_name] = ip
    return addrs


def _block_targets(ip_str):
    """The (ip, iface) pairs a block/unblock of ip_str should actually
    apply to. Normally just [(ip_str, its own iface)] -- but if ip_str is
    currently one of soc-attacker's own addresses, every one of its
    current addresses is included too (see module docstring)."""
    ip, iface = validate_lab_ip(ip_str)
    targets = [(ip, iface)]
    attacker_addrs = _attacker_addresses()
    if ip in attacker_addrs.values():
        for net_name, addr in attacker_addrs.items():
            if addr == ip:
                continue
            try:
                addr_net = net_topology.network_for_ip(ipaddress.ip_address(addr))
            except ValueError:
                continue
            if addr_net is not None:
                targets.append((addr, addr_net.bridge_iface))
    return targets


def is_blocked(ip, iface):
    r = _docker_exec(["iptables", "-C", "DOCKER-USER"] + _rule_argv(ip, iface)[1:])
    return r.returncode == 0


def block(src_ip):
    """Insert a DROP rule for src_ip, scoped to whichever lab bridge it
    belongs to. Idempotent per target: a repeat call against an
    already-blocked address is a no-op success for that address, not a
    duplicate rule. If src_ip is currently one of soc-attacker's own
    addresses, every one of its current addresses gets blocked too, not
    just this one (see module docstring) -- the return value reports
    every address this call touched, not just the one requested."""
    targets = _block_targets(src_ip)
    results = []
    for ip, iface in targets:
        if is_blocked(ip, iface):
            results.append({"src_ip": ip, "blocked": True, "already_blocked": True})
            continue
        r = _docker_exec(["iptables", "-I", "DOCKER-USER"] + _rule_argv(ip, iface)[1:])
        if r.returncode != 0:
            raise BlockError(f"iptables insert failed for {ip} (exit {r.returncode}): {r.stderr.strip()}")
        results.append({"src_ip": ip, "blocked": True, "already_blocked": False})
    return {
        "ok": True,
        "src_ip": targets[0][0],
        "multi_homed_attacker": len(targets) > 1,
        "blocked_addresses": results,
    }


def unblock(src_ip):
    """Remove the DROP rule for src_ip, if present. Deliberately literal --
    removes exactly the one rule for this one address, no multi-homed
    fan-out (that's a block()-time decision, made with the alert that's
    actually live at that moment; re-deriving "soc-attacker's current
    addresses" at unblock time could easily be a different set if
    rotate_ip() ran in between, silently leaving stale rules behind or
    removing the wrong ones). Used by reset.sh --network (via
    unblock_all(), which iterates list_blocked() -- the actual set of
    rules that exist, so a multi-homed block's rules all get individually
    found and removed there without this function needing to be clever)
    and available for symmetry; the triage agent itself has no unblock
    tool -- undoing a block is a human action."""
    ip, iface = validate_lab_ip(src_ip)
    if not is_blocked(ip, iface):
        return {"ok": True, "unblocked": True, "was_blocked": False, "src_ip": ip}
    r = _docker_exec(["iptables", "-D", "DOCKER-USER"] + _rule_argv(ip, iface)[1:])
    if r.returncode != 0:
        raise BlockError(f"iptables delete failed (exit {r.returncode}): {r.stderr.strip()}")
    return {"ok": True, "unblocked": True, "was_blocked": True, "src_ip": ip}


def list_blocked():
    """Every (ip, iface) currently blocked by this feature -- parses
    `iptables -S DOCKER-USER` for rules carrying RULE_COMMENT, so this
    only ever sees (and reset.sh --network only ever removes) rules this
    feature itself inserted, not anything else that might coexist in that
    chain. Returns iface alongside ip now (was ip-only) since a rule's
    interface is no longer implied by a single global constant."""
    r = _docker_exec(["iptables", "-S", "DOCKER-USER"])
    if r.returncode != 0:
        raise BlockError(f"iptables -S failed: {r.stderr.strip()}")
    blocked = []
    for line in r.stdout.splitlines():
        if RULE_COMMENT not in line:
            continue
        parts = line.split()
        if "-s" not in parts or "-i" not in parts:
            continue
        ip = parts[parts.index("-s") + 1].split("/")[0]
        iface = parts[parts.index("-i") + 1]
        blocked.append((ip, iface))
    return blocked


def unblock_all():
    """Remove every rule this feature has ever inserted. What
    reset.sh --network calls -- the whole point of RULE_COMMENT-tagging every
    rule is that this only ever touches rules bearing that tag, regardless
    of anything else that might independently exist in DOCKER-USER. Iterates
    the actual live rule set (list_blocked()), so a multi-homed block's
    several rules are each found and removed individually here without
    unblock() itself needing any special-casing."""
    removed = []
    for ip, iface in list_blocked():
        r = _docker_exec(["iptables", "-D", "DOCKER-USER"] + _rule_argv(ip, iface)[1:])
        if r.returncode == 0:
            removed.append(ip)
    return removed


if __name__ == "__main__":
    import argparse

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
                for ip, iface in blocked:
                    print(f"{ip} (-i {iface})")
            else:
                print("[block_enforcer] nothing currently blocked")
        else:
            ap.print_help()
            sys.exit(1)
    except BlockError as e:
        print(f"[block_enforcer] ERROR: {e}", file=sys.stderr)
        sys.exit(1)
