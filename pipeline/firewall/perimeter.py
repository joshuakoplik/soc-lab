"""
Perimeter firewall rule generator (PERIMETER_PLAN.md PR3).

Under posture=remote this publishes a mode's `exposed` ports from the internet
segment (soclab-inet) to the inside targets via DNAT, and default-denies (+logs)
everything else, so soc-attacker -- which posture re-homing has put on
soclab-inet ONLY -- reaches inside hosts SOLELY through this firewall. The exact
ruleset was validated by the PR2 spike (see plan Section 6a).

This is DUMB infrastructure: it forwards, NATs, and logs. It never touches
soc.db and never makes a SOC decision. Its logs (FW-ALLOW-THRU / FW-DENY-EXT)
are consumed downstream by Wazuh (PR4), the same "the SIEM reasons over the
logs" model as a cloud firewall's flow logs.

Mechanics mirror block_enforcer.py: every iptables call runs through the
privileged, host-netns `soc-block-enforcer` container -- the one place that can
reach the host's DOCKER-USER chain, where inter-bridge traffic is filtered.

Containment shape:
  - filter: a dedicated chain SOCLAB-PERIMETER, jumped from the top of
    DOCKER-USER. It ACCEPTs only DNAT'd (edge-published) inet->inside flows and
    LOG+DROPs every other inet->inside packet; everything else falls through
    (implicit RETURN) untouched, so ordinary inside<->inside and host<->inside
    traffic is never affected.
  - nat: comment-tagged DNAT (PREROUTING) + MASQUERADE (POSTROUTING) per
    exposed port.
Teardown (clear()) is a clean flush of that chain + removal of the tagged nat
rules; it never touches block_ip's own DROP rules or Docker's chains, and is
always safe to call (idempotent, no-op when nothing is installed).

Ordering vs block_ip: the SOCLAB-PERIMETER jump is inserted at the TOP of
DOCKER-USER at standup; a later block_ip DROP is also inserted at the top, so it
sits ABOVE the jump and correctly wins (the attacker's blocked traffic is
dropped before the perimeter can ACCEPT it). A posture re-apply after a live
block would reorder that -- revisited when remote-posture blocking is finished
(PR5).
"""

import os
import subprocess
import sys

HERE = os.path.dirname(os.path.abspath(__file__))        # pipeline/firewall
PIPELINE = os.path.dirname(HERE)                           # pipeline
if PIPELINE not in sys.path:
    sys.path.insert(0, PIPELINE)
import net_topology  # noqa: E402
sys.path.insert(0, os.path.join(PIPELINE, "redteam"))
import lab_modes  # noqa: E402

ENFORCER_CONTAINER = "soc-block-enforcer"
FILTER_CHAIN = "SOCLAB-PERIMETER"          # forward: inet->inside
INPUT_CHAIN = "SOCLAB-PERIMETER-IN"        # input: scans of the edge itself
NAT_COMMENT = "soclab-perimeter"
INET_MODE = "inet"
# Firewall logs go out via NFLOG (netlink group), NOT -j LOG: the kernel ring
# buffer isn't readable here (dmesg_restrict=1, and neither soc-block-enforcer
# nor the host user has CAP_SYSLOG), whereas NFLOG needs only CAP_NET_ADMIN,
# which the enforcer already has. ulogd (running inside the enforcer) reads this
# group and writes LOGEMU-format lines to /lab-logs/firewall/ for Wazuh (PR4).
NFLOG_GROUP = 100
LOG_PREFIX_ALLOW = "FW-ALLOW-THRU"   # nflog-prefix (<=64 chars, no trailing space)
LOG_PREFIX_DENY = "FW-DENY-EXT"


class PerimeterError(Exception):
    pass


def _ipt(*args, table=None, check=False):
    """Run one iptables command inside soc-block-enforcer (host netns)."""
    argv = ["docker", "exec", ENFORCER_CONTAINER, "iptables"]
    if table:
        argv += ["-t", table]
    argv += [str(a) for a in args]
    try:
        r = subprocess.run(argv, capture_output=True, text=True, timeout=15)
    except subprocess.TimeoutExpired as e:
        raise PerimeterError(f"enforcer iptables timed out: {e}")
    except FileNotFoundError as e:
        raise PerimeterError(f"docker CLI not available on host: {e}")
    if check and r.returncode != 0:
        raise PerimeterError(
            f"iptables {' '.join(str(a) for a in args)} failed "
            f"(exit {r.returncode}): {r.stderr.strip()}"
        )
    return r


def _container_ip(container, subnet):
    """The container's IPv4 address on `subnet` (an ipaddress network), or None
    if the container isn't running or isn't attached to that subnet. Runs on the
    host (plain `docker inspect`), same as block_enforcer._attacker_addresses."""
    import ipaddress
    r = subprocess.run(
        ["docker", "inspect", container, "--format",
         "{{range .NetworkSettings.Networks}}{{.IPAddress}}\n{{end}}"],
        capture_output=True, text=True, timeout=10,
    )
    if r.returncode != 0:
        return None
    for line in r.stdout.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            if ipaddress.ip_address(line) in subnet:
                return line
        except ValueError:
            continue
    return None


def _nat_rules_with_comment(chain):
    """The `-A <chain> ...` lines in the nat table carrying our comment tag."""
    r = _ipt("-S", chain, table="nat")
    return [ln for ln in r.stdout.splitlines() if NAT_COMMENT in ln]


def clear():
    """Remove every perimeter rule. Idempotent and always safe -- a no-op when
    nothing is installed. Never touches block_ip rules or Docker's own chains."""
    # 1. remove the jump(s) from DOCKER-USER (forward) and INPUT (edge scans)
    while _ipt("-C", "DOCKER-USER", "-j", FILTER_CHAIN).returncode == 0:
        _ipt("-D", "DOCKER-USER", "-j", FILTER_CHAIN)
    for line in [ln for ln in _ipt("-S", "INPUT").stdout.splitlines() if f"-j {INPUT_CHAIN}" in ln]:
        argv = line.split()
        argv[0] = "-D"
        _ipt(*argv)
    # 2. flush + delete both chains (ignore "no such chain")
    for chain in (FILTER_CHAIN, INPUT_CHAIN):
        _ipt("-F", chain)
        _ipt("-X", chain)
    # 3. delete the tagged nat rules
    for chain in ("PREROUTING", "POSTROUTING"):
        for line in _nat_rules_with_comment(chain):
            argv = line.split()
            argv[0] = "-D"          # -A <chain> ... -> -D <chain> ...
            _ipt(*argv, table="nat")


def apply(mode):
    """(Re)build the perimeter for `mode`. Clears first, so this is a full
    idempotent rebuild. Only meaningful under posture=remote -- the caller
    (lab-mode.sh) decides when to apply vs clear. Modes with no net_topology
    bridge (northwind) or no exposed ports (dealer default-deny) still get the
    default-deny chain, so a remote attacker is contained either way.

    Returns a dict describing what was published (for logging/CLI)."""
    clear()

    try:
        inside = net_topology.by_mode(mode)
    except KeyError:
        # adapter-backed / bridge-less mode: nothing to route, nothing to fence.
        return {"mode": mode, "published": [], "note": "no net_topology bridge; no perimeter"}

    inet = net_topology.by_mode(INET_MODE)
    inet_if = inet.bridge_iface
    edge_ip = str(inet.gateway)
    inside_if = inside.bridge_iface
    exposed = lab_modes.active_config(mode).get("exposed", ())

    # chain + jump (jump at top of DOCKER-USER; see module docstring on ordering)
    _ipt("-N", FILTER_CHAIN, check=True)
    _ipt("-I", "DOCKER-USER", "-j", FILTER_CHAIN, check=True)

    # return path for established/related inside->inet (harmless belt-and-braces;
    # MASQUERADE already keeps most returns off the inter-bridge path)
    _ipt("-A", FILTER_CHAIN, "-i", inside_if, "-o", inet_if,
         "-m", "conntrack", "--ctstate", "ESTABLISHED,RELATED", "-j", "ACCEPT", check=True)

    published = []
    for e in exposed:
        container, port = e["container"], e["port"]
        proto = e.get("proto", "tcp")
        ip = _container_ip(container, inside.subnet)
        if ip is None:
            # target not up / not on this bridge -- skip, don't fail the whole
            # apply (a mode may be brought up before every optional container is).
            published.append({"container": container, "port": port, "skipped": "not resolvable"})
            continue
        # DNAT the edge port to the inside host
        _ipt("-I", "PREROUTING", "-i", inet_if, "-d", edge_ip, "-p", proto,
             "--dport", port, "-j", "DNAT", "--to-destination", f"{ip}:{port}",
             "-m", "comment", "--comment", NAT_COMMENT, table="nat", check=True)
        # MASQUERADE so the inside host sees the firewall, replies cleanly
        _ipt("-I", "POSTROUTING", "-o", inside_if, "-p", proto, "-d", ip,
             "--dport", port, "-j", "MASQUERADE",
             "-m", "comment", "--comment", NAT_COMMENT, table="nat", check=True)
        published.append({"container": container, "ip": ip, "port": port, "proto": proto})

    # edge-published (DNAT'd) inet->inside: log the NEW connection, then ACCEPT.
    _ipt("-A", FILTER_CHAIN, "-i", inet_if, "-o", inside_if,
         "-m", "conntrack", "--ctstate", "NEW",
         "-m", "conntrack", "--ctstate", "DNAT",
         "-j", "NFLOG", "--nflog-group", NFLOG_GROUP, "--nflog-prefix", LOG_PREFIX_ALLOW, check=True)
    _ipt("-A", FILTER_CHAIN, "-i", inet_if, "-o", inside_if,
         "-m", "conntrack", "--ctstate", "DNAT", "-j", "ACCEPT", check=True)
    # everything else inet->inside (e.g. direct-to-real-IP probing): log + drop.
    # (Most such probes are dropped earlier by Docker's inter-bridge isolation,
    # so this is primarily a containment safety net; the realistic external-scan
    # noise is logged on INPUT below, where edge-IP scans actually land.)
    _ipt("-A", FILTER_CHAIN, "-i", inet_if, "-o", inside_if,
         "-m", "conntrack", "--ctstate", "NEW",
         "-j", "NFLOG", "--nflog-group", NFLOG_GROUP, "--nflog-prefix", LOG_PREFIX_DENY, check=True)
    _ipt("-A", FILTER_CHAIN, "-i", inet_if, "-o", inside_if, "-j", "DROP", check=True)

    # INPUT-side handling: a remote attacker scans the EDGE IP (= the host's inet
    # address). Exposed ports are DNAT'd in PREROUTING and go to FORWARD, so a
    # connection arriving here on soclab-inet0 is aimed at the HOST itself. The
    # edge exposes NOTHING of the host to the internet segment, so: let replies
    # pass, LOG the NEW probe (the "internet background noise" a real firewall
    # records), then DROP. The DROP is load-bearing -- without it the attacker
    # reaches host services bound to 0.0.0.0 (e.g. the host's own sshd on :22), a
    # lab-escape vector. The jump is scoped `-i soclab-inet0`, so nothing else on
    # the shared host INPUT chain is touched.
    _ipt("-N", INPUT_CHAIN, check=True)
    _ipt("-I", "INPUT", "-i", inet_if, "-j", INPUT_CHAIN, check=True)
    _ipt("-A", INPUT_CHAIN, "-m", "conntrack", "--ctstate", "ESTABLISHED,RELATED",
         "-j", "RETURN", check=True)
    _ipt("-A", INPUT_CHAIN, "-m", "conntrack", "--ctstate", "NEW",
         "-j", "NFLOG", "--nflog-group", NFLOG_GROUP, "--nflog-prefix", LOG_PREFIX_DENY, check=True)
    _ipt("-A", INPUT_CHAIN, "-j", "DROP", check=True)

    return {"mode": mode, "inside_iface": inside_if, "inet_iface": inet_if,
            "edge_ip": edge_ip, "published": published}


def status():
    """Human-readable dump of the installed perimeter rules."""
    print("== filter: DOCKER-USER (jump) ==")
    print(_ipt("-S", "DOCKER-USER").stdout, end="")
    print(f"== filter: {FILTER_CHAIN} ==")
    print(_ipt("-S", FILTER_CHAIN).stdout or "(chain absent)\n", end="")
    print(f"== filter: {INPUT_CHAIN} (edge scan logging) ==")
    print(_ipt("-S", INPUT_CHAIN).stdout or "(chain absent)\n", end="")
    print("== nat: tagged rules ==")
    for chain in ("PREROUTING", "POSTROUTING"):
        for ln in _nat_rules_with_comment(chain):
            print(ln)


if __name__ == "__main__":
    import json
    if len(sys.argv) >= 3 and sys.argv[1] == "apply":
        print(json.dumps(apply(sys.argv[2]), indent=2))
    elif len(sys.argv) >= 2 and sys.argv[1] == "clear":
        clear()
        print("[perimeter] cleared")
    elif len(sys.argv) >= 2 and sys.argv[1] == "status":
        status()
    else:
        print("usage: perimeter.py {apply <mode>|clear|status}", file=sys.stderr)
        sys.exit(1)
