"""
Canonical registry of this lab's per-mode Docker networks -- one isolated
subnet per mode (easy/hard/wordpress), each `internal: true` so nothing on
it can reach the real internet regardless of what happens inside a
container, plus Wazuh's own total isolation (`network_mode: none`, tracked
here only as a comment since it has no subnet of its own to register).

This module's job is to describe what SHOULD exist so block_enforcer.py,
executor.py, reset.sh, lab-mode.sh, and injection_asr/ don't each carry
their own copy of the same CIDR and drift out of sync with each other --
which is exactly what happened before this file existed: "10.211.0.0/24"
was independently hardcoded in compose.yaml, compose.hard.yml, reset.sh,
and attacker/README, four places that all had to be remembered and kept
in lockstep by hand.

Docker itself is the actual source of truth at runtime -- this registry
only says what the topology is supposed to be. verify-isolation.sh diffs
this against live `docker network inspect` output rather than trusting it
blindly; nothing here reaches out to Docker except bootstrap() (idempotent
network creation) and the --bootstrap/--subnets/--ifaces CLI below.

Historical note for anyone diffing this against an old soc.db/session log:
before this refactor the whole lab shared ONE bridge (`soclab`,
10.211.0.0/24, interface soclab0) -- a red-team session discovered Wazuh
(never a declared target) purely by sweeping that shared bridge and got
real root-level code execution on it via the manager's own admin API,
because everything was mutually reachable on one flat network. That's the
incident this file's whole existence is downstream of.
"""

import ipaddress
import subprocess
import sys
from dataclasses import dataclass


@dataclass(frozen=True)
class LabNetwork:
    mode: str             # matches pipeline/redteam/lab_modes.MODES key
    compose_name: str     # docker network name (compose.yaml's external network key, also the DNS zone suffix -- "nginx.soclab-easy")
    subnet: ipaddress.IPv4Network
    gateway: ipaddress.IPv4Address
    bridge_iface: str      # <=15 chars (IFNAMSIZ) -- pinned via com.docker.network.bridge.name at create time


# All three inside 10.211.0.0/16 on purpose -- suricata/overrides.yaml's
# HOME_NET is already that /16 (plus a couple of unrelated ranges), so
# adding a network here never requires touching Suricata's config, only
# its entrypoint.sh needs to notice the new bridge exists (see
# suricata/entrypoint.sh's self-discovery). Bridge interface names stay
# short (soclab-wp0, not soclab-wordpress0) because IFNAMSIZ caps kernel
# interface names at 15 bytes -- "soclab-wordpress0" is 18 and
# `docker network create` fails outright on it. The Docker network NAME
# (used for compose refs and DNS) has no such limit and stays readable.
LAB_NETWORKS = (
    LabNetwork(
        mode="easy",
        compose_name="soclab-easy",
        subnet=ipaddress.ip_network("10.211.10.0/24"),
        gateway=ipaddress.ip_address("10.211.10.1"),
        bridge_iface="soclab-easy0",
    ),
    LabNetwork(
        mode="hard",
        compose_name="soclab-hard",
        subnet=ipaddress.ip_network("10.211.20.0/24"),
        gateway=ipaddress.ip_address("10.211.20.1"),
        bridge_iface="soclab-hard0",
    ),
    LabNetwork(
        mode="wordpress",
        compose_name="soclab-wordpress",
        subnet=ipaddress.ip_network("10.211.30.0/24"),
        gateway=ipaddress.ip_address("10.211.30.1"),
        bridge_iface="soclab-wp0",
    ),
)

# soc-attacker is the one container attached to every network above,
# always, regardless of which modes' target containers happen to be up
# (see compose.yaml) -- block_enforcer.py's multi-homed-attacker handling
# and reset.sh both need this name, so it lives here rather than being
# re-guessed in each.
ATTACKER_CONTAINER = "soc-attacker"


def by_mode(mode):
    """Raises KeyError for an unknown mode -- callers should let that
    propagate rather than silently falling back to a default network,
    since a typo'd mode name here is a bug worth surfacing loudly."""
    for net in LAB_NETWORKS:
        if net.mode == mode:
            return net
    raise KeyError(mode)


def network_for_ip(ip):
    """Return the LabNetwork whose subnet contains ip (an
    ipaddress.IPv4Address), or None if it's outside every known lab
    subnet. This is the multi-subnet-aware replacement for
    block_enforcer.py's old single `ip in LAB_SUBNET` check."""
    for net in LAB_NETWORKS:
        if ip in net.subnet:
            return net
    return None


def _network_exists(name):
    return subprocess.run(
        ["docker", "network", "inspect", name], capture_output=True,
    ).returncode == 0


def bootstrap():
    """Idempotently create every network in LAB_NETWORKS if it doesn't
    already exist. Called by setup.sh and at the top of every lab-mode.sh
    verb -- cheap no-op (one `docker network inspect` each) once the
    networks are already up, so there's no reason to guard calls to this
    behind a first-run check of your own."""
    for net in LAB_NETWORKS:
        if _network_exists(net.compose_name):
            print(f"[net_topology] {net.compose_name} already exists")
            continue
        print(f"[net_topology] creating {net.compose_name} ({net.subnet}, internal)")
        subprocess.run(
            [
                "docker", "network", "create",
                "--driver", "bridge",
                "--internal",
                "--subnet", str(net.subnet),
                "--gateway", str(net.gateway),
                "--opt", f"com.docker.network.bridge.name={net.bridge_iface}",
                net.compose_name,
            ],
            check=True,
        )


if __name__ == "__main__":
    if "--bootstrap" in sys.argv:
        bootstrap()
    elif "--subnets" in sys.argv:
        for net in LAB_NETWORKS:
            print(net.subnet)
    elif "--ifaces" in sys.argv:
        for net in LAB_NETWORKS:
            print(net.bridge_iface)
    else:
        print("usage: net_topology.py [--bootstrap|--subnets|--ifaces]", file=sys.stderr)
        sys.exit(1)
