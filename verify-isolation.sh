#!/usr/bin/env bash
# Standing, rerunnable verification of the network isolation refactor
# (see pipeline/net_topology.py) -- not a one-time migration check. Same
# "verify rather than trust" convention as reset.sh's own egress checks:
# every assertion here queries live docker/iptables state, nothing is
# taken on faith from what a compose file or a comment claims.
set -uo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")"

PY="${PYTHON:-python3}"
if [ -x .venv/bin/python3 ]; then
  PY=".venv/bin/python3"
fi

PASS=0; FAIL=0
ok()  { echo "  [PASS] $1"; PASS=$((PASS+1)); }
bad() { echo "  [FAIL] $1"; FAIL=$((FAIL+1)); }

echo "=== 1. Network topology matches pipeline/net_topology.py's registry ==="
"$PY" - <<PYEOF
import sys, os, subprocess, json
sys.path.insert(0, "pipeline")
import net_topology

fail = False
for net in net_topology.LAB_NETWORKS:
    r = subprocess.run(["docker", "network", "inspect", net.compose_name],
                        capture_output=True, text=True)
    if r.returncode != 0:
        print(f"  [FAIL] {net.compose_name} does not exist")
        fail = True
        continue
    info = json.loads(r.stdout)[0]
    ipam = (info.get("IPAM", {}).get("Config") or [{}])[0]
    bridge = info.get("Options", {}).get("com.docker.network.bridge.name")
    problems = []
    if ipam.get("Subnet") != str(net.subnet):
        problems.append(f"subnet={ipam.get('Subnet')!r} (want {net.subnet})")
    if ipam.get("Gateway") != str(net.gateway):
        problems.append(f"gateway={ipam.get('Gateway')!r} (want {net.gateway})")
    if bridge != net.bridge_iface:
        problems.append(f"bridge={bridge!r} (want {net.bridge_iface})")
    if problems:
        print(f"  [FAIL] {net.compose_name}: " + ", ".join(problems))
        fail = True
    else:
        print(f"  [PASS] {net.compose_name}: subnet/gateway/bridge all match")
sys.exit(1 if fail else 0)
PYEOF
if [ $? -eq 0 ]; then ok "topology check script"; else bad "topology check script (see [FAIL] lines above)"; fi

echo
echo "=== 2. Wazuh: total network isolation ==="
NETMODE="$(docker inspect soc-wazuh --format '{{.HostConfig.NetworkMode}}' 2>/dev/null || echo MISSING)"
NETCOUNT="$(docker inspect soc-wazuh --format '{{len .NetworkSettings.Networks}}' 2>/dev/null || echo -1)"
if [ "$NETMODE" = "none" ] && [ "$NETCOUNT" = "1" ]; then
  # network_mode: none still reports one synthetic "none" network entry;
  # zero would mean something's actually wrong with the inspect itself.
  ok "soc-wazuh: network_mode=none, no real network attachment"
else
  bad "soc-wazuh: network_mode=$NETMODE, network count=$NETCOUNT (want none / 1 synthetic entry)"
fi

echo
echo "=== 3. soc-attacker: no real internet, reaches whichever modes are up ==="
if ! docker inspect -f '{{.State.Running}}' soc-attacker >/dev/null 2>&1; then
  bad "soc-attacker isn't running -- can't check"
else
  REAL_NET="$(docker exec soc-attacker curl -m 5 -s -o /dev/null -w '%{http_code}' http://1.1.1.1/ 2>/dev/null)" || true
  if [ "$REAL_NET" = "000" ]; then
    ok "soc-attacker: real internet unreachable (000)"
  else
    bad "soc-attacker: real internet returned http_code=$REAL_NET (want 000) -- run ./reset.sh --attacker"
  fi
  check_target_reachable() {
    local container="$1" target="$2" label="$3"
    docker inspect -f '{{.State.Running}}' "$container" >/dev/null 2>&1 || return 0
    local code
    code="$(docker exec soc-attacker curl -m 5 -s -o /dev/null -w '%{http_code}' "http://$target/" 2>/dev/null)" || true
    if [ "$code" != "000" ] && [ -n "$code" ]; then
      ok "soc-attacker reaches $label (http_code=$code)"
    else
      bad "soc-attacker cannot reach $label (want a real http_code, got ${code:-empty})"
    fi
  }
  check_target_reachable soc-nginx-easy nginx.soclab-easy "easy mode's nginx"
  check_target_reachable soc-nginx-hard nginx.soclab-hard "hard mode's nginx"
  check_target_reachable soc-wordpress  wordpress          "wordpress"
fi

echo
echo "=== 4. block_enforcer: multi-subnet fence + multi-homed-attacker fan-out ==="
"$PY" - <<PYEOF
import sys
sys.path.insert(0, "pipeline")
sys.path.insert(0, "pipeline/triage")
import net_topology, block_enforcer as be

fail = False

try:
    be.validate_lab_ip("192.168.1.1")
    print("  [FAIL] out-of-range IP was NOT rejected"); fail = True
except be.BlockError:
    print("  [PASS] out-of-range IP correctly rejected")

for net in net_topology.LAB_NETWORKS:
    try:
        be.validate_lab_ip(str(net.gateway))
        print(f"  [FAIL] {net.compose_name}'s gateway was NOT rejected"); fail = True
    except be.BlockError:
        print(f"  [PASS] {net.compose_name}'s gateway correctly rejected")

test_ip = str(net_topology.LAB_NETWORKS[0].subnet.network_address + 50)
try:
    r = be.block(test_ip)
    if r["multi_homed_attacker"]:
        print(f"  [FAIL] {test_ip} isn't soc-attacker's own address but was treated as multi-homed"); fail = True
    else:
        print(f"  [PASS] plain block/unblock of {test_ip} (single rule, no fan-out)")
    be.unblock(test_ip)
except Exception as e:
    print(f"  [FAIL] block/unblock of {test_ip} raised: {e}"); fail = True

attacker_addrs = be._attacker_addresses()
if len(attacker_addrs) >= 2:
    one_ip = list(attacker_addrs.values())[0]
    r = be.block(one_ip)
    if r["multi_homed_attacker"] and len(r["blocked_addresses"]) == len(attacker_addrs):
        print(f"  [PASS] blocking soc-attacker's {one_ip} fanned out to all {len(attacker_addrs)} of its addresses")
    else:
        print(f"  [FAIL] blocking soc-attacker's {one_ip} did not fan out correctly: {r}"); fail = True
    removed = be.unblock_all()
    if len(removed) == len(attacker_addrs):
        print(f"  [PASS] unblock_all() removed all {len(removed)} fanned-out rules")
    else:
        print(f"  [FAIL] unblock_all() removed {len(removed)}, expected {len(attacker_addrs)}"); fail = True
else:
    print(f"  [WARN] soc-attacker only has {len(attacker_addrs)} address(es) right now -- is it running and multi-homed?")

sys.exit(1 if fail else 0)
PYEOF
if [ $? -eq 0 ]; then ok "block_enforcer check script"; else bad "block_enforcer check script (see [FAIL] lines above)"; fi

echo
echo "=== 5. Suricata: watching every bootstrapped bridge ==="
if ! docker inspect -f '{{.State.Running}}' soc-suricata >/dev/null 2>&1; then
  bad "soc-suricata isn't running -- can't check"
else
  EXPECTED="$("$PY" pipeline/net_topology.py --ifaces | sort | tr '\n' ' ')"
  ACTUAL="$(docker logs soc-suricata 2>&1 | grep '\[suricata\] starting on:' | tail -1 | sed 's/.*starting on: //' | tr ' ' '\n' | sort | tr '\n' ' ')"
  if [ -n "$ACTUAL" ] && [ "$ACTUAL" = "$EXPECTED" ]; then
    ok "soc-suricata watching exactly the bootstrapped interfaces ($ACTUAL)"
  else
    bad "soc-suricata interface mismatch -- expected [$EXPECTED] got [$ACTUAL]"
  fi
fi

echo
echo "=== Result: $PASS passed, $FAIL failed ==="
[ "$FAIL" -eq 0 ] && echo "Network isolation verified end to end." || echo "Fix the failures above."
exit $([ "$FAIL" -eq 0 ] && echo 0 || echo 1)
