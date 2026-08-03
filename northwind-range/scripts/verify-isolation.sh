#!/usr/bin/env bash
# Standing, rerunnable verification of Northwind's network isolation
# (SPEC.md §0.1/§0.2/§2.1). Same "verify rather than trust" convention as
# the parent soc-lab's own verify-isolation.sh -- every assertion here
# queries live docker state, nothing is taken on faith from what
# docker-compose.yml claims.
#
# Pass --cold-start to force a full down + rebuild + up first, matching
# §0.1's "must pass on a cold start" requirement. Without it, checks run
# against whatever is currently up (faster for iterative dev).
set -uo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")/.."

PASS=0; FAIL=0
ok()  { echo "  [PASS] $1"; PASS=$((PASS+1)); }
bad() { echo "  [FAIL] $1"; FAIL=$((FAIL+1)); }

if [ "${1:-}" = "--cold-start" ]; then
  echo "=== Cold start: down -v, rebuild, up ==="
  docker compose down -v
  docker compose up -d --build --wait
  echo
fi

echo "=== 1. Network topology: internal flags and CIDRs ==="
declare -A WANT_INTERNAL=( [nw_dmz]=true [nw_app]=true [nw_ops]=false [nw_llm_egress]=false )
declare -A WANT_SUBNET=( [nw_dmz]=172.28.10.0/24 [nw_app]=172.28.20.0/24 [nw_ops]=172.28.40.0/24 [nw_llm_egress]=172.28.50.0/24 )

for net in nw_dmz nw_app nw_ops nw_llm_egress; do
  full_name="northwind-range_${net}"
  info="$(docker network inspect "$full_name" 2>/dev/null)" || { bad "$net: network does not exist"; continue; }
  internal="$(echo "$info" | python3 -c 'import json,sys; print(json.load(sys.stdin)[0]["Internal"])' 2>/dev/null)"
  subnet="$(echo "$info" | python3 -c 'import json,sys; print(json.load(sys.stdin)[0]["IPAM"]["Config"][0]["Subnet"])' 2>/dev/null)"
  want_i="$(echo "${WANT_INTERNAL[$net]}" | sed 's/^./\U&/')"
  problems=""
  [ "$internal" = "$want_i" ] || problems="internal=$internal (want $want_i) "
  [ "$subnet" = "${WANT_SUBNET[$net]}" ] || problems="${problems}subnet=$subnet (want ${WANT_SUBNET[$net]})"
  if [ -z "$problems" ]; then
    ok "$net: internal=$internal, subnet=$subnet"
  else
    bad "$net: $problems"
  fi
done

echo
echo "=== 2. No container reaches a real external address ==="
check_no_egress() {
  local container="$1" method="$2"
  if ! docker inspect -f '{{.State.Running}}' "$container" >/dev/null 2>&1; then
    bad "$container isn't running -- can't check"
    return
  fi
  local result
  case "$method" in
    wget)
      result="$(docker exec "$container" wget -q -T 5 -O /dev/null http://1.1.1.1/ 2>&1; echo "exit=$?")"
      ;;
    python)
      result="$(docker exec "$container" python3 -c "import urllib.request; urllib.request.urlopen('http://1.1.1.1/', timeout=5)" 2>&1; echo "exit=$?")"
      ;;
  esac
  if echo "$result" | grep -q "exit=0"; then
    bad "$container: reached 1.1.1.1 -- egress is NOT blocked"
  else
    ok "$container: real internet unreachable"
  fi
}
check_no_egress nw-edge-nginx wget
check_no_egress nw-portal-api python

echo
echo "=== 2b. nw_ops members (harness, postgres) also can't reach the internet ==="
echo "    (nw_ops is the one non-internal network -- egress here is enforced by"
echo "     per-container iptables, not the network itself. See harness/entrypoint.sh"
echo "     and services/postgres/entrypoint.sh.)"
check_no_egress nw-harness python
if docker inspect -f '{{.State.Running}}' nw-postgres >/dev/null 2>&1; then
  if docker exec nw-postgres timeout 5 bash -c 'exec 3<>/dev/tcp/1.1.1.1/80' 2>/dev/null; then
    bad "nw-postgres: reached 1.1.1.1 -- egress is NOT blocked"
  else
    ok "nw-postgres: real internet unreachable"
  fi
  if docker exec nw-postgres timeout 5 bash -c 'exec 3<>/dev/tcp/nw-redis.northwind-range_nw_app/6379' 2>/dev/null; then
    ok "nw-postgres: still reaches other range containers (172.28.0.0/16 not over-blocked)"
  else
    bad "nw-postgres: can't reach nw-redis over the range's own subnet -- lockdown is too broad"
  fi
else
  bad "nw-postgres isn't running -- can't check"
fi

echo
echo "=== 2c. llm-backend: narrow egress, exactly the configured host, nothing else ==="
echo "    (SPEC.md §0.1/§4's one deliberate exception -- see"
echo "     services/llm-backend/entrypoint.sh. Must NOT be a wide-open hole.)"
if ! docker inspect -f '{{.State.Running}}' nw-llm-backend >/dev/null 2>&1; then
  bad "nw-llm-backend isn't running -- can't check"
else
  if docker exec nw-llm-backend wget -q -T 5 -O /dev/null http://1.1.1.1/ 2>/dev/null; then
    bad "nw-llm-backend: reached 1.1.1.1 -- egress allow-list is too broad"
  else
    ok "nw-llm-backend: unrelated external address (1.1.1.1) still unreachable"
  fi
  UPSTREAM="$(docker inspect nw-llm-backend --format '{{range .Config.Env}}{{println .}}{{end}}' | sed -n 's/^OLLAMA_UPSTREAM_HOST=//p')"
  if [ -n "$UPSTREAM" ] && docker exec nw-llm-backend wget -q -T 10 -O /dev/null "http://${UPSTREAM}:11434/api/tags" 2>/dev/null; then
    ok "nw-llm-backend: configured upstream ($UPSTREAM) is reachable"
  else
    bad "nw-llm-backend: configured upstream ($UPSTREAM) is NOT reachable"
  fi
fi

echo
echo "=== 3. Only the harness publishes a host port, and only on 127.0.0.1 ==="
ALL_SERVICES="nw-edge-nginx nw-chat-web nw-portal-api nw-litellm nw-llm-backend nw-retrieval-svc nw-tool-svc nw-ingest-svc nw-postgres nw-redis nw-harness"
BAD_PUBLISH=0
for c in $ALL_SERVICES; do
  ports="$(docker port "$c" 2>/dev/null || true)"
  if [ "$c" = "nw-harness" ]; then
    if echo "$ports" | grep -q "127.0.0.1:8090"; then
      ok "nw-harness: published on 127.0.0.1:8090"
    else
      bad "nw-harness: expected 127.0.0.1:8090 published, got: ${ports:-none}"
    fi
  else
    if [ -z "$ports" ]; then
      : # fine, no port
    else
      bad "$c: unexpectedly has a published port: $ports"
      BAD_PUBLISH=1
    fi
  fi
done
[ "$BAD_PUBLISH" -eq 0 ] && ok "no other service has any host-published port"

echo
echo "=== 4. Harness API actually reachable from the host ==="
CODE="$(curl -m 5 -s -o /dev/null -w '%{http_code}' http://127.0.0.1:8090/health 2>/dev/null)" || true
if [ "$CODE" = "200" ]; then
  ok "harness /health responded 200 on 127.0.0.1:8090"
else
  bad "harness /health returned '$CODE' on 127.0.0.1:8090 (want 200)"
fi

echo
echo "=== Result: $PASS passed, $FAIL failed ==="
[ "$FAIL" -eq 0 ] && echo "Network isolation verified end to end." || echo "Fix the failures above."
exit $([ "$FAIL" -eq 0 ] && echo 0 || echo 1)
