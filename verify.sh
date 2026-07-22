#!/usr/bin/env bash
set -uo pipefail
cd "$(dirname "$0")"

PASS=0; FAIL=0
ok()   { echo "  [PASS] $1"; PASS=$((PASS+1)); }
bad()  { echo "  [FAIL] $1"; FAIL=$((FAIL+1)); }

echo "=== 1. Containers running ==="
for c in soc-cowrie soc-juiceshop soc-nginx; do
  if [ "$(docker inspect -f '{{.State.Running}}' "$c" 2>/dev/null)" = "true" ]; then
    ok "$c is up"
  else
    bad "$c is NOT running  ->  docker compose logs $c"
  fi
done

echo
echo "=== 2. Generate web traffic through nginx ==="
curl -s -o /dev/null -w '  GET /            -> %{http_code}\n' http://localhost:8080/
# A benign-looking request with attacker-controlled fields, so you can see them land verbatim.
curl -s -o /dev/null -w '  GET /?q=test     -> %{http_code}\n' \
     -A 'soc-lab-verify/1.0' \
     'http://localhost:8080/rest/products/search?q=test'
sleep 1

echo
echo "=== 3. Generate SSH traffic against Cowrie ==="
if command -v sshpass >/dev/null 2>&1; then
  for i in 1 2 3; do
    sshpass -p 'hunter2' ssh -p 2222 -o StrictHostKeyChecking=no \
      -o UserKnownHostsFile=/dev/null -o ConnectTimeout=5 \
      root@localhost 'whoami' >/dev/null 2>&1
  done
  echo "  3 login attempts sent"
else
  # No sshpass? A bare TCP connect still produces a cowrie.session.connect event.
  (exec 3<>/dev/tcp/localhost/2222 && head -c 40 <&3 >/dev/null) 2>/dev/null \
    && echo "  TCP connect sent (install sshpass for full login events)" \
    || echo "  [WARN] could not reach localhost:2222"
fi
sleep 2

echo
echo "=== 4. Telemetry on disk ==="
if [ -s logs/nginx/access.json ]; then
  ok "logs/nginx/access.json has content ($(wc -l < logs/nginx/access.json) lines)"
  python3 -c 'import json,sys; json.loads(open("logs/nginx/access.json").readlines()[-1]); print("  [PASS] last nginx line is valid JSON")' 2>/dev/null \
    || bad "last nginx line is not valid JSON"
else
  bad "logs/nginx/access.json missing or empty"
fi

if [ -s logs/cowrie/cowrie.json ]; then
  ok "logs/cowrie/cowrie.json has content ($(wc -l < logs/cowrie/cowrie.json) lines)"
  python3 -c 'import json,sys; json.loads(open("logs/cowrie/cowrie.json").readlines()[-1]); print("  [PASS] last cowrie line is valid JSON")' 2>/dev/null \
    || bad "last cowrie line is not valid JSON"
else
  bad "logs/cowrie/cowrie.json missing or empty  ->  almost always a permissions problem: chmod -R 0777 logs/cowrie && docker compose restart cowrie"
fi

echo
echo "=== 5. Sample events (this is what your parser will consume) ==="
echo "--- nginx ---"; tail -n 1 logs/nginx/access.json 2>/dev/null | python3 -m json.tool 2>/dev/null || echo "  (none)"
echo "--- cowrie ---"; tail -n 1 logs/cowrie/cowrie.json 2>/dev/null | python3 -m json.tool 2>/dev/null || echo "  (none)"

echo
echo "=== Result: $PASS passed, $FAIL failed ==="
[ "$FAIL" -eq 0 ] && echo "Step 1 complete. Both sources are emitting JSON to disk." || echo "Fix the failures above before moving to step 2."
