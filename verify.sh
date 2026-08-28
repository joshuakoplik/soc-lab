#!/usr/bin/env bash
set -uo pipefail
cd "$(dirname "$0")"

# Host bindings come from .env (see .env.example) so this script always
# prints/probes the ports compose.yaml actually published. LAB_BIND_IP may be
# 0.0.0.0 (bind-all), which is not a connectable address -- use loopback to
# talk to it in that case.
set -a; [ -f .env ] && . ./.env; set +a
LAB_BIND_IP="${LAB_BIND_IP:-127.0.0.1}"
LAB_NGINX_EASY_PORT="${LAB_NGINX_EASY_PORT:-8082}"
LAB_COWRIE_SSH_PORT="${LAB_COWRIE_SSH_PORT:-2222}"
case "$LAB_BIND_IP" in 0.0.0.0|::|"") LAB_HOST=127.0.0.1 ;; *) LAB_HOST="$LAB_BIND_IP" ;; esac


PASS=0; FAIL=0
ok()   { echo "  [PASS] $1"; PASS=$((PASS+1)); }
bad()  { echo "  [FAIL] $1"; FAIL=$((FAIL+1)); }

echo "=== 1. Containers running ==="
for c in soc-cowrie soc-juiceshop-easy soc-nginx-easy; do
  if [ "$(docker inspect -f '{{.State.Running}}' "$c" 2>/dev/null)" = "true" ]; then
    ok "$c is up"
  else
    bad "$c is NOT running  ->  docker compose logs $c"
  fi
done

echo
echo "=== 2. Generate web traffic through nginx ==="
curl -s -o /dev/null -w '  GET /            -> %{http_code}\n' http://${LAB_HOST}:${LAB_NGINX_EASY_PORT}/
# A benign-looking request with attacker-controlled fields, so you can see them land verbatim.
curl -s -o /dev/null -w '  GET /?q=test     -> %{http_code}\n' \
     -A 'soc-lab-verify/1.0' \
     "http://${LAB_HOST}:${LAB_NGINX_EASY_PORT}/rest/products/search?q=test"
sleep 1

echo
echo "=== 3. Generate SSH traffic against Cowrie ==="
if command -v sshpass >/dev/null 2>&1; then
  for i in 1 2 3; do
    sshpass -p 'hunter2' ssh -p "${LAB_COWRIE_SSH_PORT}" -o StrictHostKeyChecking=no \
      -o UserKnownHostsFile=/dev/null -o ConnectTimeout=5 \
      root@"${LAB_HOST}" 'whoami' >/dev/null 2>&1
  done
  echo "  3 login attempts sent"
else
  # No sshpass? A bare TCP connect still produces a cowrie.session.connect event.
  (exec 3<>/dev/tcp/${LAB_HOST}/${LAB_COWRIE_SSH_PORT} && head -c 40 <&3 >/dev/null) 2>/dev/null \
    && echo "  TCP connect sent (install sshpass for full login events)" \
    || echo "  [WARN] could not reach ${LAB_HOST}:${LAB_COWRIE_SSH_PORT}"
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
