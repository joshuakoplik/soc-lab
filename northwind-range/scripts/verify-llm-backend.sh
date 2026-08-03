#!/usr/bin/env bash
# Functional check for llm-backend + litellm (SPEC.md §13 milestone 4).
# Narrow-egress *isolation* properties (llm-backend reaches only the
# configured host) live in verify-isolation.sh, same family as the other
# network-isolation checks -- this script only asks "does inference work."
set -uo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")/.."

PASS=0; FAIL=0
ok()  { echo "  [PASS] $1"; PASS=$((PASS+1)); }
bad() { echo "  [FAIL] $1"; FAIL=$((FAIL+1)); }

# Run from inside retrieval-svc (a plain nw_app peer) rather than the host --
# nw_app is internal:true, nothing on it has a host-published port.
py_call() {
  docker compose exec -T retrieval-svc python3 -c "$1" < /dev/null 2>&1
}

echo "=== 1. Real completion from llm-backend directly ==="
RESP="$(py_call "
import urllib.request, json
body = json.dumps({'model': 'qwen3:8b', 'prompt': 'Reply with exactly the word: PONG', 'stream': False, 'think': False}).encode()
req = urllib.request.Request('http://llm-backend:11434/api/generate', data=body, headers={'Content-Type':'application/json'})
with urllib.request.urlopen(req, timeout=60) as resp:
    print(json.loads(resp.read())['response'].strip())
")"
if echo "$RESP" | grep -qi "PONG"; then
  ok "llm-backend direct: got a real completion ('$RESP')"
else
  bad "llm-backend direct: unexpected response: $RESP"
fi

echo
echo "=== 2. Real completion through litellm, per configured model ==="
for model in qwen3-8b gemma4-31b; do
  RESP="$(py_call "
import urllib.request, json
body = json.dumps({'model': '$model', 'messages': [{'role':'user','content':'Reply with exactly the word: PONG'}]}).encode()
req = urllib.request.Request('http://litellm:4000/chat/completions', data=body,
    headers={'Content-Type':'application/json', 'Authorization': 'Bearer sk-northwind-placeholder'})
with urllib.request.urlopen(req, timeout=90) as resp:
    d = json.loads(resp.read())
    print(d['choices'][0]['message']['content'].strip())
")"
  if echo "$RESP" | grep -qi "PONG"; then
    ok "litellm/$model: got a real completion ('$RESP')"
  else
    bad "litellm/$model: unexpected response: $RESP"
  fi
done

echo
echo "=== Result: $PASS passed, $FAIL failed ==="
[ "$FAIL" -eq 0 ] && echo "llm-backend + litellm verified end to end." || echo "Fix the failures above."
exit $([ "$FAIL" -eq 0 ] && echo 0 || echo 1)
