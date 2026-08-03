#!/usr/bin/env bash
# SPEC.md §13 milestone 7 -- the path a browser would actually take,
# through edge-nginx, not internal service-to-service shortcuts.
set -uo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")/.."

PASS=0; FAIL=0
ok()  { echo "  [PASS] $1"; PASS=$((PASS+1)); }
bad() { echo "  [FAIL] $1"; FAIL=$((FAIL+1)); }

echo "=== 1. Real HTML pages through edge-nginx ==="
for path in / /login; do
  RESULT="$(docker compose exec -T portal-api python3 -c "
import urllib.request
resp = urllib.request.urlopen('http://edge-nginx${path}', timeout=10)
body = resp.read().decode()
print(resp.status)
print(len(body))
print('doctype-ok' if body.startswith('<!DOCTYPE html>') else 'doctype-missing')
" < /dev/null)"
  STATUS="$(echo "$RESULT" | sed -n '1p')"
  LEN="$(echo "$RESULT" | sed -n '2p')"
  DOCTYPE="$(echo "$RESULT" | sed -n '3p')"
  if [ "$STATUS" = "200" ] && [ "$DOCTYPE" = "doctype-ok" ] && [ "${LEN:-0}" -gt 500 ]; then
    ok "GET $path: 200, real HTML ($LEN bytes)"
  else
    bad "GET $path: status=$STATUS doctype=$DOCTYPE len=$LEN"
  fi
done

echo
echo "=== 2. Full chat flow through edge-nginx (real seeded user) ==="
if [ ! -f .seed-credentials.json ]; then
  bad ".seed-credentials.json missing -- run 'make seed' first"
else
  # .seed-credentials.json is a host file, not reachable from inside the
  # container -- read the one password needed here and pass it via env.
  MARIA_PW="$(.venv/bin/python3 -c "import json; print(json.load(open('.seed-credentials.json'))['maria.support'])" 2>/dev/null || python3 -c "import json; print(json.load(open('.seed-credentials.json'))['maria.support'])")"

  OUT="$(docker compose exec -T -e MARIA_PW="$MARIA_PW" portal-api python3 - <<'PYEOF'
import http.cookiejar
import json
import os
import urllib.error
import urllib.request

import psycopg2
import psycopg2.extras
from policy import policy

password = os.environ["MARIA_PW"]

cj = http.cookiejar.CookieJar()
opener = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(cj))


def post(path, body, timeout=15):
    req = urllib.request.Request(
        f"http://edge-nginx{path}", data=json.dumps(body).encode(),
        headers={"Content-Type": "application/json"},
    )
    return opener.open(req, timeout=timeout)


# --- login ---
resp = post("/api/auth/login", {"tenant": "fenwick", "username": "maria.support", "password": password})
print(f"LOGIN_STATUS={resp.status}")

# --- entitled question: maria has an active Engineering grant in her own tenant ---
resp = post("/api/chat", {"message": "What is our on-call escalation process?"}, timeout=120)
data = json.loads(resp.read())
print(f"CHAT_STATUS={resp.status}")
print(f"CHAT_RESPONSE_LEN={len(data.get('response', ''))}")
print(f"CHAT_SOURCE_COUNT={len(data.get('sources', []))}")

conn = psycopg2.connect(policy.DATABASE_URL)
cur = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
cur.execute("SELECT id FROM app.users WHERE username = 'maria.support'")
maria_id = cur.fetchone()["id"]

bad_sources = 0
for doc_id in data.get("sources", []):
    if not policy.decide(maria_id, doc_id, "read", conn=conn).allowed:
        bad_sources += 1
        print(f"BAD_SOURCE doc={doc_id}")
print(f"BAD_SOURCE_COUNT={bad_sources}")

# --- denied-document probe: embed a document maria is denied as the "question" ---
cur.execute("SELECT tenant_id, department_id FROM app.users WHERE id = %s", (maria_id,))
u = cur.fetchone()
cur.execute(
    "SELECT id, content FROM app.documents WHERE tenant_id = %s AND label != 'public' AND owning_department_id != %s",
    (u["tenant_id"], u["department_id"]),
)
denied_doc = None
for row in cur.fetchall():
    if not policy.decide(maria_id, row["id"], "read", conn=conn).allowed:
        denied_doc = row
        break

if denied_doc:
    resp = post("/api/chat", {"message": denied_doc["content"]}, timeout=120)
    probe_data = json.loads(resp.read())
    leaked = denied_doc["id"] in probe_data.get("sources", [])
    print(f"DENIED_DOC_ID={denied_doc['id']}")
    print(f"DENIED_DOC_LEAKED={'yes' if leaked else 'no'}")
else:
    print("DENIED_DOC_ID=none-found")
PYEOF
)"
  echo "$OUT" | sed 's/^/  /'
  echo

  echo "$OUT" | grep -q "^LOGIN_STATUS=200" && ok "login through edge-nginx succeeded" \
    || bad "login through edge-nginx did not return 200"

  echo "$OUT" | grep -q "^CHAT_STATUS=200" && ok "chat request succeeded" \
    || bad "chat request did not return 200"

  RESP_LEN="$(echo "$OUT" | sed -n 's/^CHAT_RESPONSE_LEN=//p')"
  if [ -n "$RESP_LEN" ] && [ "$RESP_LEN" -gt 0 ]; then
    ok "chat returned a non-empty response ($RESP_LEN chars)"
  else
    bad "chat returned an empty response"
  fi

  BAD_COUNT="$(echo "$OUT" | sed -n 's/^BAD_SOURCE_COUNT=//p')"
  if [ "$BAD_COUNT" = "0" ]; then
    ok "every source in the chat response is policy-allowed for this user"
  else
    bad "$BAD_COUNT source(s) in the chat response were policy-denied (see BAD_SOURCE lines above)"
  fi

  if echo "$OUT" | grep -q "^DENIED_DOC_ID=none-found"; then
    bad "could not find a denied document to probe with -- check corpus/entitlement data"
  elif echo "$OUT" | grep -q "^DENIED_DOC_LEAKED=no"; then
    ok "a denied document, submitted as the chat question itself, never appears in sources"
  else
    bad "a denied document leaked into sources when submitted as the chat question"
  fi
fi

echo
echo "=== Result: $PASS passed, $FAIL failed ==="
[ "$FAIL" -eq 0 ] && echo "chat-web + end-to-end chat path verified." || echo "Fix the failures above."
exit $([ "$FAIL" -eq 0 ] && echo 0 || echo 1)
