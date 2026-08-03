#!/usr/bin/env bash
# SPEC.md §13 milestone 5 -- "the gate that matters." Every (user, document)
# pair swept against an independently-computed expected decision (never by
# calling policy.decide() and checking it agrees with itself), plus the
# login/session/token flow.
set -uo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")/.."

PASS=0; FAIL=0
ok()  { echo "  [PASS] $1"; PASS=$((PASS+1)); }
bad() { echo "  [FAIL] $1"; FAIL=$((FAIL+1)); }

echo "=== 1. Full entitlement sweep: every user x every document ==="
SWEEP_OUT="$(docker compose exec -T portal-api python3 - <<'PYEOF'
import sys
import psycopg2
from policy import policy

conn = psycopg2.connect(policy.DATABASE_URL)
cur = conn.cursor()

cur.execute("SELECT id, tenant_id, department_id FROM app.users")
users = cur.fetchall()

cur.execute("SELECT id, tenant_id, label, owning_department_id FROM app.documents")
docs = cur.fetchall()

cur.execute("""
    SELECT user_id, department_id FROM app.grants
    WHERE revoked_at IS NULL AND (expires_at IS NULL OR expires_at > now())
""")
active_grants = set(cur.fetchall())

cur.execute("SELECT document_id, department_id FROM app.document_shares")
shares = set(cur.fetchall())


def expected(user, doc):
    _, u_tenant, u_dept = user
    _, d_tenant, label, d_owner = doc
    if u_tenant != d_tenant:
        return False, "cross-tenant"
    if label == "public":
        return True, "public"
    if u_dept == d_owner:
        return True, "same-department"
    if (user[0], d_owner) in active_grants:
        return True, "active-grant"
    # u_dept, not d_owner -- a share names the department being granted
    # access, never the document's own owning department.
    if (doc[0], u_dept) in shares:
        return True, "explicit-share"
    return False, "no-entitlement"


mismatches = []
total = 0
for user in users:
    for doc in docs:
        total += 1
        want_allowed, want_reason = expected(user, doc)
        got = policy.decide(user[0], doc[0], "read", conn=conn)
        if got.allowed != want_allowed:
            mismatches.append((user[0], doc[0], want_allowed, want_reason, got.allowed, got.reason))

print(f"SWEEP_TOTAL={total}")
print(f"SWEEP_MISMATCHES={len(mismatches)}")
for m in mismatches[:20]:
    print(f"MISMATCH user={m[0]} doc={m[1]} want=({m[2]},{m[3]}) got=({m[4]},{m[5]})")
sys.exit(1 if mismatches else 0)
PYEOF
)"
SWEEP_STATUS=$?
echo "$SWEEP_OUT" | grep -E "^SWEEP_|^MISMATCH"
TOTAL="$(echo "$SWEEP_OUT" | sed -n 's/^SWEEP_TOTAL=//p')"
MISMATCHES="$(echo "$SWEEP_OUT" | sed -n 's/^SWEEP_MISMATCHES=//p')"
if [ "$SWEEP_STATUS" -eq 0 ]; then
  ok "$TOTAL/$TOTAL pairs correct"
else
  bad "$MISMATCHES/$TOTAL pairs incorrect (see MISMATCH lines above)"
fi

echo
echo "=== 2. Login / session / token flow ==="
if [ ! -f .seed-credentials.json ]; then
  bad ".seed-credentials.json missing -- run 'make seed' first"
else
  MARIA_PW="$(python3 -c "import json; print(json.load(open('.seed-credentials.json'))['maria.support'])" 2>/dev/null || .venv/bin/python3 -c "import json; print(json.load(open('.seed-credentials.json'))['maria.support'])")"
  FLOW_OUT="$(docker compose exec -T retrieval-svc python3 - <<PYEOF
import urllib.request, urllib.error, json, http.cookiejar

cj = http.cookiejar.CookieJar()
opener = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(cj))

def post(path, body, opener=opener):
    req = urllib.request.Request(f"http://portal-api:8000{path}", data=json.dumps(body).encode(),
                                  headers={"Content-Type": "application/json"})
    return opener.open(req, timeout=10)

# correct login
resp = post("/auth/login", {"tenant": "fenwick", "username": "maria.support", "password": "$MARIA_PW"})
print("LOGIN_STATUS=" + str(resp.status))

# /auth/me reflects the logged-in user
req = urllib.request.Request("http://portal-api:8000/auth/me")
resp = opener.open(req, timeout=10)
me = json.loads(resp.read())
print("ME_USERNAME=" + me.get("username", ""))

# wrong password rejected
try:
    post("/auth/login", {"tenant": "fenwick", "username": "maria.support", "password": "wrong-password"})
    print("WRONG_PW_STATUS=200")
except urllib.error.HTTPError as e:
    print("WRONG_PW_STATUS=" + str(e.code))

# issue an API token, then use it (no cookie) to hit /auth/me
resp = post("/auth/tokens", {})
token = json.loads(resp.read())["token"]
req = urllib.request.Request("http://portal-api:8000/auth/me", headers={"Authorization": f"Bearer {token}"})
resp = urllib.request.urlopen(req, timeout=10)
me2 = json.loads(resp.read())
print("TOKEN_ME_USERNAME=" + me2.get("username", ""))
PYEOF
)"
  echo "$FLOW_OUT" | sed 's/^/  /'
  echo "$FLOW_OUT" | grep -q "^LOGIN_STATUS=200" && ok "login succeeded" || bad "login did not return 200"
  echo "$FLOW_OUT" | grep -q "^ME_USERNAME=maria.support" && ok "/auth/me reflects the logged-in session" || bad "/auth/me did not reflect maria.support"
  echo "$FLOW_OUT" | grep -q "^WRONG_PW_STATUS=401" && ok "wrong password rejected (401)" || bad "wrong password was not rejected with 401"
  echo "$FLOW_OUT" | grep -q "^TOKEN_ME_USERNAME=maria.support" && ok "API token path authenticates correctly" || bad "API token path did not authenticate maria.support"
fi

echo
echo "=== Result: $PASS passed, $FAIL failed ==="
[ "$FAIL" -eq 0 ] && echo "Entitlements verified end to end." || echo "Fix the failures above."
exit $([ "$FAIL" -eq 0 ] && echo 0 || echo 1)
