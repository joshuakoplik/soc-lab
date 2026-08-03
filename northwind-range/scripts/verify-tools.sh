#!/usr/bin/env bash
# SPEC.md §13 milestone 8 / §8: proves the ENT_TOOL confused-deputy gap is
# real and measurable, not just that four endpoints exist.
set -uo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")/.."

PASS=0; FAIL=0
ok()  { echo "  [PASS] $1"; PASS=$((PASS+1)); }
bad() { echo "  [FAIL] $1"; FAIL=$((FAIL+1)); }

OUT="$(docker compose exec -T tool-svc python3 - <<'PYEOF'
import json
import urllib.error
import urllib.request

import psycopg2
import psycopg2.extras

from policy import policy

conn = psycopg2.connect(policy.DATABASE_URL)
cur = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)


def invoke(tool, args, user_id, ent_tool=True):
    body = json.dumps({"tool": tool, "args": args, "user_id": user_id, "ent_tool": ent_tool}).encode()
    req = urllib.request.Request(
        "http://localhost:8000/invoke", data=body, headers={"Content-Type": "application/json"}
    )
    try:
        resp = urllib.request.urlopen(req, timeout=30)
        return resp.status, json.loads(resp.read())
    except urllib.error.HTTPError as e:
        return e.code, json.loads(e.read())


# A user and a customer/ticket in a *different* tenant.
cur.execute("SELECT id, tenant_id FROM app.users ORDER BY id LIMIT 1")
user = cur.fetchone()
cur.execute("SELECT id, tenant_id, name, email, phone FROM app.customers WHERE tenant_id != %s ORDER BY id LIMIT 1", (user["tenant_id"],))
other_customer = cur.fetchone()
cur.execute("SELECT id FROM app.customers WHERE tenant_id = %s ORDER BY id LIMIT 1", (user["tenant_id"],))
own_customer = cur.fetchone()
cur.execute("SELECT id, tenant_id FROM app.tickets WHERE tenant_id != %s ORDER BY id LIMIT 1", (user["tenant_id"],))
other_ticket = cur.fetchone()

# === 1. customer_record: the confused-deputy leak ===
status_on, body_on = invoke("customer_record", {"customer_id": other_customer["id"]}, user["id"], True)
status_off, body_off = invoke("customer_record", {"customer_id": other_customer["id"]}, user["id"], False)
print(f"CR_DENIED_STATUS={status_on}")
print(f"CR_LEAK_STATUS={status_off}")
leaked_email = body_off.get("result", {}).get("email") if status_off == 200 else None
print(f"CR_LEAK_EMAIL={leaked_email == other_customer['email']}")

# === 2. Same-tenant access works regardless of ent_tool ===
status_a, _ = invoke("customer_record", {"customer_id": own_customer["id"]}, user["id"], True)
status_b, _ = invoke("customer_record", {"customer_id": own_customer["id"]}, user["id"], False)
print(f"CR_SAME_TENANT_ON={status_a}")
print(f"CR_SAME_TENANT_OFF={status_b}")

# === 3. ticket_lookup gets the same treatment ===
status_ton, _ = invoke("ticket_lookup", {"ticket_id": other_ticket["id"]}, user["id"], True)
status_toff, _ = invoke("ticket_lookup", {"ticket_id": other_ticket["id"]}, user["id"], False)
print(f"TICKET_DENIED_STATUS={status_ton}")
print(f"TICKET_LEAK_STATUS={status_toff}")

# === 4. usage_calc gets the same treatment ===
status_uon, _ = invoke("usage_calc", {"customer_id": other_customer["id"], "metric": "api_calls"}, user["id"], True)
status_uoff, body_uoff = invoke("usage_calc", {"customer_id": other_customer["id"], "metric": "api_calls"}, user["id"], False)
print(f"USAGE_DENIED_STATUS={status_uon}")
print(f"USAGE_LEAK_STATUS={status_uoff}")
print(f"USAGE_LEAK_HAS_RESULT={body_uoff.get('result', {}).get('result') is not None}")

# === 5. doc_search passthrough consistency ===
_, tool_result = invoke("doc_search", {"query": "on-call escalation process", "k": 5}, user["id"], True)
tool_ids = sorted(r["document_id"] for r in tool_result["result"]["results"])

direct_body = json.dumps({"user_id": user["id"], "query": "on-call escalation process", "k": 5, "mode": "prefilter"}).encode()
direct_req = urllib.request.Request(
    "http://retrieval-svc:8000/search", data=direct_body, headers={"Content-Type": "application/json"}
)
direct_result = json.loads(urllib.request.urlopen(direct_req, timeout=30).read())
direct_ids = sorted(r["document_id"] for r in direct_result["results"])
print(f"DOC_SEARCH_MATCH={tool_ids == direct_ids}")
PYEOF
)"

echo "$OUT" | sed 's/^/  /'
echo

echo "=== 1. customer_record: confused-deputy leak, demonstrated on real data ==="
echo "$OUT" | grep -q "^CR_DENIED_STATUS=403" && ok "cross-tenant lookup denied when ent_tool=True" \
  || bad "cross-tenant lookup was NOT denied with ent_tool=True"
echo "$OUT" | grep -q "^CR_LEAK_STATUS=200" && ok "cross-tenant lookup succeeds when ent_tool=False" \
  || bad "cross-tenant lookup did not succeed with ent_tool=False (expected the leak to reproduce)"
echo "$OUT" | grep -q "^CR_LEAK_EMAIL=True" && ok "real customer PII (email) leaked when ent_tool=False" \
  || bad "leaked record's email didn't match the expected customer -- leak not confirmed"

echo
echo "=== 2. Same-tenant access always works ==="
echo "$OUT" | grep -q "^CR_SAME_TENANT_ON=200" && echo "$OUT" | grep -q "^CR_SAME_TENANT_OFF=200" \
  && ok "same-tenant customer_record succeeds regardless of ent_tool" \
  || bad "same-tenant customer_record failed for at least one ent_tool state"

echo
echo "=== 3. ticket_lookup: same confused-deputy treatment ==="
echo "$OUT" | grep -q "^TICKET_DENIED_STATUS=403" && ok "cross-tenant ticket denied when ent_tool=True" \
  || bad "cross-tenant ticket was NOT denied with ent_tool=True"
echo "$OUT" | grep -q "^TICKET_LEAK_STATUS=200" && ok "cross-tenant ticket leaks when ent_tool=False" \
  || bad "cross-tenant ticket did not leak with ent_tool=False"

echo
echo "=== 4. usage_calc: same confused-deputy treatment ==="
echo "$OUT" | grep -q "^USAGE_DENIED_STATUS=403" && ok "cross-tenant usage_calc denied when ent_tool=True" \
  || bad "cross-tenant usage_calc was NOT denied with ent_tool=True"
echo "$OUT" | grep -q "^USAGE_LEAK_STATUS=200" && echo "$OUT" | grep -q "^USAGE_LEAK_HAS_RESULT=True" \
  && ok "cross-tenant usage_calc leaks a real computed result when ent_tool=False" \
  || bad "cross-tenant usage_calc did not leak a real result with ent_tool=False"

echo
echo "=== 5. doc_search passthrough consistency ==="
echo "$OUT" | grep -q "^DOC_SEARCH_MATCH=True" && ok "tool-svc's doc_search matches retrieval-svc called directly" \
  || bad "tool-svc's doc_search returned different documents than calling retrieval-svc directly"

echo
echo "=== Result: $PASS passed, $FAIL failed ==="
[ "$FAIL" -eq 0 ] && echo "tool-svc verified end to end." || echo "Fix the failures above."
exit $([ "$FAIL" -eq 0 ] && echo 0 || echo 1)
