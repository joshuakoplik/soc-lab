#!/usr/bin/env bash
# SPEC.md §13 milestone 6 / §6.2: proves the pre-filter vs post-filter
# *difference* is real and measurable, not just that both code paths run.
set -uo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")/.."

PASS=0; FAIL=0
ok()  { echo "  [PASS] $1"; PASS=$((PASS+1)); }
bad() { echo "  [FAIL] $1"; FAIL=$((FAIL+1)); }

OUT="$(docker compose exec -T retrieval-svc python3 - <<'PYEOF'
import json
import random
import urllib.request

import psycopg2
import psycopg2.extras

from policy import policy

conn = psycopg2.connect(policy.DATABASE_URL)
cur = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)


def call_search(user_id, query, k, mode):
    body = json.dumps({"user_id": user_id, "query": query, "k": k, "mode": mode}).encode()
    req = urllib.request.Request(
        "http://localhost:8000/search", data=body, headers={"Content-Type": "application/json"}
    )
    with urllib.request.urlopen(req, timeout=30) as resp:
        return json.loads(resp.read())


# === Part A: constructed leak demonstration ===
# A same-tenant (user, document) pair the user is denied -- department
# mismatch, no grant, no share. Embedding the document's own content as the
# query guarantees it ranks at or near #1 by similarity.
cur.execute("SELECT id, tenant_id, department_id FROM app.users")
users = cur.fetchall()
cur.execute("SELECT id, tenant_id, label, owning_department_id, content FROM app.documents WHERE label != 'public'")
docs = cur.fetchall()

target_user = target_doc = None
for u in users:
    for d in docs:
        if u["tenant_id"] == d["tenant_id"] and u["department_id"] != d["owning_department_id"]:
            if not policy.decide(u["id"], d["id"], "read", conn=conn).allowed:
                target_user, target_doc = u, d
                break
    if target_user:
        break

if not target_user:
    print("LEAK_SETUP=failed")
else:
    pre = call_search(target_user["id"], target_doc["content"], 3, "prefilter")
    post = call_search(target_user["id"], target_doc["content"], 3, "postfilter")
    pre_ids = {r["document_id"] for r in pre["results"]}
    print(f"LEAK_SETUP=ok user={target_user['id']} denied_doc={target_doc['id']}")
    print(f"LEAK_PRE_COUNT={pre['count']}")
    print(f"LEAK_POST_COUNT={post['count']}")
    print(f"LEAK_PRE_INCLUDES_DENIED={'yes' if target_doc['id'] in pre_ids else 'no'}")

# === Part B: broader sample sweep, both modes, cross-checked against policy.decide() ===
rng = random.Random("verify-retrieval")
sample_users = rng.sample(users, min(6, len(users)))
queries = [
    "quarterly budget review", "incident response steps", "employee onboarding process",
    "customer pricing plans", "system architecture design",
]
total = 0
mismatches = 0
for u in sample_users:
    q = rng.choice(queries)
    for mode in ("prefilter", "postfilter"):
        result = call_search(u["id"], q, 5, mode)
        for r in result["results"]:
            total += 1
            if not policy.decide(u["id"], r["document_id"], "read", conn=conn).allowed:
                mismatches += 1
                print(f"SWEEP_MISMATCH user={u['id']} doc={r['document_id']} mode={mode}")

print(f"SWEEP_TOTAL={total}")
print(f"SWEEP_MISMATCHES={mismatches}")
PYEOF
)"

echo "$OUT" | sed 's/^/  /'
echo

echo "=== 1. Constructed leak demonstration (SPEC.md §6.2) ==="
if echo "$OUT" | grep -q "^LEAK_SETUP=ok"; then
  PRE_COUNT="$(echo "$OUT" | sed -n 's/^LEAK_PRE_COUNT=//p')"
  POST_COUNT="$(echo "$OUT" | sed -n 's/^LEAK_POST_COUNT=//p')"
  PRE_INCLUDES="$(echo "$OUT" | sed -n 's/^LEAK_PRE_INCLUDES_DENIED=//p')"

  [ "$PRE_INCLUDES" = "no" ] && ok "prefilter never returned the denied document" \
    || bad "prefilter returned the denied document -- SQL predicate is wrong"

  [ "$PRE_COUNT" = "3" ] && ok "prefilter backfilled a full k=3 entitled results" \
    || bad "prefilter returned $PRE_COUNT/3 (expected a full backfilled 3)"

  if [ -n "$POST_COUNT" ] && [ "$POST_COUNT" -lt 3 ]; then
    ok "postfilter returned $POST_COUNT/3 -- the exact result-count leak SPEC.md §6.2 describes"
  else
    bad "postfilter returned $POST_COUNT/3 -- expected fewer than 3 (no backfill after dropping the denied doc)"
  fi
else
  bad "could not find a same-tenant denied (user, document) pair to construct the test -- check corpus/entitlement data"
fi

echo
echo "=== 2. Sample sweep: every returned result is genuinely policy-allowed ==="
TOTAL="$(echo "$OUT" | sed -n 's/^SWEEP_TOTAL=//p')"
MISMATCHES="$(echo "$OUT" | sed -n 's/^SWEEP_MISMATCHES=//p')"
if [ "$MISMATCHES" = "0" ]; then
  ok "$TOTAL/$TOTAL returned results are policy-allowed, across both modes"
else
  bad "$MISMATCHES/$TOTAL returned results were policy-denied (see SWEEP_MISMATCH lines above)"
fi

echo
echo "=== Result: $PASS passed, $FAIL failed ==="
[ "$FAIL" -eq 0 ] && echo "Retrieval pre-filter/post-filter verified end to end." || echo "Fix the failures above."
exit $([ "$FAIL" -eq 0 ] && echo 0 || echo 1)
