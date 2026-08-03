#!/usr/bin/env bash
# SPEC.md §13 milestone 9 / §6.3: proves all three ingestion sources land
# content in the real index (retrievable, not just stored), that the two
# polled sources (ticket feed, drive sync) are idempotent and pick up
# edits, that the background poll thread is real infrastructure and not
# dead code, and that provenance (source/submitter/content_hash) is
# recorded correctly per §10.
set -uo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")/.."

PASS=0; FAIL=0
ok()  { echo "  [PASS] $1"; PASS=$((PASS+1)); }
bad() { echo "  [FAIL] $1"; FAIL=$((FAIL+1)); }

psql_q() { docker compose exec -T postgres psql -U northwind -d northwind -tAc "$1" 2>&1 < /dev/null; }

poll_once() {
  docker compose exec -T portal-api python3 -c "
import json, urllib.request
req = urllib.request.Request('http://ingest-svc:8000/poll', data=b'{}', headers={'Content-Type': 'application/json'})
print(json.dumps(json.loads(urllib.request.urlopen(req, timeout=60).read())))
" < /dev/null
}

echo "=== 1+2. Feedback form (unauthenticated, through edge-nginx) + retrievability ==="
FEEDBACK_OUT="$(docker compose exec -T portal-api python3 - <<'PYEOF'
import hashlib
import json
import urllib.request

import psycopg2
import psycopg2.extras

DB = "postgresql://northwind:northwind-placeholder@postgres:5432/northwind"
MSG = "Northwind verify-ingest feedback probe: please add a bulk CSV export option to the customer dashboard."
SUBMITTER = "anonymous-tester@example.com"

req = urllib.request.Request(
    "http://edge-nginx/api/feedback",
    data=json.dumps({"tenant": "riverside", "message": MSG, "submitter": SUBMITTER}).encode(),
    headers={"Content-Type": "application/json"},
)
resp = urllib.request.urlopen(req, timeout=15)
data = json.loads(resp.read())
print(f"FEEDBACK_STATUS={resp.status}")
doc_id = data["document_id"]
print(f"FEEDBACK_DOC_ID={doc_id}")

conn = psycopg2.connect(DB)
cur = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
cur.execute(
    "SELECT d.source, d.submitter, d.label, d.content, dep.name AS dept, "
    "       (d.embedding IS NOT NULL) AS has_embedding "
    "FROM app.documents d JOIN app.departments dep ON dep.id = d.owning_department_id "
    "WHERE d.id = %s",
    (doc_id,),
)
doc = cur.fetchone()
print(f"FEEDBACK_SOURCE={doc['source']}")
print(f"FEEDBACK_SUBMITTER_MATCH={doc['submitter'] == SUBMITTER}")
print(f"FEEDBACK_LABEL={doc['label']}")
print(f"FEEDBACK_DEPT={doc['dept']}")
print(f"FEEDBACK_HAS_EMBEDDING={doc['has_embedding']}")
print(f"FEEDBACK_CONTENT_MATCH={doc['content'] == MSG}")

expected_hash = hashlib.sha256(MSG.encode()).hexdigest()
cur.execute("SELECT content_hash FROM app.ingest_events WHERE document_id = %s", (doc_id,))
ev = cur.fetchone()
print(f"FEEDBACK_EVENT_HASH_MATCH={ev is not None and ev['content_hash'] == expected_hash}")

cur.execute(
    "SELECT u.id FROM app.users u JOIN app.tenants t ON t.id = u.tenant_id "
    "JOIN app.departments d ON d.id = u.department_id "
    "WHERE t.slug = 'riverside' AND d.name = 'Support' ORDER BY u.id LIMIT 1"
)
support_user_id = cur.fetchone()["id"]

search_req = urllib.request.Request(
    "http://retrieval-svc:8000/search",
    data=json.dumps({
        "user_id": support_user_id, "query": "bulk CSV export customer dashboard",
        "k": 10, "mode": "prefilter",
    }).encode(),
    headers={"Content-Type": "application/json"},
)
search_data = json.loads(urllib.request.urlopen(search_req, timeout=30).read())
found = next((r for r in search_data["results"] if r["document_id"] == doc_id), None)
print(f"FEEDBACK_RETRIEVABLE={found is not None}")
if found:
    print(f"FEEDBACK_RESULT_SOURCE={found['source']}")
    print(f"FEEDBACK_RESULT_SUBMITTER_MATCH={found['submitter'] == SUBMITTER}")
PYEOF
)"
echo "$FEEDBACK_OUT" | sed 's/^/  /'
echo

echo "$FEEDBACK_OUT" | grep -q "^FEEDBACK_STATUS=200" && ok "feedback form accepted unauthenticated" \
  || bad "feedback form did not return 200"
echo "$FEEDBACK_OUT" | grep -q "^FEEDBACK_SOURCE=feedback_form" && ok "document tagged source=feedback_form" \
  || bad "document's source field is wrong"
echo "$FEEDBACK_OUT" | grep -q "^FEEDBACK_SUBMITTER_MATCH=True" && ok "submitter recorded as claimed" \
  || bad "submitter not recorded correctly"
echo "$FEEDBACK_OUT" | grep -q "^FEEDBACK_LABEL=internal" && echo "$FEEDBACK_OUT" | grep -q "^FEEDBACK_DEPT=Support" \
  && ok "landed in Support/internal, no human review" \
  || bad "wrong department/label for a feedback-form document"
echo "$FEEDBACK_OUT" | grep -q "^FEEDBACK_HAS_EMBEDDING=True" && ok "embedded synchronously at ingestion" \
  || bad "document has no embedding"
echo "$FEEDBACK_OUT" | grep -q "^FEEDBACK_CONTENT_MATCH=True" && ok "stored content matches what was submitted" \
  || bad "stored content doesn't match the submission"
echo "$FEEDBACK_OUT" | grep -q "^FEEDBACK_EVENT_HASH_MATCH=True" && ok "ingest_events content_hash is a real sha256 of the content" \
  || bad "ingest_events content_hash doesn't match"
echo "$FEEDBACK_OUT" | grep -q "^FEEDBACK_RETRIEVABLE=True" && ok "feedback document is genuinely retrievable via retrieval-svc" \
  || bad "feedback document did not come back from a real search"
echo "$FEEDBACK_OUT" | grep -q "^FEEDBACK_RESULT_SOURCE=feedback_form" && echo "$FEEDBACK_OUT" | grep -q "^FEEDBACK_RESULT_SUBMITTER_MATCH=True" \
  && ok "provenance (source/submitter) travels with the search result" \
  || bad "search result is missing correct provenance fields"

echo
echo "=== 3. Ticket feed + idempotency ==="
TICKET_OUT="$(docker compose exec -T portal-api python3 - <<'PYEOF'
import json
import urllib.request

import psycopg2
import psycopg2.extras

DB = "postgresql://northwind:northwind-placeholder@postgres:5432/northwind"
conn = psycopg2.connect(DB)
cur = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)

cur.execute(
    "SELECT tk.id, tk.subject, tk.body, c.email AS customer_email "
    "FROM app.tickets tk JOIN app.customers c ON c.id = tk.customer_id "
    "WHERE tk.status = 'closed' ORDER BY tk.id LIMIT 1"
)
ticket = cur.fetchone()
print(f"TICKET_ID={ticket['id']}")


def poll():
    req = urllib.request.Request(
        "http://ingest-svc:8000/poll", data=b"{}", headers={"Content-Type": "application/json"}
    )
    return json.loads(urllib.request.urlopen(req, timeout=60).read())


result1 = poll()
print(f"POLL1_TICKETS={result1['tickets_ingested']}")

cur.execute(
    "SELECT document_id FROM app.ingest_events WHERE source = 'ticket_feed' AND source_ref = %s",
    (str(ticket["id"]),),
)
ev = cur.fetchone()
print(f"TICKET_EVENT_FOUND={ev is not None}")
if ev:
    cur.execute("SELECT title, content, submitter, source FROM app.documents WHERE id = %s", (ev["document_id"],))
    doc = cur.fetchone()
    print(f"TICKET_TITLE_MATCH={doc['title'] == ticket['subject']}")
    print(f"TICKET_CONTENT_MATCH={doc['content'] == ticket['body']}")
    print(f"TICKET_SUBMITTER_MATCH={doc['submitter'] == ticket['customer_email']}")
    print(f"TICKET_SOURCE={doc['source']}")

result2 = poll()
print(f"POLL2_TICKETS={result2['tickets_ingested']}")

cur.execute(
    "SELECT count(*) AS n FROM app.ingest_events WHERE source = 'ticket_feed' AND source_ref = %s",
    (str(ticket["id"]),),
)
print(f"TICKET_EVENT_COUNT_AFTER_REPOLL={cur.fetchone()['n']}")
PYEOF
)"
echo "$TICKET_OUT" | sed 's/^/  /'
echo

echo "$TICKET_OUT" | grep -q "^TICKET_EVENT_FOUND=True" && ok "closed ticket auto-indexed on poll" \
  || bad "closed ticket was not ingested"
echo "$TICKET_OUT" | grep -q "^TICKET_TITLE_MATCH=True" && echo "$TICKET_OUT" | grep -q "^TICKET_CONTENT_MATCH=True" \
  && ok "document title/content match the ticket's subject/body" \
  || bad "document content doesn't match the source ticket"
echo "$TICKET_OUT" | grep -q "^TICKET_SUBMITTER_MATCH=True" && ok "submitter recorded as the ticket's customer email" \
  || bad "submitter not derived from the ticket's customer"
echo "$TICKET_OUT" | grep -q "^TICKET_SOURCE=ticket_feed" && ok "document tagged source=ticket_feed" \
  || bad "document's source field is wrong"
echo "$TICKET_OUT" | grep -q "^POLL2_TICKETS=0" && echo "$TICKET_OUT" | grep -q "^TICKET_EVENT_COUNT_AFTER_REPOLL=1" \
  && ok "re-polling the same ticket is a no-op (idempotent)" \
  || bad "re-polling created a duplicate ingestion"

echo
echo "=== 4. Drive sync + idempotency + edit detection ==="
# Unique per invocation -- so re-running this script without a fresh
# `make reset` in between never collides with a previous run's leftover
# ingest_events rows for the same source_ref.
RUN_ID="$$-$(date +%s)"
WATCH_TENANT_DIR="services/ingest-svc/watched/riverside"
mkdir -p "$WATCH_TENANT_DIR"
TEST_FILE="$WATCH_TENANT_DIR/verify-ingest-test-$RUN_ID.md"
TEST_REF="riverside/verify-ingest-test-$RUN_ID.md"
ORIGINAL_TEXT="Internal note: rotate the shared signing key before the next audit."
UPDATED_TEXT="Internal note: rotate the shared signing key before the next audit. UPDATE: rotation completed."

printf '%s' "$ORIGINAL_TEXT" > "$TEST_FILE"
POLL_A="$(poll_once)"
echo "  poll after new file: $POLL_A"

COUNT_A="$(psql_q "select count(*) from app.ingest_events where source='drive_sync' and source_ref='$TEST_REF';")"
[ "$COUNT_A" = "1" ] && ok "new watched file ingested on poll" || bad "new watched file was not ingested (count=$COUNT_A)"

DRIVE_DETAIL="$(docker compose exec -T postgres psql -U northwind -d northwind -tAc "
select d.source || '|' || coalesce(d.submitter,'NULL') || '|' || d.label || '|' || dep.name || '|' || (d.content = '$ORIGINAL_TEXT')
from app.ingest_events e join app.documents d on d.id = e.document_id
join app.departments dep on dep.id = d.owning_department_id
where e.source='drive_sync' and e.source_ref='$TEST_REF'
order by e.created_at desc limit 1;" 2>&1 < /dev/null)"
echo "  detail: $DRIVE_DETAIL"
IFS='|' read -r D_SOURCE D_SUBMITTER D_LABEL D_DEPT D_CONTENT_MATCH <<< "$DRIVE_DETAIL"
[ "$D_SOURCE" = "drive_sync" ] && ok "document tagged source=drive_sync" || bad "wrong source tag"
[ "$D_SUBMITTER" = "NULL" ] && ok "submitter is NULL for a drive-sync document (no identity captured)" || bad "drive-sync document has an unexpected submitter"
[ "$D_LABEL" = "internal" ] && [ "$D_DEPT" = "Admin" ] && ok "landed in Admin/internal, no human review" \
  || bad "wrong department/label for a drive-sync document (label=$D_LABEL dept=$D_DEPT)"
[ "$D_CONTENT_MATCH" = "true" ] && ok "stored content matches the watched file" || bad "stored content doesn't match the watched file"

POLL_B="$(poll_once)"
echo "  poll again, no change: $POLL_B"
COUNT_B="$(psql_q "select count(*) from app.ingest_events where source='drive_sync' and source_ref='$TEST_REF';")"
[ "$COUNT_B" = "1" ] && ok "re-polling an unchanged watched file is a no-op (idempotent)" \
  || bad "re-polling an unchanged file created a duplicate (count=$COUNT_B)"

printf '%s' "$UPDATED_TEXT" > "$TEST_FILE"
POLL_C="$(poll_once)"
echo "  poll after editing the file: $POLL_C"
COUNT_C="$(psql_q "select count(*) from app.ingest_events where source='drive_sync' and source_ref='$TEST_REF';")"
[ "$COUNT_C" = "2" ] && ok "editing a watched file produces a new ingested version (content_hash changed)" \
  || bad "editing the watched file did not trigger re-ingestion (count=$COUNT_C)"

echo
echo "=== 5. Background poll thread is real, not dead code ==="
BG_FILE="$WATCH_TENANT_DIR/verify-ingest-bg-test-$RUN_ID.md"
BG_REF="riverside/verify-ingest-bg-test-$RUN_ID.md"
echo "Background-poll probe -- never submitted through /poll manually." > "$BG_FILE"
echo "  dropped $BG_FILE, waiting on the background thread (no manual /poll call)..."
sleep 27
COUNT_BG="$(psql_q "select count(*) from app.ingest_events where source='drive_sync' and source_ref='$BG_REF';")"
[ "$COUNT_BG" = "1" ] && ok "background poll thread picked up a new file on its own timer" \
  || bad "background poll thread never ingested the file (count=$COUNT_BG) -- is it actually running?"

echo
echo "=== 6. Unrecognized tenant directory is safely skipped ==="
mkdir -p "services/ingest-svc/watched/does-not-exist-tenant"
echo "should never be ingested" > "services/ingest-svc/watched/does-not-exist-tenant/skip-test-$RUN_ID.md"
poll_once > /dev/null
COUNT_SKIP="$(psql_q "select count(*) from app.ingest_events where source='drive_sync' and source_ref='does-not-exist-tenant/skip-test-$RUN_ID.md';")"
[ "$COUNT_SKIP" = "0" ] && ok "file under an unrecognized tenant directory was not ingested" \
  || bad "a file under a fake tenant directory got ingested anyway"

# Cleanup -- test fixtures, not part of make reset.
rm -f "$TEST_FILE" "$BG_FILE"
rm -rf "services/ingest-svc/watched/does-not-exist-tenant"

echo
echo "=== Result: $PASS passed, $FAIL failed ==="
[ "$FAIL" -eq 0 ] && echo "ingest-svc verified end to end." || echo "Fix the failures above."
exit $([ "$FAIL" -eq 0 ] && echo 0 || echo 1)
