#!/usr/bin/env bash
# SPEC.md §13 milestone 12 / §10: proves telemetry actually ships into the
# existing SOC-lab normalizer schema. Runs the real pipeline/ingest.py code
# against an isolated scratch SQLite database (never soc.db -- the same
# isolation precedent injection_asr/run_asr.py already established) so the
# live Northwind stack's real telemetry files can be tailed for real
# without ever touching production SOC telemetry.
set -uo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")/.."
REPO_ROOT="$(cd .. && pwd)"
SCRATCH_DB="$(mktemp -u /tmp/verify-telemetry-XXXXXX.db)"
PY="$( [ -x .venv/bin/python3 ] && echo .venv/bin/python3 || echo python3)"

PASS=0; FAIL=0
ok()  { echo "  [PASS] $1"; PASS=$((PASS+1)); }
bad() { echo "  [FAIL] $1"; FAIL=$((FAIL+1)); }

cleanup() { rm -f "$SCRATCH_DB" "$SCRATCH_DB-wal" "$SCRATCH_DB-shm"; }
trap cleanup EXIT

echo "=== 1. Generate real content through the live stack ==="
MARIA_PW="$(.venv/bin/python3 -c "import json; print(json.load(open('.seed-credentials.json'))['maria.support'])" 2>/dev/null || python3 -c "import json; print(json.load(open('.seed-credentials.json'))['maria.support'])")"
GEN_OUT="$(docker compose exec -T -e MARIA_PW="$MARIA_PW" portal-api python3 - <<'PYEOF'
import http.cookiejar, json, os, time, urllib.request

password = os.environ["MARIA_PW"]
cj = http.cookiejar.CookieJar()
opener = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(cj))

def post(path, body, timeout=15):
    req = urllib.request.Request(f"http://localhost:8000{path}", data=json.dumps(body).encode(),
                                  headers={"Content-Type": "application/json"})
    return opener.open(req, timeout=timeout)

post("/auth/login", {"tenant": "fenwick", "username": "maria.support", "password": password})
resp = post("/chat", {"message": "What is our on-call escalation process?"}, timeout=120)
print(f"CHAT_STATUS={resp.status}")

marker = f"verify-telemetry probe {int(time.time())}"
resp2 = post("/feedback", {"tenant": "riverside", "message": marker, "submitter": "verify-telemetry@example.com"}, timeout=15)
data = json.loads(resp2.read())
print(f"FEEDBACK_STATUS={resp2.status}")
print(f"FEEDBACK_DOC_ID={data['document_id']}")
print(f"FEEDBACK_CONTENT={marker}")
PYEOF
)"
echo "$GEN_OUT" | sed 's/^/  /'
echo "$GEN_OUT" | grep -q "^CHAT_STATUS=200" && echo "$GEN_OUT" | grep -q "^FEEDBACK_STATUS=200" \
  && ok "generated real /chat and /feedback activity" || bad "failed to generate real activity -- see output above"

FEEDBACK_CONTENT="$(echo "$GEN_OUT" | sed -n 's/^FEEDBACK_CONTENT=//p')"
FEEDBACK_DOC_ID="$(echo "$GEN_OUT" | sed -n 's/^FEEDBACK_DOC_ID=//p')"

echo
echo "=== 2. Isolated ingest (scratch DB, never soc.db) ==="
INGEST_OUT="$("$PY" -c "
import sys
sys.path.insert(0, '$REPO_ROOT/pipeline')
import ingest

conn = ingest.connect(reset=True, db_path='$SCRATCH_DB')
total = 0
for source, path in ingest.SOURCES:
    n = ingest.read_new(conn, source, path)
    total += n
    print(f'{source}={n}')
for source, path in ingest.TRANSCRIPT_SOURCES:
    n = ingest.read_new_transcripts(conn, path)
    total += n
    print(f'transcripts_{source}={n}')
print(f'TOTAL={total}')
fails = conn.execute('SELECT COUNT(*) FROM parse_failures').fetchone()[0]
print(f'PARSE_FAILURES={fails}')
")"
echo "$INGEST_OUT" | sed 's/^/  /'
for src in northwind-nginx northwind-portal-api northwind-policy northwind-ingest northwind-retrieval; do
  N="$(echo "$INGEST_OUT" | sed -n "s/^${src}=//p")"
  [ -n "$N" ] && [ "$N" -gt 0 ] 2>/dev/null && ok "$src: $N row(s) ingested" || bad "$src: no rows ingested (got: $N)"
done
TRANSCRIPT_N="$(echo "$INGEST_OUT" | sed -n 's/^transcripts_northwind-portal-api=//p')"
[ -n "$TRANSCRIPT_N" ] && [ "$TRANSCRIPT_N" -gt 0 ] 2>/dev/null && ok "llm_transcripts: $TRANSCRIPT_N row(s) ingested" \
  || bad "llm_transcripts: no rows ingested"
echo "$INGEST_OUT" | grep -q "^PARSE_FAILURES=0$" && ok "zero parse failures on well-formed real telemetry" \
  || bad "unexpected parse failures on real telemetry (see PARSE_FAILURES above)"

echo
echo "=== 3. Trust-column placement ==="
TRUST_OUT="$(sqlite3 "$SCRATCH_DB" "
select username, request_body from events
where source='northwind-ingest' and message = (
  select message from events where source='northwind-ingest' order by id desc limit 1
) order by id desc limit 1;
")"
echo "  $TRUST_OUT"
if echo "$TRUST_OUT" | grep -qF "$FEEDBACK_CONTENT"; then
  ok "ingested (attacker-controlled) content landed in request_body, not elsewhere"
else
  bad "ingested content did not land in request_body as expected"
fi

CONTROLS_OUT="$("$PY" -c "
import sqlite3, json
conn = sqlite3.connect('$SCRATCH_DB')
row = conn.execute(\"select request_body from events where source='northwind-portal-api' and event_type='portal.chat' order by id desc limit 1\").fetchone()
if row and row[0]:
    parsed = json.loads(row[0])
    print('VALID_JSON=True')
    print('HAS_ENT_RETRIEVAL=' + str('ENT_RETRIEVAL' in parsed))
else:
    print('VALID_JSON=False')
")"
echo "$CONTROLS_OUT" | sed 's/^/  /'
echo "$CONTROLS_OUT" | grep -q "^VALID_JSON=True" && echo "$CONTROLS_OUT" | grep -q "^HAS_ENT_RETRIEVAL=True" \
  && ok "portal-api's active control vector landed in request_body as valid, complete JSON" \
  || bad "control vector did not land correctly in request_body"

echo
echo "=== 4. llm_transcripts row shape ==="
TRANSCRIPT_ROW="$("$PY" -c "
import sqlite3, json
conn = sqlite3.connect('$SCRATCH_DB')
row = conn.execute('select system_prompt, user_turn, completion, retrieved_context, controls from llm_transcripts order by id desc limit 1').fetchone()
if not row:
    print('NO_ROW=True')
else:
    system_prompt, user_turn, completion, retrieved_context, controls = row
    print(f'HAS_SYSTEM_PROMPT={bool(system_prompt)}')
    print(f'HAS_USER_TURN={bool(user_turn)}')
    print(f'HAS_COMPLETION={bool(completion)}')
    try:
        json.loads(retrieved_context)
        json.loads(controls)
        print('JSON_FIELDS_VALID=True')
    except Exception as e:
        print(f'JSON_FIELDS_VALID=False ({e})')
")"
echo "$TRANSCRIPT_ROW" | sed 's/^/  /'
echo "$TRANSCRIPT_ROW" | grep -q "^HAS_SYSTEM_PROMPT=True" && echo "$TRANSCRIPT_ROW" | grep -q "^HAS_USER_TURN=True" \
  && echo "$TRANSCRIPT_ROW" | grep -q "^HAS_COMPLETION=True" \
  && ok "llm_transcripts row has non-empty system_prompt/user_turn/completion" \
  || bad "llm_transcripts row is missing expected content"
echo "$TRANSCRIPT_ROW" | grep -q "^JSON_FIELDS_VALID=True" && ok "retrieved_context/controls parse as valid JSON" \
  || bad "retrieved_context/controls are not valid JSON"

echo
echo "=== 5. Malformed-line handling ==="
MALFORMED_OUT="$("$PY" -c "
import sys
sys.path.insert(0, '$REPO_ROOT/pipeline')
import ingest

conn = sys.modules['ingest'].sqlite3.connect('$SCRATCH_DB')
conn.row_factory = sys.modules['ingest'].sqlite3.Row
before = conn.execute('SELECT COUNT(*) FROM parse_failures').fetchone()[0]
result = ingest.ingest_line(conn, 'northwind-ingest', 'fabricated-for-verify', 'not valid json{')
conn.commit()
after = conn.execute('SELECT COUNT(*) FROM parse_failures').fetchone()[0]
print(f'INGEST_LINE_RESULT={result}')
print(f'PARSE_FAILURE_RECORDED={after == before + 1}')
")"
echo "$MALFORMED_OUT" | sed 's/^/  /'
echo "$MALFORMED_OUT" | grep -q "^INGEST_LINE_RESULT=False$" && echo "$MALFORMED_OUT" | grep -q "^PARSE_FAILURE_RECORDED=True$" \
  && ok "a malformed line is rejected and recorded to parse_failures, not silently dropped" \
  || bad "malformed-line handling did not behave as expected"

echo
echo "=== 6. Idempotent re-tail ==="
COUNT_BEFORE="$(sqlite3 "$SCRATCH_DB" "select count(*) from events;")"
"$PY" -c "
import sys
sys.path.insert(0, '$REPO_ROOT/pipeline')
import ingest
conn = ingest.connect(db_path='$SCRATCH_DB')
for source, path in ingest.SOURCES:
    ingest.read_new(conn, source, path)
for source, path in ingest.TRANSCRIPT_SOURCES:
    ingest.read_new_transcripts(conn, path)
" > /dev/null
COUNT_AFTER="$(sqlite3 "$SCRATCH_DB" "select count(*) from events;")"
[ "$COUNT_BEFORE" = "$COUNT_AFTER" ] && ok "re-tailing with no new content is a no-op ($COUNT_BEFORE -> $COUNT_AFTER)" \
  || bad "re-tailing double-counted rows ($COUNT_BEFORE -> $COUNT_AFTER)"

echo
echo "=== 7. northwind-nginx is a thin wrapper, not a diverged duplicate ==="
WRAPPER_OUT="$("$PY" -c "
import sys
sys.path.insert(0, '$REPO_ROOT/pipeline')
from normalize import normalize_nginx, normalize_northwind_nginx

sample = '{\"@timestamp\":\"2026-01-01T00:00:00+00:00\",\"source_ip\":\"1.2.3.4\",\"source_port\":\"1234\",\"http_method\":\"GET\",\"url_path\":\"/x\",\"url_query\":\"\",\"status\":200,\"bytes_sent\":10,\"referer\":\"-\",\"user_agent\":\"ua\",\"request_body\":\"\"}'
import json
obj = json.loads(sample)
row_a = normalize_nginx(obj, sample)
row_b = normalize_northwind_nginx(obj, sample)
diffs = {k: (row_a[k], row_b[k]) for k in row_a if k != 'source' and row_a[k] != row_b[k]}
print(f'SOURCE_A={row_a[\"source\"]}')
print(f'SOURCE_B={row_b[\"source\"]}')
print(f'ONLY_SOURCE_DIFFERS={not diffs}')
")"
echo "$WRAPPER_OUT" | sed 's/^/  /'
echo "$WRAPPER_OUT" | grep -q "^SOURCE_A=nginx$" && echo "$WRAPPER_OUT" | grep -q "^SOURCE_B=northwind-nginx$" \
  && echo "$WRAPPER_OUT" | grep -q "^ONLY_SOURCE_DIFFERS=True$" \
  && ok "normalize_northwind_nginx() differs from normalize_nginx() only in the source field" \
  || bad "normalize_northwind_nginx() has diverged from normalize_nginx() beyond the source field"

echo
echo "=== Result: $PASS passed, $FAIL failed ==="
[ "$FAIL" -eq 0 ] && echo "Telemetry shippers verified end to end." || echo "Fix the failures above."
exit $([ "$FAIL" -eq 0 ] && echo 0 || echo 1)
