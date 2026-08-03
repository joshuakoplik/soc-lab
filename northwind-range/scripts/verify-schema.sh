#!/usr/bin/env bash
# Standing check for the entitlement schema/seed data (SPEC.md §13 milestone
# 2) -- structure and seed correctness only. Distinct from milestone 5's
# verify-entitlements.sh, which will test policy *decisions* once the
# policy module exists; this script has no decision logic, just "did the
# schema and seed load the way the fixtures say they should."
set -uo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")/.."

PY="python3"
[ -x .venv/bin/python3 ] && PY=".venv/bin/python3"

PASS=0; FAIL=0
ok()  { echo "  [PASS] $1"; PASS=$((PASS+1)); }
bad() { echo "  [FAIL] $1"; FAIL=$((FAIL+1)); }

psql_q() { docker compose exec -T postgres psql -U northwind -d northwind -tAc "$1" 2>&1 < /dev/null; }

echo "=== 1. Extensions ==="
EXT="$(psql_q "select extname from pg_extension where extname in ('vector','pgcrypto') order by extname;")"
if [ "$EXT" = "$(printf 'pgcrypto\nvector')" ]; then
  ok "vector and pgcrypto both installed"
else
  bad "extensions mismatch, got: [$EXT]"
fi

echo
echo "=== 2. Tables ==="
WANT_TABLES="$(printf 'api_tokens\ncustomers\ndepartments\ndocument_shares\ndocuments\ngrants\ninvoices\npolicy_decisions\ntenants\ntickets\nusage_records\nusers')"
GOT_TABLES="$(psql_q "select table_name from information_schema.tables where table_schema='app' order by table_name;")"
if [ "$GOT_TABLES" = "$WANT_TABLES" ]; then
  ok "all 12 app.* tables exist"
else
  bad "table set mismatch, got: [$GOT_TABLES]"
fi

echo
echo "=== 3. Row counts match fixtures ==="
FIXTURE_COUNTS="$("$PY" - <<'PYEOF'
import yaml
from pathlib import Path
d = Path("corpus/entitlements")
for name in ("tenants", "departments", "users", "grants"):
    fixtures = yaml.safe_load((d / f"{name}.yaml").read_text())[name]
    print(f"{name} {len(fixtures)}")
PYEOF
)"
while read -r table count; do
  got="$(psql_q "select count(*) from app.${table};")"
  if [ "$got" = "$count" ]; then
    ok "app.${table}: $got rows (matches fixture)"
  else
    bad "app.${table}: $got rows, fixture has $count"
  fi
done <<< "$FIXTURE_COUNTS"

echo
echo "=== 4. Messy-case grants ==="
MARIA="$(psql_q "select expires_at is not null and expires_at > now() and revoked_at is null
                  from app.grants g join app.users u on u.id = g.user_id
                  where u.username = 'maria.support';")"
if [ "$MARIA" = "t" ]; then
  ok "maria.support: active time-boxed Engineering grant (future expires_at, not revoked)"
else
  bad "maria.support: expected an active future-expiring grant, got: $MARIA"
fi

OLIVIA="$(psql_q "select revoked_at is not null
                   from app.grants g join app.users u on u.id = g.user_id
                   where u.username = 'olivia.hr';")"
if [ "$OLIVIA" = "t" ]; then
  ok "olivia.hr: revoked grant present"
else
  bad "olivia.hr: expected a revoked grant, got: $OLIVIA"
fi

echo
echo "=== 5. Embeddings (milestone 6) ==="
EMB_COL="$(psql_q "select data_type from information_schema.columns
                    where table_schema='app' and table_name='documents' and column_name='embedding';")"
if [ "$EMB_COL" = "USER-DEFINED" ]; then
  ok "app.documents.embedding column exists"
else
  bad "app.documents.embedding column missing, got data_type: [$EMB_COL]"
fi

EMB_NULL="$(psql_q "select count(*) from app.documents where embedding is null;")"
if [ "$EMB_NULL" = "0" ]; then
  ok "every document has a non-null embedding"
else
  bad "$EMB_NULL document(s) missing an embedding -- run 'make embed-corpus'"
fi

EMB_IDX="$(psql_q "select count(*) from pg_indexes where schemaname='app' and tablename='documents' and indexname='documents_embedding_idx';")"
if [ "$EMB_IDX" = "1" ]; then
  ok "documents_embedding_idx (HNSW) exists"
else
  bad "documents_embedding_idx missing"
fi

echo
echo "=== 6. Records + generalized policy_decisions (milestone 8) ==="
REC_COUNTS="$(psql_q "select
    (select count(*) from app.customers) || ' ' ||
    (select count(*) from app.tickets) || ' ' ||
    (select count(*) from app.invoices) || ' ' ||
    (select count(*) from app.usage_records);")"
read -r N_CUST N_TICK N_INV N_USAGE <<< "$REC_COUNTS"
if [ "${N_CUST:-0}" -gt 0 ] && [ "${N_TICK:-0}" -gt 0 ] && [ "${N_INV:-0}" -gt 0 ] && [ "${N_USAGE:-0}" -gt 0 ]; then
  ok "records seeded: $N_CUST customers, $N_TICK tickets, $N_INV invoices, $N_USAGE usage rows"
else
  bad "records missing or empty (customers=$N_CUST tickets=$N_TICK invoices=$N_INV usage=$N_USAGE) -- run 'make seed-records'"
fi

PD_COLS="$(psql_q "select column_name from information_schema.columns
                    where table_schema='app' and table_name='policy_decisions'
                    and column_name in ('object_type','object_id') order by column_name;")"
if [ "$PD_COLS" = "$(printf 'object_id\nobject_type')" ]; then
  ok "app.policy_decisions generalized to object_type/object_id"
else
  bad "app.policy_decisions doesn't have the expected object_type/object_id columns, got: [$PD_COLS]"
fi

echo
echo "=== 7. Every seeded password verifies against its bcrypt hash ==="
if [ ! -f .seed-credentials.json ]; then
  bad ".seed-credentials.json missing -- run 'make seed' first"
else
  VALUES_SQL="$("$PY" - <<'PYEOF'
import json
creds = json.loads(open(".seed-credentials.json").read())
def esc(s): return s.replace("'", "''")
print(", ".join(f"('{esc(u)}', '{esc(p)}')" for u, p in creds.items()))
PYEOF
)"
  BAD_COUNT="$(psql_q "SELECT count(*) FROM app.users u
                        JOIN (VALUES $VALUES_SQL) AS c(username, plaintext) ON c.username = u.username
                        WHERE crypt(c.plaintext, u.password_hash) != u.password_hash;")"
  if [ "$BAD_COUNT" = "0" ]; then
    ok "all seeded passwords verify against their stored bcrypt hash"
  else
    bad "$BAD_COUNT user(s) whose stored hash doesn't match .seed-credentials.json"
  fi
fi

echo
echo "=== Result: $PASS passed, $FAIL failed ==="
[ "$FAIL" -eq 0 ] && echo "Schema and seed data verified." || echo "Fix the failures above."
exit $([ "$FAIL" -eq 0 ] && echo 0 || echo 1)
