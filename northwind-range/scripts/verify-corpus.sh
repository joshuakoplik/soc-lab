#!/usr/bin/env bash
# Standing check for the generated document corpus (SPEC.md §13 milestone 3).
set -uo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")/.."

PY="python3"
[ -x .venv/bin/python3 ] && PY=".venv/bin/python3"

PASS=0; FAIL=0
ok()  { echo "  [PASS] $1"; PASS=$((PASS+1)); }
bad() { echo "  [FAIL] $1"; FAIL=$((FAIL+1)); }

psql_q() { docker compose exec -T postgres psql -U northwind -d northwind -tAc "$1" 2>&1 < /dev/null; }

echo "=== 1. File-level checks (manifest, frontmatter, messy cases, pii/credential counts) ==="
"$PY" - <<'PYEOF'
import sys
import yaml
from pathlib import Path

manifest = yaml.safe_load(open("corpus/docs_manifest.yaml"))["documents"]
docs_dir = Path("corpus/docs")
valid_labels = {"public", "internal", "confidential", "restricted"}
tenants = {"riverside", "bluepeak", "fenwick"}
departments = {"Support", "Engineering", "HR", "Finance", "Admin"}

fail = False

files = sorted(docs_dir.glob("*/*.md"))
n = len(files)
if 150 <= n <= 300:
    print(f"  [PASS] {n} documents (in 150-300 range)")
else:
    print(f"  [FAIL] {n} documents (want 150-300)")
    fail = True

missing = [r["slug"] for r in manifest if not (docs_dir / r["tenant"] / f"{r['slug']}.md").exists()]
if not missing:
    print(f"  [PASS] every manifest row ({len(manifest)}) has a file")
else:
    print(f"  [FAIL] {len(missing)} manifest rows missing a file, e.g. {missing[:5]}")
    fail = True

bad_frontmatter = []
pii_count = cred_count = 0
share_doc = mislabel_doc = None
for path in files:
    text = path.read_text()
    if not text.startswith("---\n"):
        bad_frontmatter.append((path, "no frontmatter"))
        continue
    _, fm_raw, body = text.split("---\n", 2)
    meta = yaml.safe_load(fm_raw)
    if meta.get("tenant") not in tenants:
        bad_frontmatter.append((path, f"bad tenant {meta.get('tenant')!r}"))
    if meta.get("department") not in departments:
        bad_frontmatter.append((path, f"bad department {meta.get('department')!r}"))
    if meta.get("label") not in valid_labels:
        bad_frontmatter.append((path, f"bad label {meta.get('label')!r}"))
    if not body.strip():
        bad_frontmatter.append((path, "empty body"))
    if meta.get("contains_pii"):
        pii_count += 1
    if meta.get("contains_credential"):
        cred_count += 1
    if meta.get("shares"):
        share_doc = (path, meta)
    if meta.get("tenant") == "bluepeak" and "competitive-technical-analysis" in path.stem:
        mislabel_doc = (path, meta, body)

if not bad_frontmatter:
    print(f"  [PASS] all {len(files)} files have valid frontmatter (tenant/department/label) and non-empty body")
else:
    print(f"  [FAIL] {len(bad_frontmatter)} files with bad frontmatter, e.g. {bad_frontmatter[:3]}")
    fail = True

if pii_count >= 10:
    print(f"  [PASS] {pii_count} documents flagged contains_pii")
else:
    print(f"  [FAIL] only {pii_count} documents flagged contains_pii (want >= 10)")
    fail = True

if cred_count >= 10:
    print(f"  [PASS] {cred_count} documents flagged contains_credential")
else:
    print(f"  [FAIL] only {cred_count} documents flagged contains_credential (want >= 10)")
    fail = True

if share_doc and share_doc[1].get("tenant") == "riverside" and share_doc[1].get("department") == "HR" \
        and "Finance" in share_doc[1].get("shares", []):
    print(f"  [PASS] HR-shared-with-Finance messy case present: {share_doc[0].name}")
else:
    print(f"  [FAIL] HR-shared-with-Finance messy case missing or wrong shape: {share_doc}")
    fail = True

if mislabel_doc and mislabel_doc[1].get("label") == "internal":
    print(f"  [PASS] internal-labeled mislabeling messy case present: {mislabel_doc[0].name}")
else:
    print(f"  [FAIL] internal-quotes-restricted messy case missing or wrong label: {mislabel_doc}")
    fail = True

sys.exit(1 if fail else 0)
PYEOF
if [ $? -eq 0 ]; then ok "file-level checks"; else bad "file-level checks (see [FAIL] lines above)"; fi

echo
echo "=== 2. DB load matches files ==="
FILE_COUNT="$(find corpus/docs -name '*.md' | wc -l | tr -d ' ')"
DB_COUNT="$(psql_q "select count(*) from app.documents;")"
if [ "$FILE_COUNT" = "$DB_COUNT" ]; then
  ok "app.documents row count ($DB_COUNT) matches file count"
else
  bad "app.documents has $DB_COUNT rows, $FILE_COUNT files on disk -- run 'make load-corpus'"
fi

ORPHAN_SHARES="$(psql_q "select count(*) from app.document_shares s
                          left join app.documents d on d.id = s.document_id
                          left join app.departments p on p.id = s.department_id
                          where d.id is null or p.id is null;")"
if [ "$ORPHAN_SHARES" = "0" ]; then
  ok "every app.document_shares row resolves to a real document and department"
else
  bad "$ORPHAN_SHARES orphaned document_shares rows"
fi

echo
echo "=== Result: $PASS passed, $FAIL failed ==="
[ "$FAIL" -eq 0 ] && echo "Corpus verified." || echo "Fix the failures above."
exit $([ "$FAIL" -eq 0 ] && echo 0 || echo 1)
