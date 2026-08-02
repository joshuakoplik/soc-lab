#!/usr/bin/env python3
"""Load corpus/docs/**/*.md into app.documents/app.document_shares
(SPEC.md §13 milestone 3). Companion to scripts/seed_entitlements.py --
same docker-compose-exec-through-internal-network approach, same
TRUNCATE-then-reload idempotency.
"""
import subprocess
import sys
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parent.parent
DOCS_DIR = ROOT / "corpus" / "docs"


def sql_str(value: str) -> str:
    return "'" + value.replace("'", "''") + "'"


def sql_bool(value: bool) -> str:
    return "true" if value else "false"


def parse_doc(path: Path) -> dict:
    text = path.read_text()
    if not text.startswith("---\n"):
        sys.exit(f"load_corpus: {path} missing frontmatter")
    _, frontmatter_raw, body = text.split("---\n", 2)
    meta = yaml.safe_load(frontmatter_raw)
    meta["content"] = body.strip()
    meta["source"] = str(path.relative_to(ROOT))
    return meta


def build_sql(docs: list[dict]) -> str:
    lines = [
        "BEGIN;",
        "TRUNCATE app.document_shares, app.documents RESTART IDENTITY CASCADE;",
    ]
    for doc in docs:
        lines.append(
            "WITH ins AS ("
            "INSERT INTO app.documents (tenant_id, label, owning_department_id, title, source, content) "
            f"SELECT t.id, {sql_str(doc['label'])}, d.id, {sql_str(doc['title'])}, "
            f"{sql_str(doc['source'])}, {sql_str(doc['content'])} "
            f"FROM app.tenants t, app.departments d "
            f"WHERE t.slug = {sql_str(doc['tenant'])} AND d.name = {sql_str(doc['department'])} "
            "RETURNING id) "
            + (
                " ".join(
                    f"INSERT INTO app.document_shares (document_id, department_id) "
                    f"SELECT ins.id, dep.id FROM ins, app.departments dep "
                    f"WHERE dep.name = {sql_str(share)};"
                    for share in doc.get("shares") or []
                )
                if doc.get("shares") else "SELECT 1 FROM ins;"
            )
        )
    lines.append("COMMIT;")
    return "\n".join(lines)


def main() -> None:
    paths = sorted(DOCS_DIR.glob("*/*.md"))
    if not paths:
        sys.exit(f"load_corpus: no documents found under {DOCS_DIR}")
    docs = [parse_doc(p) for p in paths]

    sql = build_sql(docs)
    result = subprocess.run(
        ["docker", "compose", "exec", "-T", "postgres", "psql", "-v", "ON_ERROR_STOP=1",
         "-U", "northwind", "-d", "northwind"],
        input=sql, capture_output=True, text=True, cwd=str(ROOT),
    )
    if result.returncode != 0:
        sys.exit(f"load_corpus: psql failed:\n{result.stdout}\n{result.stderr}")

    print(f"Loaded {len(docs)} documents.")


if __name__ == "__main__":
    main()
