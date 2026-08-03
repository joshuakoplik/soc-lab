"""harness/loader.py: parses corpus/attacks/*.yaml and corpus/benign/*.yaml
into harness.corpus_items (SPEC.md §13 milestone 11 / §9.5). Idempotent
upsert by (kind, item_key) -- unlike load_corpus.py's TRUNCATE-then-reload
(fine there, the real document corpus is fully replaced each time),
harness.results references corpus_items.id by foreign key and must not be
orphaned by a destructive reload when the maintainer adds or edits attack
content out of band.

A file under either directory may contain a single item (a YAML mapping) or
a list of items (a YAML sequence) -- see corpus/attacks/README.md for the
full item shape. schema.yaml (an annotated template, not a real item) is
skipped by name.
"""
import json
import os
import sys
from pathlib import Path

import psycopg2
import yaml

DATABASE_URL = os.environ.get(
    "DATABASE_URL", "postgresql://northwind:northwind-placeholder@postgres:5432/northwind"
)
CORPUS_ROOT = Path(os.environ.get("CORPUS_ROOT", "/app/corpus"))

CATEGORIES = {
    "direct_entitlement", "indirect_retrieval", "confused_deputy", "enumeration",
    "cross_tenant", "system_prompt_extraction", "stale_entitlement", "resource_abuse",
}
TARGET_TYPES = {"document", "customer_record", "ticket", "usage", "system_prompt", "none"}


def _iter_items(directory: Path):
    if not directory.is_dir():
        return
    for path in sorted(directory.rglob("*.yaml")):
        if path.name == "schema.yaml":
            continue
        loaded = yaml.safe_load(path.read_text())
        if loaded is None:
            continue
        items = loaded if isinstance(loaded, list) else [loaded]
        for item in items:
            yield path, item


def _validate(item: dict, kind: str, path: Path) -> None:
    item_id = item.get("id")
    if not isinstance(item_id, str) or not item_id:
        raise ValueError(f"{path}: item missing a non-empty string 'id'")

    if kind == "attack" and item.get("category") not in CATEGORIES:
        raise ValueError(f"{path}: item {item_id!r} has an invalid or missing category")

    actor = item.get("actor")
    if not isinstance(actor, dict) or not actor.get("tenant"):
        raise ValueError(f"{path}: item {item_id!r} missing actor.tenant")
    if not actor.get("username") and not actor.get("department"):
        raise ValueError(f"{path}: item {item_id!r} actor needs a department or an exact username")

    steps = item.get("steps")
    if not isinstance(steps, list) or not steps or not all(isinstance(s, dict) and s.get("message") for s in steps):
        raise ValueError(f"{path}: item {item_id!r} missing a non-empty 'steps' list of {{message: ...}}")

    target = item.get("target")
    if target is not None and (not isinstance(target, dict) or target.get("type") not in TARGET_TYPES):
        raise ValueError(f"{path}: item {item_id!r} has an invalid 'target'")

    expected = item.get("expected")
    if expected is not None and not isinstance(expected.get("refuse"), bool):
        raise ValueError(f"{path}: item {item_id!r} has an invalid 'expected.refuse'")


def load_all() -> dict[str, int]:
    conn = psycopg2.connect(DATABASE_URL)
    counts = {"attack": 0, "benign": 0}
    try:
        with conn.cursor() as cur:
            for kind, directory in (("attack", CORPUS_ROOT / "attacks"), ("benign", CORPUS_ROOT / "benign")):
                for path, item in _iter_items(directory):
                    _validate(item, kind, path)
                    cur.execute(
                        "INSERT INTO harness.corpus_items (kind, category, item_key, definition) "
                        "VALUES (%s, %s, %s, %s) "
                        "ON CONFLICT (kind, item_key) DO UPDATE SET "
                        "category = EXCLUDED.category, definition = EXCLUDED.definition",
                        (kind, item.get("category"), item["id"], json.dumps(item)),
                    )
                    counts[kind] += 1
        conn.commit()
    finally:
        conn.close()
    return counts


if __name__ == "__main__":
    try:
        result = load_all()
    except ValueError as e:
        sys.exit(f"loader: {e}")
    print(f"Loaded {result['attack']} attack item(s), {result['benign']} benign item(s).")
