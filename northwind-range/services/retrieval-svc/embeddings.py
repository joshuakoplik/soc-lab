"""Shared embedding helper -- used by both the live /search endpoint and
backfill_embeddings.py, so there's one embedding call-path, not two.

Goes through llm-backend's existing narrow-egress proxy (SPEC.md §4.1) --
nginx's proxy_pass forwards any path to the configured upstream, so
/api/embed works exactly like /api/generate already does. No changes to
llm-backend, nw_llm_egress, or its iptables allow-list.
"""
import json
import os
import urllib.request

LLM_BACKEND_URL = os.environ.get("LLM_BACKEND_URL", "http://llm-backend:11434")
EMBED_MODEL = os.environ.get("EMBED_MODEL", "embeddinggemma")


def embed(text: str) -> list[float]:
    body = json.dumps({"model": EMBED_MODEL, "input": text}).encode()
    req = urllib.request.Request(
        f"{LLM_BACKEND_URL}/api/embed", data=body, headers={"Content-Type": "application/json"}
    )
    with urllib.request.urlopen(req, timeout=60) as resp:
        result = json.loads(resp.read())
    return result["embeddings"][0]


def as_vector_literal(vec: list[float]) -> str:
    """pgvector's text input format -- pass this with an explicit ::vector
    cast in SQL. psycopg2's default list adapter produces a Postgres
    ARRAY[...], not a vector literal; register_vector's auto-adaptation
    doesn't reliably override that for plain Python lists, so this is
    explicit rather than relying on it."""
    return "[" + ",".join(repr(float(x)) for x in vec) + "]"
