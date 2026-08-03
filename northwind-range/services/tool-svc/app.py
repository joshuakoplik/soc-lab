"""tool-svc: the four SPEC.md §8 tools, and the ENT_TOOL confused-deputy
seam (milestone 8).

doc_search is a thin passthrough to retrieval-svc -- its correctness rides
entirely on retrieval-svc's own pre-filter guarantee (milestone 6), and
there's no "service credential" mode that would make sense for semantic
search the way there is for a records lookup by ID. The other three tools
each resolve the record's tenant and, when ent_tool=True, call
policy.decide_record() before returning anything; when ent_tool=False they
skip that check entirely -- the "service credential can see everything"
mode SPEC.md §8 describes. That's the whole point of this service: the
same tool call, same arguments, produces a real cross-tenant PII leak or a
clean denial depending on nothing but that one flag.
"""
import json
import os
import urllib.request

import psycopg2
import psycopg2.extras
from fastapi import FastAPI, HTTPException
from pydantic import BaseModel

from policy import policy

DATABASE_URL = os.environ.get(
    "DATABASE_URL", "postgresql://northwind:northwind-placeholder@postgres:5432/northwind"
)
RETRIEVAL_SVC_URL = os.environ.get("RETRIEVAL_SVC_URL", "http://retrieval-svc:8000")

app = FastAPI()


def db():
    return psycopg2.connect(DATABASE_URL)


class InvokeRequest(BaseModel):
    tool: str
    args: dict
    user_id: int
    ent_tool: bool = True


def _doc_search(args: dict, user_id: int, ent_tool: bool) -> dict:
    body = json.dumps({
        "user_id": user_id, "query": args["query"], "k": args.get("k", 5), "mode": "prefilter",
    }).encode()
    req = urllib.request.Request(
        f"{RETRIEVAL_SVC_URL}/search", data=body, headers={"Content-Type": "application/json"}
    )
    with urllib.request.urlopen(req, timeout=60) as resp:
        return json.loads(resp.read())


def _ticket_lookup(args: dict, user_id: int, ent_tool: bool) -> dict:
    ticket_id = args["ticket_id"]
    conn = db()
    try:
        with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
            cur.execute(
                "SELECT id, customer_id, subject, body, status, created_at, closed_at "
                "FROM app.tickets WHERE id = %s",
                (ticket_id,),
            )
            row = cur.fetchone()
            if not row:
                raise HTTPException(status_code=404, detail="unknown ticket")

            if ent_tool:
                decision = policy.decide_record(user_id, "tickets", ticket_id, "read", conn=conn)
                if not decision.allowed:
                    raise HTTPException(status_code=403, detail=decision.reason)

            return dict(row)
    finally:
        conn.close()


def _customer_record(args: dict, user_id: int, ent_tool: bool) -> dict:
    customer_id = args["customer_id"]
    conn = db()
    try:
        with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
            cur.execute(
                "SELECT id, name, email, phone, plan, created_at FROM app.customers WHERE id = %s",
                (customer_id,),
            )
            row = cur.fetchone()
            if not row:
                raise HTTPException(status_code=404, detail="unknown customer")

            if ent_tool:
                decision = policy.decide_record(user_id, "customers", customer_id, "read", conn=conn)
                if not decision.allowed:
                    raise HTTPException(status_code=403, detail=decision.reason)

            return dict(row)
    finally:
        conn.close()


USAGE_OPS = {
    "sum": "SUM(value)",
    "average": "AVG(value)",
    "max": "MAX(value)",
    "min": "MIN(value)",
}


def _usage_calc(args: dict, user_id: int, ent_tool: bool) -> dict:
    customer_id = args["customer_id"]
    metric = args["metric"]
    op = args.get("op", "sum")
    if op not in USAGE_OPS:
        raise HTTPException(status_code=400, detail=f"op must be one of {sorted(USAGE_OPS)}")

    conn = db()
    try:
        with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
            cur.execute("SELECT id FROM app.customers WHERE id = %s", (customer_id,))
            if not cur.fetchone():
                raise HTTPException(status_code=404, detail="unknown customer")

            if ent_tool:
                decision = policy.decide_record(user_id, "customers", customer_id, "read", conn=conn)
                if not decision.allowed:
                    raise HTTPException(status_code=403, detail=decision.reason)

            cur.execute(
                f"SELECT {USAGE_OPS[op]} AS result FROM app.usage_records "
                "WHERE customer_id = %s AND metric = %s",
                (customer_id, metric),
            )
            row = cur.fetchone()
            result = float(row["result"]) if row and row["result"] is not None else None
            return {"customer_id": customer_id, "metric": metric, "op": op, "result": result}
    finally:
        conn.close()


TOOLS = {
    "doc_search": {"tier": "low", "handler": _doc_search},
    "ticket_lookup": {"tier": "low", "handler": _ticket_lookup},
    "customer_record": {"tier": "high", "handler": _customer_record},
    "usage_calc": {"tier": "low", "handler": _usage_calc},
}


@app.get("/health")
def health():
    return {"status": "ok"}


@app.post("/invoke")
def invoke(body: InvokeRequest):
    tool = TOOLS.get(body.tool)
    if tool is None:
        raise HTTPException(status_code=400, detail=f"unknown tool: {body.tool}")
    result = tool["handler"](body.args, body.user_id, body.ent_tool)
    return {"tool": body.tool, "tier": tool["tier"], "result": result}
