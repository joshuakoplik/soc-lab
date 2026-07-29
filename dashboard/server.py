"""
Real-time observability layer over soc.db -- read-only, changes nothing.

Polls the lab's SQLite DB on a timer (WAL mode makes this safe alongside the
ingest/triage/redteam writers), diffs against the highest id seen per table,
and fan-outs new rows to connected browsers over a WebSocket. A REST endpoint
serves recent history so a freshly-opened tab isn't staring at an empty page.

This process opens soc.db with `mode=ro` in the connection URI -- it is
physically incapable of writing to the lab's data, regardless of what a bug
here might otherwise attempt.

Run: python3 dashboard/server.py  (serves http://127.0.0.1:8090 by default)
Override with SOC_DASHBOARD_HOST / SOC_DASHBOARD_PORT / SOC_DASHBOARD_DB /
SOC_DASHBOARD_POLL_INTERVAL env vars -- e.g. bind to a Tailscale address so
other devices on the tailnet can reach it:
    SOC_DASHBOARD_HOST=$(tailscale ip -4) python3 dashboard/server.py
"""
import asyncio
import json
import os
import sqlite3
from pathlib import Path

from contextlib import asynccontextmanager

from fastapi import FastAPI, WebSocket, WebSocketDisconnect
from fastapi.responses import HTMLResponse
from fastapi.staticfiles import StaticFiles

DB_PATH = Path(os.environ.get("SOC_DASHBOARD_DB", Path(__file__).resolve().parent.parent / "soc.db"))
STATIC_DIR = Path(__file__).resolve().parent / "static"
POLL_INTERVAL_S = float(os.environ.get("SOC_DASHBOARD_POLL_INTERVAL", "1.5"))
PORT = int(os.environ.get("SOC_DASHBOARD_PORT", "8090"))
HOST = os.environ.get("SOC_DASHBOARD_HOST", "127.0.0.1")

# table -> (message type tag, how many rows to hand a freshly-connected client)
TABLES = {
    "events":                ("event",                300),
    "candidates":            ("candidate",             150),
    "triage":                ("triage",                150),
    "agent_alerts":          ("alert",                 100),
    "block_recommendations": ("block_recommendation",  100),
    "block_ip_calls":        ("block_ip_call",         100),
    "human_pages":           ("human_page",            100),
    "redteam_sessions":      ("redteam_session",        60),
    "recon_findings":        ("recon_finding",         300),
    "vuln_findings":         ("vuln_finding",          150),
    "pending_actions":       ("pending_action",        150),
    "loot":                  ("loot",                  150),
    "captured_flags":        ("captured_flag",          60),
}

# These three get UPDATEd in place after insert (candidates.status flips
# new->triaged; redteam_sessions.stage/status advances recon->assess->done;
# pending_actions.approved/executed/result_json fill in later) -- an
# id-cursor alone would miss those transitions. Diff a full snapshot instead.
# The rest are insert-only per their own schema docstrings, so a cheap
# id-cursor is correct for them.
MUTABLE_TABLES = {"candidates", "redteam_sessions", "pending_actions"}


def connect_ro() -> sqlite3.Connection:
    conn = sqlite3.connect(f"file:{DB_PATH}?mode=ro", uri=True, check_same_thread=False)
    conn.row_factory = sqlite3.Row
    return conn


class Broadcaster:
    def __init__(self):
        self.clients: set[WebSocket] = set()
        self.lock = asyncio.Lock()

    async def register(self, ws: WebSocket):
        async with self.lock:
            self.clients.add(ws)

    async def unregister(self, ws: WebSocket):
        async with self.lock:
            self.clients.discard(ws)

    async def send(self, message: dict):
        payload = json.dumps(message, default=str)
        async with self.lock:
            dead = []
            for ws in self.clients:
                try:
                    await ws.send_text(payload)
                except Exception:
                    dead.append(ws)
            for ws in dead:
                self.clients.discard(ws)


broadcaster = Broadcaster()


@asynccontextmanager
async def lifespan(_app: FastAPI):
    task = asyncio.create_task(poll_loop())
    yield
    task.cancel()


app = FastAPI(lifespan=lifespan)


def fetch_bootstrap() -> dict:
    conn = connect_ro()
    try:
        out = {}
        for table, (tag, limit) in TABLES.items():
            rows = conn.execute(
                f"SELECT * FROM {table} ORDER BY id DESC LIMIT ?", (limit,)
            ).fetchall()
            out[table] = {"tag": tag, "rows": [dict(r) for r in reversed(rows)]}
        return out
    finally:
        conn.close()


async def poll_loop():
    conn = connect_ro()
    append_only = [t for t in TABLES if t not in MUTABLE_TABLES]
    mutable = [t for t in TABLES if t in MUTABLE_TABLES]

    # Start from "now" -- only stream rows/changes from after this process
    # came up. History is served separately via /api/bootstrap.
    last_id = {}
    for table in append_only:
        row = conn.execute(f"SELECT COALESCE(MAX(id), 0) AS m FROM {table}").fetchone()
        last_id[table] = row["m"]

    snapshots = {}
    for table in mutable:
        rows = conn.execute(f"SELECT * FROM {table}").fetchall()
        snapshots[table] = {r["id"]: dict(r) for r in rows}

    while True:
        try:
            for table in append_only:
                tag = TABLES[table][0]
                rows = conn.execute(
                    f"SELECT * FROM {table} WHERE id > ? ORDER BY id ASC",
                    (last_id[table],),
                ).fetchall()
                for r in rows:
                    last_id[table] = max(last_id[table], r["id"])
                    await broadcaster.send({"table": table, "tag": tag, "row": dict(r)})

            for table in mutable:
                tag = TABLES[table][0]
                prev = snapshots[table]
                cur = {}
                rows = conn.execute(f"SELECT * FROM {table}").fetchall()
                for r in rows:
                    d = dict(r)
                    cur[d["id"]] = d
                    if prev.get(d["id"]) != d:
                        await broadcaster.send({"table": table, "tag": tag, "row": d})
                snapshots[table] = cur
        except Exception as exc:  # keep polling even if one cycle hiccups
            await broadcaster.send({"table": "_error", "tag": "error", "row": {"detail": str(exc)}})
        await asyncio.sleep(POLL_INTERVAL_S)


@app.get("/api/bootstrap")
async def bootstrap():
    return await asyncio.to_thread(fetch_bootstrap)


@app.websocket("/ws")
async def ws_endpoint(ws: WebSocket):
    await ws.accept()
    await broadcaster.register(ws)
    try:
        while True:
            # Client never needs to send anything; just keep the socket open.
            await ws.receive_text()
    except WebSocketDisconnect:
        pass
    finally:
        await broadcaster.unregister(ws)


@app.get("/")
async def index():
    # Plain FileResponse left style.css/app.js on flat /static/... URLs with
    # no cache-busting -- across a run of edits to this dashboard, browsers
    # kept serving a stale mix of old CSS with new HTML (or vice versa) on a
    # normal reload. Stamp each asset URL with its own mtime so any edit
    # forces a fresh fetch of exactly that file.
    html = (STATIC_DIR / "index.html").read_text()
    for asset in ("style.css", "app.js"):
        mtime = int((STATIC_DIR / asset).stat().st_mtime)
        html = html.replace(f"/static/{asset}", f"/static/{asset}?v={mtime}")
    return HTMLResponse(html)


app.mount("/static", StaticFiles(directory=STATIC_DIR), name="static")


if __name__ == "__main__":
    import uvicorn

    uvicorn.run(app, host=HOST, port=PORT)
