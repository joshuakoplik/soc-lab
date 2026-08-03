"""harness/api.py: the harness's own operator-facing API (SPEC.md §2's
architecture diagram -- "operator -> harness, 127.0.0.1 only"). POST /runs
starts a run in a background thread (SPEC.md §9.1: "unattended") and
returns immediately with a run_id; GET /runs/{id} reports status and
summary stats once attempts have been scored; GET /runs/{id}/results
returns the raw per-attempt rows.
"""
import threading
from pathlib import Path

import psycopg2.extras
import yaml
from fastapi import FastAPI, HTTPException
from pydantic import BaseModel

import runner

CONFIGS_DIR = Path("/app/configs")

app = FastAPI()


class RunRequest(BaseModel):
    model: str
    controls: str          # filename under configs/, e.g. "baseline.yaml"
    corpus_version: str


@app.get("/health")
def health():
    return {"status": "ok"}


@app.post("/runs")
def post_runs(body: RunRequest):
    controls_path = CONFIGS_DIR / body.controls
    if not controls_path.is_file():
        raise HTTPException(status_code=400, detail=f"unknown controls config: {body.controls}")

    # Create the run row synchronously (fast) so the caller gets a real
    # run_id back immediately; the attempt loop itself runs in the
    # background thread below -- SPEC.md §9.1's "unattended."
    controls_payload = yaml.safe_load(controls_path.read_text()) or {}
    conn = runner.db()
    try:
        runner.reset_app_state(conn)
        runner.reset_controls()
        runner.put_controls(controls_payload)
        resolved = runner.get_controls()
        run_id = runner.create_run(conn, body.model, body.controls, resolved, body.corpus_version)
    finally:
        conn.close()

    def _background():
        runner.execute_run(body.model, str(controls_path), body.corpus_version, resume_run_id=run_id)

    threading.Thread(target=_background, daemon=True).start()
    return {"run_id": run_id}


@app.get("/runs/{run_id}")
def get_run(run_id: int):
    conn = runner.db()
    try:
        with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
            cur.execute("SELECT * FROM harness.runs WHERE id = %s", (run_id,))
            run = cur.fetchone()
            if not run:
                raise HTTPException(status_code=404, detail="unknown run")
            cur.execute(
                "SELECT count(*) AS attempted, "
                "count(*) FILTER (WHERE leaked) AS leaked, "
                "count(*) FILTER (WHERE over_refusal) AS over_refusals "
                "FROM harness.results WHERE run_id = %s",
                (run_id,),
            )
            stats = cur.fetchone()
    finally:
        conn.close()
    status = "finished" if run["finished_at"] else "in_progress"
    return {**run, "status": status, **stats}


@app.get("/runs/{run_id}/results")
def get_run_results(run_id: int):
    conn = runner.db()
    try:
        with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
            cur.execute(
                "SELECT r.*, c.kind, c.category, c.item_key FROM harness.results r "
                "JOIN harness.corpus_items c ON c.id = r.corpus_item_id "
                "WHERE r.run_id = %s ORDER BY r.id",
                (run_id,),
            )
            rows = [dict(row) for row in cur.fetchall()]
    finally:
        conn.close()
    return {"run_id": run_id, "results": rows}
