"""Shared JSON-line telemetry writer (SPEC.md §10, milestone 12). Each
producer (portal-api, ingest-svc, retrieval-svc, policy/) writes to its own
file under the shared telemetry/ directory -- one writer per file, so no
cross-process locking is needed. The parent soc-lab pipeline's ingest.py
tails these exactly like it already tails cowrie/nginx/suricata/wazuh logs.

Best-effort: a write failure is swallowed, never raised. Telemetry must
never take the actual request path down -- unlike the parent pipeline's own
"never silently drop a line" principle, which is about not losing a line
that already made it into a log file, not about guaranteeing the write
itself always succeeds.
"""
import json
import os
from datetime import datetime, timezone

TELEMETRY_DIR = os.environ.get("TELEMETRY_DIR", "/app/telemetry")


def emit(log_name: str, event: dict) -> None:
    payload = {"ts": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"), **event}
    try:
        with open(os.path.join(TELEMETRY_DIR, f"{log_name}.log"), "a") as f:
            f.write(json.dumps(payload) + "\n")
    except OSError:
        pass
