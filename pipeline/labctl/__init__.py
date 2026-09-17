"""Lab manager (`labctl`) -- the SOC lab's orchestration layer.

`labctl` is the one component allowed to know lab *meta*: which mode is up, which
agents/infra processes are running, whether an attack run just finished. It sets
up and tears down targets, NPC flocks, and the LLM agents; keeps the DB clean,
the dashboard connected, and telemetry flowing; and enforces token-conservation
policy (stop the idle hunter; stop the hunter once an attack run finishes) so the
individual components stay free of artificial cross-agent constraints.

Load-bearing invariant: labctl reads signals the agents ALREADY emit into soc.db
(hunt_sessions.status, redteam_sessions.status) and observes OS process state. It
changes NO agent internals -- the hunter never learns what an "attack run" is;
that lifecycle concern lives here instead.

Stdlib-only on purpose (like pipeline/ingest.py): the manager itself must run
without the venv. It *launches* the dashboard with the venv interpreter, but never
imports fastapi/uvicorn itself. It complements the existing scripts -- lab-mode.sh,
reset.sh, npcctl.py, reset_lab.py all keep working standalone; labctl calls them
via subprocess, it does not reimplement them.
"""
