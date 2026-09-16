# dashboard -- read-only live view over soc.db

A small server that polls `soc.db`, diffs against the highest row id seen per
table, and pushes new rows to connected browsers over a WebSocket. A REST
endpoint serves recent history so a freshly-opened tab isn't staring at a blank
page. WAL mode makes polling safe alongside the ingest/triage/red-team writers.

```bash
python3 dashboard/server.py     # http://127.0.0.1:8095
```

It opens the database with `mode=ro` in the connection URI, so it is
*physically* incapable of writing to the lab's data no matter what a bug here
might attempt. That is the whole design: an observability layer that cannot
become another writer.

Binds loopback by default, deliberately — this lab runs intentionally
vulnerable services and nothing here should become reachable off-host by
accident. Override via `SOC_DASHBOARD_HOST` / `SOC_DASHBOARD_PORT` /
`SOC_DASHBOARD_DB` / `SOC_DASHBOARD_POLL_INTERVAL` in the repo-root `.env`. To
reach it from another of your machines, bind one specific private-interface
address (a WireGuard/Tailscale IP), never `0.0.0.0`.

## The Analyst tab (a deliberate exception to "read-only")

The **Analyst** tab is an interactive chat an on-call analyst drives — "what's
going on?", then digging in. It is the one part of this server that *writes*.
The design above still holds: the **poll loop keeps its `mode=ro` connection**
and can never write. The chat is a separate concern (`dashboard/chat.py`,
mounted at `/api/chat/*`) that opens its **own** read-write connection — one per
turn, inside the worker thread that runs the blocking provider call — pointed at
the same `SOC_DASHBOARD_DB` the poller reads. Two connections, two privilege
levels, one process.

Streaming is free: the agent logs each step of a turn (your message, each tool
call + result, the final reply) as `chat_turns` rows, and those stream to the
browser over the **same** WebSocket as every other table. Posting a message
returns immediately; the reply arrives over the feed.

Config (repo-root `.env`):

- `SOC_ANALYST_PROVIDER` / `SOC_ANALYST_MODEL` — which model answers (defaults to
  the analyst agent's built-in default; set e.g. `gmi` / `moonshotai/kimi-k3`).
- `SOC_ANALYST_MAX_ITERATIONS` — tool-call budget per turn.
- `SOC_ANALYST_EGRESS` — **off by default.** When truthy, enables the external
  enrichment tools (DNS/reverse-DNS/RDAP-whois/traceroute/HTTP-headers/web-search).
  These reach off-host — the only outbound path in this otherwise egress-locked
  lab — and are guarded by an SSRF check (public targets only) plus
  `<untrusted-evidence>` fencing of their results. Leave it off unless you want
  live external lookups.

The same agent is also runnable head-less from the CLI:
`python3 pipeline/analyst/agent.py --sitrep` (see `pipeline/analyst/agent.py`).

## The Lab tab (drive lab state from the browser)

The **Lab** tab is the UI for the lab manager (`pipeline/labctl`). It shows lab
state — current mode/posture, which agents and infra are running, the standing
hunt and any active attack runs, supervisor policy — and lets you drive it: switch
modes, start/stop the hunter/attacker/ingest/dashboard, spin NPC flocks up/down,
start/stop the supervisor `watch` loop and toggle its policies/timers, and run
resets.

Pickers where names are unfamiliar:
- **Dealer target** opens a modal listing the Vulhub catalog from the local cache
  with per-entry metadata (software/CVE + a description parsed from the entry's
  README); if the cache isn't cloned yet the modal offers a one-click fetch
  (shallow `git clone`) and a few well-known suggestions. You can also type any
  `software/CVE` or image ref.
- **NPC flock** template and live-flock names are dropdowns (from
  `npc-range/templates/` and the live `.run/` flocks).
- **Hunter** and **attacker** launch via a modal to pick provider/model and set
  their budget/iteration params (and, for the hunter, the supervisor's
  idle-timeout / attack-drain knobs). The **model** is a provider-aware dropdown
  backed by a persisted catalog (`.labctl/models.json`): claude and local are
  queried live (Anthropic `/v1/models`, ollama `/api/tags` — so `local` shows
  what's actually pulled, never a made-up tag); gmi/fireworks fall back to a
  maintained seed because their list endpoints reject our key. The supervisor
  refreshes the catalog on a long interval (`models_refresh_interval`, models
  rarely change), there's a ↻ button in the modal to force a re-query, and a
  "custom…" option reaches anything not listed.

Same architecture exception as the Analyst tab, but simpler: the router
(`dashboard/labctl_control.py`, mounted at `/api/lab/*`) does **not** write
`soc.db` at all — it imports `pipeline.labctl` and runs the *same* code path
`./labctl` uses, executing the existing scripts (`lab-mode.sh` / `reset.sh` /
`npc-range` Makefile) as subprocesses. The poll loop keeps its `mode=ro`
connection. Actions run in a worker thread under a single global lock (a second
concurrent action → 409). The tab does **not** auto-refresh (that fights with
typing and clicking): status loads on tab-open, after each action, and via the
Refresh button — and it fetches `?docker=false`, so `docker compose ps` never
runs on a timer. Live agent state (hunt/redteam sessions) still streams over the
existing WebSocket.

Powerful by nature (it can start the attacker or wipe the DB), so keep the server
loopback-only (the default `SOC_DASHBOARD_HOST=127.0.0.1`). A destructive reset
(`--db`/`--all`) requires an explicit confirm — a browser dialog **and** a
server-side `confirm=true` (a 409 otherwise). Every action is appended to
`.labctl/logs/actions.log`.
