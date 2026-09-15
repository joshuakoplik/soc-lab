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
