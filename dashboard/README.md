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
