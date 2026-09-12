# dealer-range — "dealer's choice" ephemeral targets

A `dealer` lab mode that stands up a **docker-based vulnerable target sourced
from [Vulhub](https://github.com/vulhub/vulhub)** (the docker analog of VulnHub;
VulnHub's own VM images can't run on this host — no virtualization), attacks it,
and tears it down clean on the next mode switch — "like it was never there."

The target is chosen **by argument**, not by an in-code discovery/random engine
(that judgment is the operator's/assistant's — ask Claude to pick one):

```bash
../lab-mode.sh up dealer struts2/CVE-2017-5638     # a Vulhub <software>/<CVE> path
../lab-mode.sh up dealer vulnerables/web-dvwa      # or a plain docker image ref
../lab-mode.sh switch dealer <target>              # exclusive; tears down other modes
../lab-mode.sh down dealer                         # remove it, wipe .run/
../lab-mode.sh status                              # shows what's up + the current target
```

## What happens

1. `make cache` shallow-clones Vulhub into `.cache/vulhub/` (once; `make refresh`
   to update). This is the only network step; picking a target is out-of-band.
2. `up.py <target>` resolves the target to a docker-compose, then **rewrites** it
   into `.run/compose.yml`: strips all host `ports:`, puts every service on the
   internal `soclab-dealer` bridge, and aliases the externally-facing service as
   **`target`** so `soc-attacker` reaches it as `target.soclab-dealer`.
3. `docker compose -p dealer-range up -d --build` brings it up; `make wait`
   health-gates it (fail loud → pick another).
4. `make wire` (`wire.py`) makes the healthy target **observable to the
   defender** — see below. Best-effort: a wiring hiccup never fails `up`.

## Containment

`soclab-dealer` is an **internal** bridge (`pipeline/net_topology.py`), so the
untrusted, live-fetched target has **no route off-host** — structural, zero
iptables. It publishes no host ports. Inter-service DNS (app→db) still works on
the bridge; `soc-attacker` (multi-homed onto it) reaches `target`.

## Making the target observable (`wire.py`)

A Vulhub container has no wazuh agent and logs to unknown places/formats, and it
joins `soclab-dealer` *after* Suricata discovered its interfaces — so out of the
box the defender is blind on both legs. `make wire` (run automatically at the end
of `make up`) fixes both:

- **Network (Suricata)** — deterministic, no model. Suricata self-discovers
  `soclab-*0` bridges only at entrypoint, so a later bridge is missed. If
  `soc-suricata` isn't already capturing `soclab-dealer0`, `wire.py` restarts it
  to re-run discovery. `HOME_NET` (`/16`) already covers `10.211.40.0/24`, so no
  config edit.
- **Logs (Wazuh)** — a deterministic baseline plus one LLM refinement turn.
  Wazuh reads only real files under `/lab-logs` and copies `ossec.conf` only at
  boot (no live reload), so two **permanent** dealer buckets live in
  `wazuh/ossec.conf` — `/lab-logs/dealer/dealer.log` (`syslog`: plain text + HTTP
  access logs, which get the `web_accesslog` decoder / 31100 web ruleset for
  free) and `/lab-logs/dealer/dealer.json` (`json`). All per-image work is then
  host-side: `wire.py` tails each service's stdout into the syslog bucket
  (baseline — never blind even if the model turn fails), then runs **one LLM turn**
  (`WIRE_PROVIDER`, default `local`/qwen; `WIRE_MODEL`) that, additively,
  re-routes a JSON-on-stdout service to the json bucket and exec-tails
  in-container log files the app writes to disk. Every model-proposed entry is
  validated; bad ones are dropped. Wazuh's logcollector tolerates the
  not-yet-existing bucket paths and picks them up once the tailers create them.

Spawned tailers are detached and recorded in `.run/tailers.json`; `make down`
kills them and clears `logs/dealer/` so a target stays ephemeral. The permanent
ossec.conf buckets remain, harmlessly pointing at absent files.

> **One-time setup:** the two dealer `<localfile>` stanzas were added to
> `wazuh/ossec.conf` — since Wazuh copies its config in only at boot, run
> `docker restart soc-wazuh` once to activate them. After that, no dealer target
> ever needs a Wazuh restart.
>
> An alert still only fires if a shipped decoder/rule matches the target's log
> format (access logs are the rich case) — the plumbing is format-agnostic, the
> detection content is not. And the defender pipeline (`ingest.py`/`detect`/
> `triage`) must be running for the telemetry to reach `soc.db`; `wire.py` only
> guarantees the sensors *produce* it.

## The agent's view

The red-team agent is told only that it has a target named `target` — it must
recon from zero (dealer's choice). What the target actually is lives in
`.run/state.json`, for the operator only. Success is a foothold/RCE
(`state_footholds`/`wins`), not a captured flag — Vulhub envs aren't CTF boxes.

Not committed: `.cache/`, `.run/`, `.env` (see `.gitignore`).
