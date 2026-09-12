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

## Containment

`soclab-dealer` is an **internal** bridge (`pipeline/net_topology.py`), so the
untrusted, live-fetched target has **no route off-host** — structural, zero
iptables. It publishes no host ports. Inter-service DNS (app→db) still works on
the bridge; `soc-attacker` (multi-homed onto it) reaches `target`.

## Telemetry note

A Vulhub container has no wazuh agent or log bind-mount, so the **defender's
only visibility is Suricata network IDS** on `soclab-dealer` (its `/16`
`HOME_NET` already covers the subnet). `dealer` is a rich red-team-variety play
but a thin blue-team one.

## The agent's view

The red-team agent is told only that it has a target named `target` — it must
recon from zero (dealer's choice). What the target actually is lives in
`.run/state.json`, for the operator only. Success is a foothold/RCE
(`state_footholds`/`wins`), not a captured flag — Vulhub envs aren't CTF boxes.

Not committed: `.cache/`, `.run/`, `.env` (see `.gitignore`).
