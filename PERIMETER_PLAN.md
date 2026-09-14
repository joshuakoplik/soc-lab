# PERIMETER_PLAN — build plan for the virtual firewall + posture switch

**Companion to:** `PERIMETER_SPEC.md` (the design). This is the *how/what-order*.
**Status:** plan, not started. Written 2026-09-14.

## 0. Decisions locked (supersede the spec's open questions where they differ)

The spec imagined a firewall *appliance* that might make decisions. That was
wrong. **The firewall is dumb infrastructure: it forwards, NATs, and logs —
nothing else.** It never touches `soc.db`, never emits candidates, knows nothing
about the SOC. Everything the spec's §5 called "detection semantics" moves
*downstream* onto the log pipeline we already run. Locked calls:

- **Engine: plain netfilter (iptables), no new firewall container/appliance.**
  netfilter *is* the firewall; `soc-block-enforcer` already proves we can filter
  between Docker bridges from a `network_mode: host` privileged container
  (`DOCKER-USER`, interface-scoped, comment-tagged — see
  `pipeline/triage/block_enforcer.py`). nftables/VyOS/OPNsense would be a heavier
  skin over the same kernel. Ruled out. (OPNsense ≈ pf + Suricata + a UI; we
  already run Suricata + netfilter, so we already have the engines — we'd only be
  adding a config UI a `lab-mode.sh`-driven lab doesn't need. pfSense/OPNsense are
  also VM-only, and this host has no virtualization.)
- **Topology: true two-zone perimeter ("Design B").** The attacker sits on its
  own *internet* segment (`soclab-inet`), **not** multi-homed onto the target
  subnet. The host routes/NATs between the two via iptables `FORWARD`+DNAT. This
  is what yields the *infrastructure-asserted* "external vs internal origin"
  signal (the segment an IP sits on is a fact, not a planted label — preserves
  recon-from-zero / no-insider-leak). A pure in-place port filter ("Design A")
  was rejected: it leaves the attacker LAN-adjacent and forces us to *label* its
  IP to call it "external."
- **Logs → Wazuh, SIEM-consumed (the CloudTrail model).** Firewall emits
  allow/deny lines → `./logs/firewall/` → a new Wazuh `<localfile>` bucket →
  decoder + `local_rules.xml`. **Wazuh rules decide what becomes a `soc.db`
  candidate**, exactly the fleet/NPC pattern (`ossec.conf` `/lab-logs/fleet/*`:
  only alerts land in soc.db, never raw logs). Firewall events reach soc.db
  through the **existing `wazuh` ingest source** (`ingest.py`, `siem_*` columns) —
  so **no new `normalize.py` source is needed.**
- **Posture is a runtime switch, default `insider`.** A `posture` key in
  `lab_mode.json`, orthogonal to the vuln mode. Default `insider` = today's
  behavior, so every existing script/run is unaffected until explicitly switched.
- **Dealer exposure: default-deny + per-target opt-in.** Unknown dealer targets
  are pivot-only (nothing exposed); a target may declare `exposed` ports to be
  remotely solvable.
- **Firewall log format: iptables `-j LOG --log-prefix` (syslog).** Controlled
  prefixes (`FW-DENY-EXT`, `FW-ALLOW-THRU`, `FW-INTERNAL`) so the Wazuh decoder is
  trivial and dependency-free (no ulogd2/nflog build). Log **denies** (realistic
  background noise + volume signal, kept in Wazuh) *and* **allow-throughs** (the
  events that matter).

## 1. Trust boundary (unchanged, restated for this feature)

Every field the classification keys on — action (allow/deny), ingress/egress
interface (= segment), 5-tuple, dst port — is **infrastructure-asserted**, read
straight off the firewall log. No attacker-controlled text drives a firewall
decision or a Wazuh rule. The one place attacker text could ride along (an
HTTP payload behind an allowed port) is already handled by the existing
Suricata/nginx path and its `<untrusted-evidence>` fencing; the firewall log
itself carries none.

## 2. Topology (spec §3, as iptables)

- **New network `soclab-inet`** — `10.211.99.0/24`, inside the `10.211.0.0/16`
  HOME_NET (Suricata needs no reconfig). Registered in `pipeline/net_topology.py`
  as a `LabNetwork` (a distinct role, not a vuln mode). This is "the internet."
- **The host is the router.** No `soc-fw` container. Docker DROPs inter-bridge
  traffic by default (`DOCKER-ISOLATION-STAGE-*`); we punch controlled holes:
  `FORWARD` default-drop between `soclab-inet` and the active inside bridge, plus
  DNAT publishing only the mode's exposed ports to specific inside hosts. Rules
  installed via the **same privileged host-net path block-enforcer uses**
  (`docker exec` into it, or a throwaway `--net=host --cap-add NET_ADMIN`
  container), tagged in a **dedicated chain `SOCLAB-PERIMETER`** so they never mix
  with dynamic `block_ip` DROPs or Docker's own chains.
- **Attacker attachment is runtime, per posture** — `docker network
  connect/disconnect`, no compose rebuild. `remote`: disconnect `soc-attacker`
  from `soclab-<mode>`, ensure it's on `soclab-inet` only. `insider`: reconnect to
  the target bridge (today's state, [compose.yaml:487](compose.yaml:487)).
- **Edge address**: DNAT destination-published on a chosen `soclab-inet` address
  (the segment gateway / a `.2` edge IP). The attacker only ever talks to that.
- `soc-attacker`'s OUTPUT egress lockdown (`reset.sh --attacker`) adds
  `soclab-inet` to its ACCEPT list.

## 3. Detection, relocated (spec §5 → Wazuh rules)

The classification is authored as **Wazuh `local_rules.xml` rules**, keyed on the
LOG prefixes + fields:

| firewall event | Wazuh verdict | reaches soc.db? |
|---|---|---|
| external-origin, denied (closed/unexposed port) | background noise — no alert (optionally a rolled-up volume rule so a *spike* is a weak signal) | no (stays in Wazuh) |
| external-origin, **allow-through** on an exposed port + follow-through | alert, normal/high | yes → candidate |
| **internal-origin** scan/exploit (any inside host originating) | elevate — lateral-movement alarm | yes → high candidate |

`pipeline/detect/rules.py` barely changes: the cross-source correlation rule
already fuses across sources and simply gains firewall-sourced events in the
stream. The hunter gets a one-line **posture note** in its rendered
context/doctrine ("recon from the internet is background noise; alert on
throughput and on anything originating inside").

## 4. Attacker scope & prompt (spec §6)

- `executor.validate_target` / `ALLOWED_NETWORKS` become posture-aware: under
  `remote`, reachable scope is the firewall's exposed surface (the `soclab-inet`
  edge), expanding post-pivot to whatever a compromised inside host can reach
  (`shell_exec` from the foothold).
- `rotate_ip` rotates the `soclab-inet` leg; `block_enforcer._block_targets`
  learns the attacker's inet address is the blockable one.
- Recon prompt tells the attacker its position ("you're on the public internet;
  only the exposed edge is reachable; internal services need a foothold")
  **without** naming the mode or which ports are open — recon-from-zero holds.
- Composes with low-and-slow: loud external recon is free (it's noise), stealth
  timing earns its keep only after the pivot, on the watched inside segment.

## 5. PR breakdown (one mergeable unit each; through PR3 changes no behavior)

- **PR 0 — untangle the branch.** `PERIMETER_SPEC.md` (+ this plan) → their own PR
  onto `main`. Cherry-pick the unrelated hunter/attacker tuning commit `dc5fefe`
  off `wip-tuning-and-firewall-spec` into its own branch → separate PR(s), split
  per `project_hunter_block_calibration`. Clean base to build from.
- **PR 1 — posture plumbing (inert).** `posture` key in `lab_mode.json`;
  `lab_modes.active_config()` surfaces it + `current_posture()` (default
  `insider`); `lab-mode.sh posture {remote|insider}` verb + `status` line.
  Nothing else moves.
- **PR 2 — SPIKE + topology.** Add `soclab-inet` to `net_topology.py` + compose
  external net. **Prove the routing works first** (see §6 risks): attacker on
  `soclab-inet` only → host `FORWARD`+DNAT → inside target, through Docker's
  isolation chains. Attacker re-homing via `docker network connect/disconnect` in
  the `lab-mode.sh` posture switch. **Gate PRs 3-5 on this spike passing.**
- **PR 3 — perimeter ruleset + exposure config.** `pipeline/firewall/perimeter.py`
  generates the `SOCLAB-PERIMETER` chain (default-drop `FORWARD`, DNAT exposed
  ports, `LOG` rules) from a new per-mode `exposed: [{host, port, proto}]` block in
  `lab_modes.py` (dealer = default-deny + opt-in). Applied on `up`/`switch` when
  `posture=remote`; torn down on `down`/`switch`; `reset.sh` clears the chain
  (alongside the existing `block_ip` teardown).
- **PR 4 — firewall → Wazuh (the realism).** `/lab-logs/firewall` `<localfile>`
  bucket in `ossec.conf` + a tail into `./logs/firewall/firewall.log`; Wazuh
  decoder for the LOG prefixes; `local_rules.xml` rules implementing the §3
  classification. This is where the measurement actually changes.
- **PR 5 — attacker scope/prompt for `remote`** (§4): posture-aware
  `validate_target`/`ALLOWED_NETWORKS`, pivot-to-expand reachability,
  recon-from-zero remote prompt, `block_enforcer` inet leg, hunter posture line.
- **PR 6 — (optional, defer) `assumed_breach`**: attacker starts with a foothold
  on a named inside host.

## 6a. Spike result (2026-09-14) — PASSED, Design B validated

Prototyped manually (raw docker + iptables via `soc-block-enforcer`, `hard` mode,
nginx on `soclab-hard`) before writing any code:

- attacker on `soclab-inet` only, off the inside bridge → **HTTP 200 to the edge
  `10.211.99.1:80`** (reaches nginx through DNAT) but **timeout to nginx's real
  `10.211.20.4:80`** (Docker isolation holds — no bypass) and **refused on the
  edge `:443`** (unexposed port closed). Exactly the intended behavior.
- The working ruleset (→ the PR-3 generator):
  ```
  nat PREROUTING  -i soclab-inet0 -d <edge> -p tcp --dport <P> -j DNAT --to <host>:<P>
  nat POSTROUTING -o <inside0> -p tcp -d <host> --dport <P> -j MASQUERADE
  DOCKER-USER     -i soclab-inet0 -o <inside0> -p tcp -d <host> --dport <P> -j ACCEPT
  DOCKER-USER     -i <inside0> -o soclab-inet0 -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
  ```
  ACCEPT in `DOCKER-USER` (first chain off `FORWARD`) wins ahead of Docker's
  isolation drop. `MASQUERADE` keeps the return path on one bridge.
- **Confirmed §6 risks:** (3) the attacker's OUTPUT egress lockdown DROPs the new
  `.99` until `soclab-inet` is added to it — so `soclab-inet` must join the
  `net_topology` subnet list `reset.sh --attacker` iterates (falls out for free by
  adding the network there). (2) Suricata (started before the bridge existed) will
  NOT watch `soclab-inet0` without a restart — same "restart to pick up the new
  bridge" the dealer range already does; inside-bridge east-west visibility is
  unaffected. (1) inter-bridge routing + DNAT works from the existing
  block-enforcer container — no new privileged container needed.
- **Remaining unknown for PR 4:** how firewall LOG lines get into a file bucket for
  Wazuh. `-j LOG` goes to the host kernel ring buffer; the tail into
  `/lab-logs/firewall/` likely needs NFLOG→ulogd2 or a syslog path, TBD in PR 4.

## 6b. PR-3 result (2026-09-14) — generator works; deny-log placement is a PR-4 note

`pipeline/firewall/perimeter.py` apply/clear/status verified live on `hard`:
allow-through to the edge `:80` → HTTP 200 with **FW-ALLOW-THRU logged**;
direct-to-inside-IP and non-exposed edge ports all blocked. Wired into
`lab-mode.sh` (apply under remote / clear under insider, on the posture verb and
after up/switch) and `reset.sh --network` (teardown).

Important finding for PR 4: the *interesting denied traffic under remote is not in
FORWARD.* A remote attacker scans the **edge IP (= the host's inet address)**, so
non-exposed-port probes hit the host's **INPUT** chain (refused there), and
direct-to-inside-IP probes are dropped by **Docker's own inter-bridge isolation**
before reaching `SOCLAB-PERIMETER`. So the realistic "external scan = background
noise" deny-logging belongs in an **INPUT-side LOG rule on `soclab-inet0`** (new,
non-established, non-DNAT to the edge), added in PR 4 — not the FORWARD deny-log,
which stays only as a containment safety net. Containment itself is complete
(everything non-exposed is blocked three ways: perimeter DROP, host INPUT, Docker
isolation).

## 6. Risks to validate in the PR-2 spike (before committing to the rest)

1. **Docker inter-bridge routing + DNAT hairpin.** Docker's
   `DOCKER-ISOLATION-STAGE-*` chains DROP inter-bridge traffic by default. Confirm
   an inet-only `soc-attacker` can reach an inside target *only* via host
   `FORWARD`+DNAT, and that our rules survive Docker re-writing its chains on
   container/network events. **This is the make-or-break for Design B.**
2. **Suricata sees the routed flow.** The inet↔inside traffic traverses the host,
   not one bridge. Confirm Suricata's self-discovery + `/16` HOME_NET still
   captures the DNAT'd flow on the inside bridge (east-west visibility).
3. **Egress lockdown interaction.** `reset.sh --attacker`'s OUTPUT lockdown and the
   `remote` re-homing must not strand the attacker or accidentally re-open the
   inside subnet at L2.

## 7. What did NOT survive the reframe (vs `PERIMETER_SPEC.md`)

- The `soc-fw` **container** — gone; the host + netfilter is the router.
- The spec's §5 **`rules.py` rewrite** — mostly gone; the classification is Wazuh
  rules now, `rules.py` only picks up new events via existing correlation.
- Any notion of the firewall **making SOC decisions or writing soc.db** — gone;
  it only logs.
- A new **`normalize.py` source** — not needed; firewall events arrive via the
  existing `wazuh` source.
