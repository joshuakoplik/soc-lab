# PERIMETER_SPEC — virtual firewall + attacker posture switch

**Status:** design doc, not yet implemented. Written 2026-09-14.
**Companion:** `REDTEAM_MODE_SPEC.md`, `pipeline/net_topology.py`, `CLAUDE.md`.

## 1. Why

Today `soc-attacker` is multi-homed directly onto every mode's target subnet
(`net_topology.LAB_NETWORKS`), i.e. it is **LAN-adjacent to every target**.
Every service a mode runs is reachable on every port, and every recon scan the
attacker fires is a candidate the defender can alert/block on. That models an
attacker who is *already inside*, and it makes recon itself a high-signal event.

Real internet-facing apps don't work that way:

1. **Internet background noise is not signal.** Any public IP is scanned
   constantly; you do not page a human for a port sweep against your edge. The
   defender should wake up for someone getting *through* the perimeter or moving
   *inside* it — not for the sweep.
2. **The firewall is most of the defense.** A real edge exposes only the ports a
   public app needs (usually 80/443, sometimes 22). The database, the message
   broker, the admin panel on :8161, the RCE on :50000 — none of those are
   reachable from the internet. Many services become **exploitable only after
   the attacker breaches the edge and pivots**.

This spec adds a **virtual firewall** between the attacker and the targets, and
makes the attacker's starting position a **switch**, so one lab can simulate a
fully-remote attacker on some runs and an insider / east-west attacker on
others.

### The uncanny valley we're currently in

Right now the attacker sits on an **unfettered subnet** (wide-open nmap works)
but the defender treats that same subnet as **untrusted** (freaks out at the
scan). That combination exists nowhere in the real world, and it's why the
hunter's aggression reads as both "correct" and "wrong" at once. The two real
setups it's stuck between:

- **Internet edge:** attackers *do* run wide-open nmap against you constantly,
  and you **ignore all of it** — a scan yields nothing but your intentionally
  open ports, so it isn't signal. The defender's hard problem here is
  **filtering**: not drowning in / not reacting to background noise, and firing
  only when something gets *through*.
- **Internal network:** you may be wired to see everything, but you're
  **reluctant to classify anything malicious and act**, because taking defensive
  action (blocking a host) risks friendly fire and outage. The defender's hard
  problem here is **courage under friendly-fire risk** — making the act/don't-act
  call well when everything looks like it could be legitimate.

The two postures below map onto exactly those two challenges, which is the point
of making it a switch:

| posture | defender's real challenge | failure mode being measured |
|---|---|---|
| `remote` | filter background recon; react only to throughput/breach | alerting on noise; missing the one that got through |
| `insider` | act correctly under friendly-fire risk | friendly fire (over-block) **or** paralysis (never acts) |

The hunter tuning already done (shape-based blocking, never auto-DROP a CMDB
asset, recommend-vs-block calibration) is precisely the **insider**-posture
skill. The **remote** posture is what the detection rewrite in §5 unlocks — and
it's the half the lab is missing today.

## 2. Attacker posture — a switch, orthogonal to the vuln mode

Posture is a **second axis**, independent of the vulnerability mode
(`easy`/`hard`/`wordpress`/`dealer`/`northwind`). The same WordPress target can
be attacked remotely (through the firewall) or from inside (assume-breach /
insider). So posture is **not** a new `MODES` entry — it is a separate key.

Proposed values:

| posture | attacker sits… | sees | models |
|---|---|---|---|
| `remote` | on the **internet** segment, outside the firewall | only the firewall's exposed surface (DNAT'd ports) | external, fully-remote attacker |
| `insider` | on the **inside** target subnet (today's behavior) | every service on every port | malicious insider / east-west lateral movement / assume-breach |

Optional third value worth considering: `assumed_breach` — attacker starts with
a shell/foothold on one inside host (a specific low-value box), everything else
reachable only from there. This is the most realistic "post-phish" scenario and
a natural middle ground; can be a later phase.

### Wiring the switch

- New key in `lab_mode.json`: `{"mode": "...", "posture": "remote|insider", ...}`.
  `lab_modes.active_config()` surfaces it; default `insider` preserves current
  behavior for every existing script and run.
- `lab-mode.sh` gains `posture {remote|insider}` (and reports it in `status`),
  the same single-source-of-truth pattern as `mode`.
- Nothing in the vuln-mode definitions changes; posture is read alongside.

## 3. Topology

### New: the internet segment + a firewall/router container

- A new **external network** (call it `soclab-inet`, e.g. `10.211.99.0/24`,
  still inside the `10.211.0.0/16` HOME_NET so Suricata needs no reconfig — see
  the note in `net_topology.py`). This is "the internet" from the lab's POV.
- A new **firewall container** (`soc-fw`) with two legs: one on `soclab-inet`,
  one on the active mode's inside subnet. It is the only path between them.
  Implemented as an iptables router: `FORWARD` default DROP, plus DNAT rules that
  publish only the mode's allowlisted ports to specific inside hosts. (This is
  the same shape as the existing `soc-block-enforcer` — a privileged container
  that owns a chain — so it fits the codebase's model.)
- `LabNetwork` already carries `internal: bool`; the inside subnets under a
  firewall want `internal=True` (no direct route off-host; the only way in is
  through `soc-fw`), exactly the containment `dealer` already uses.

### Attacker attachment by posture

- `posture=remote`: `soc-attacker` attaches to `soclab-inet` **only**. It is no
  longer multi-homed onto the target subnets. `discover_hosts`/`nmap_scan` see
  only the firewall's public IP + exposed ports.
- `posture=insider`: unchanged — `soc-attacker` on the inside subnet as today.

### `rotate_ip` and blocks under a firewall

- `rotate_ip` in `remote` posture rotates the attacker's **internet** address
  (`soclab-inet`), not an inside one. `net_topology`/`executor.rotate_ip` already
  pick the interface by subnet membership, so this mostly falls out — but the
  block-enforcer's "multi-homed attacker" expansion (`_block_targets`) needs to
  learn that the attacker's blockable address is now on `soclab-inet`.
- The defender's real `block_ip` still works: dropping the attacker's internet
  IP at the firewall's external leg is exactly a real edge block.

## 4. Per-mode exposure policy

Each mode declares which ports are internet-exposed and to which inside host —
the firewall's DNAT allowlist. This is the core realism lever.

- `wordpress`: 80/443 → the WP host. The RCE chain is reachable remotely (it's a
  web CVE), so this mode stays solvable in `remote` posture.
- `easy`/`hard`: expose whatever a real deployment of that surface would (e.g.
  nginx 80/443). Cowrie's SSH honeypot on 2222 is a deliberate exposure choice.
- `dealer`: **per Vulhub target.** Many Vulhub exploits live on non-standard
  ports (ActiveMQ 8161, Nexus 8081, Jenkins 8080, fastjson/JMX 50000, …). A real
  firewall would **not** expose those — so in `remote` posture those targets are
  **pivot-only**: unreachable until the attacker breaches an exposed service and
  moves laterally. This is the big difficulty/realism win and a genuine test of
  pivot capability. The exposure list is per-target metadata in the dealer range.
- `northwind`: expose the app's public edge (its nginx) only; the RAG internals,
  ollama upstream, and postgres stay internal.

Representation: a `posture`-aware block in `lab_modes.py` per mode, e.g.
`exposed: [{"host": "...", "port": 443}]`, consumed by `soc-fw`'s rule
generator at standup. In `insider` posture the exposure list is ignored (the
attacker is already inside).

## 5. Detection semantics — "internet background noise"

This is the change with the most blast radius, in `pipeline/detect/rules.py`
(and by extension the hunter's feed).

Today `rule_ids_alert` turns **every** Suricata scan alert into a candidate.
Under a perimeter that is wrong: an external port sweep against the firewall is
noise. The new classification, keyed on **where the source sits** (an
infrastructure-asserted fact — the segment an IP belongs to, via
`net_topology.network_for_ip`) and **whether it got through**:

1. **External-origin, hit-a-closed/blocked-port (didn't get through)** →
   *background noise.* Suppress, or emit at `info` severity that the feed shows
   only as a volume line, never a per-alert candidate. (The volume is still
   itself a weak signal — a spike over baseline could precede a real attempt —
   but it is not a to-do item.)
2. **External-origin, on an EXPOSED port, with follow-through** (a real request,
   an exploit signature, a completed connection behind the allowed port) →
   *keep, normal/high.* This is "someone is actually attacking the app."
3. **Internal-origin activity** (any scan/exploit whose source is an inside
   host) → *elevate.* Inside the perimeter nothing should be scanning its
   neighbors; this is the lateral-movement / post-compromise signal the defender
   most needs. A host that was benign yesterday suddenly scanning 5432 across the
   subnet is the alarm.

The trust boundary is preserved: source-segment and dst-port are
infrastructure-asserted, so this classification uses only trustworthy facts.

This also fixes a philosophical wart in the current lab: the hunter blocking an
attacker for *recon alone* (which it does aggressively) is realistic only for an
insider. For a remote attacker, recon is noise and the block should come from
throughput/exploitation, not the sweep. Posture should inform the hunter's
`RESPONSE DOCTRINE` too (a short posture line in the rendered context: "recon
from the internet is background noise; alert on throughput and on anything
originating inside").

## 6. Attacker scope & prompt changes

- `executor.validate_target`/`ALLOWED_NETWORKS`: in `remote` posture the
  attacker's reachable scope is the firewall's public surface, not the inside
  subnet. Post-pivot, reachability expands to whatever the compromised host can
  reach (this is where `shell_exec` from a foothold does the work).
- Recon prompt: tell the attacker its position ("you are on the public internet;
  only the target's exposed edge is reachable; internal services require a
  foothold") **without** naming the mode or which ports are open — recon from
  zero still holds; it must discover the exposed surface itself.
- This composes with **low-and-slow** (just shipped): external recon is ignored
  noise, so the attacker can scan the edge loud and free; stealth timing only
  earns its keep **after the pivot**, on the watched inside segment. Loud
  outside, quiet inside — a clean two-phase game.

## 7. Implementation phases

1. **Posture plumbing (no firewall yet):** add `posture` to `lab_mode.json`,
   `lab_modes.active_config()`, `lab-mode.sh`. Default `insider`. Everything
   behaves as today. (Small, safe, unblocks the rest.)
2. **The `soclab-inet` network + `soc-fw` container:** two-legged iptables
   router, DNAT allowlist generated from a mode's `exposed` list; default DROP.
   `remote` posture attaches `soc-attacker` to `soclab-inet` only.
3. **Per-mode exposure lists** in `lab_modes.py` + dealer per-target metadata.
4. **Detection rewrite** in `rules.py`: source-segment + through-perimeter
   classification; noise suppression; internal-origin elevation. Posture line in
   the hunter context/doctrine.
5. **Attacker scope/prompt** for `remote`: perimeter-aware `validate_target`,
   pivot-to-expand reachability, recon-from-zero prompt.
6. **(Optional) `assumed_breach` posture:** attacker starts with a foothold on a
   named inside host.

Phases 1–3 stand up the topology; 4 is where the lab's *measurement* actually
changes; 5 makes the attacker play the new game.

## 8. Open decisions

- **Posture representation:** a `posture` key in `lab_mode.json` (recommended,
  orthogonal) vs. folding it into mode names. Recommend the key.
- **`block_ip` under `remote`:** confirm the enforcer blocks the attacker's
  `soclab-inet` address and that reset.sh clears it. `_block_targets` multi-home
  logic needs the inet leg added.
- **Noise handling:** hard-suppress external recon candidates, or keep them at
  `info` with a volume roll-up so a sweep *spike* is still visible? Recommend the
  latter — cheaper to reason about, and a spike over baseline is real weak
  signal.
- **Dealer exposure:** where does each Vulhub target's "realistic exposed port"
  list live — hand-curated per target, or default-deny-all (pure pivot-only)?
  Default-deny-all is simplest and hardest; a curated "this one really is a
  public web app" list keeps some dealer targets remotely solvable.
- **Suricata visibility inside vs. at the edge:** confirm `soc-fw`'s inside leg
  and the inside bridge are both covered by Suricata's interface discovery so
  east-west traffic is still seen.
