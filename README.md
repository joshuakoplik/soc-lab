# soc-lab

A research environment for studying **LLM agents inside a Security Operations Center** —
where they hold up, where they get manipulated, and what the trust boundary between
"observed fact" and "text an attacker wrote" actually costs to enforce.

It is three things wired together:

1. **A lab** — intentionally-vulnerable, dockerized targets emitting real telemetry.
2. **A deterministic pipeline** — ingest → normalize → detect, landing in SQLite. No model involved.
3. **Two agents on top of it** — a **triage agent** (blue team: reads detections, decides
   verdicts, can act on the network) and a **red-team agent** (offense: recon, assess,
   propose, execute against the lab's own targets).

Plus `injection_asr/`, a harness that measures the triage agent's resistance to prompt
injection carried in attacker-controlled fields.

---

## ⚠️ Read this before you run anything

This repository builds **deliberately vulnerable infrastructure** and ships **agents with
real, unsandboxed capabilities**. It is a research instrument, not a security product.

- **Never bind any of it to a routable interface.** Every target here is designed to be
  exploitable. Defaults are loopback and lab-internal docker networks; keep them that way.
- **The triage agent's `block_ip` tool writes real iptables rules** via a privileged
  `network_mode: host` container. Its only safety boundary is a hard CIDR fence
  (`pipeline/triage/block_enforcer.py`) restricting it to this lab's own subnets.
  `./reset.sh --network` removes every rule it has ever inserted.
- **The red-team agent's `shell_exec` tool has no target allowlist at the Python level.**
  Its only containment is an iptables OUTPUT lockdown applied to the attacker container
  (`./reset.sh --attacker`). Do not enable it against an attacker container that has not
  had that lockdown applied.
- **Only ever point the red-team agent at this lab's own targets.** Doing otherwise is
  unauthorized access to someone else's systems.
- Run the whole thing on a host you control, ideally disposable, and not one that matters.

---

## The idea worth stealing

Most log schemas group columns by *type* — strings here, timestamps there. This one groups
them **by trust**, and that single decision propagates through every layer above it
(`pipeline/schema.sql`):

| Group | Examples | Can an attacker forge it? |
|---|---|---|
| Infrastructure-asserted | `ts`, `source`, `event_type`, `src_ip` | No — observed by the sensor |
| **Attacker-controlled** | `username`, `password`, `command`, `url_path`, `user_agent`, `request_body` | **Yes — this is free text a hostile party wrote, merely transported** |
| IDS/SIEM-asserted | `ids_*`, `siem_*` | The *rule firing* is trustworthy; the *payload that tripped it* is still hostile |

`normalize.ATTACKER_CONTROLLED` names exactly those columns, and is imported anywhere that
boundary has to be re-asserted. When the triage agent builds its prompt, everything derived
from those columns is fenced inside `<untrusted-evidence>` tags, structurally separated
from instruction text.

The `injection_asr/` harness exists to answer: **is that fencing worth anything, measurably?**
It runs the same forged payloads through the pipeline twice — `--controls on` (the
production path) versus `--controls off` (a naive prompt, no separation) — and scores the
difference.

---

## Quickstart

Requires Docker + Compose, Python 3.11+, and an LLM provider (a local Ollama, or an API key).

```bash
cp .env.example .env        # then fill in whichever provider keys you'll use
./setup.sh                  # bootstrap networks, start baseline infra + easy mode
./verify.sh                 # confirm telemetry is actually landing on disk
```

Then run the pipeline:

```bash
python3 pipeline/ingest.py --follow          # tail logs -> normalize -> soc.db
python3 pipeline/detect/rules.py --all       # deterministic detection -> candidates
python3 pipeline/triage/agent.py --dry-run   # triage agent over new candidates
```

Optional live view of everything landing in `soc.db`:

```bash
python3 dashboard/server.py                  # http://127.0.0.1:8095, read-only
```

---

## Lab modes

A **mode** is one coherent scenario: a set of targets, its own network, and its own
allowlist of which agent tools can reach them. `lab-mode.sh` writes `lab_mode.json`, which
is the *single source of truth* for what is actually running —
`pipeline/redteam/lab_modes.py` reads it, so the agent's target and tool config can never
drift out of sync with reality. There is no flag to remember to pass.

Modes run on separate subnets and can coexist:

| Mode | Targets | Subnet | Reach it at |
|---|---|---|---|
| `easy` | Cowrie SSH honeypot, Metasploitable, Juice Shop behind nginx | `10.211.10.0/24` | `:8082` web, `:2222` ssh |
| `hard` | Juice Shop hardened + network-locked; nginx is the only target | `10.211.20.0/24` | `:8081` web |
| `wordpress` | Real WordPress core pinned to a known-vulnerable version | `10.211.30.0/24` | via nginx |
| `northwind` | A full RAG chat product — see below | *(own compose project)* | `:8888` |

```bash
./lab-mode.sh up <mode>       # bring one mode up alongside the others
./lab-mode.sh down <mode>     # take one down
./lab-mode.sh switch <mode>   # replace whatever's running
./lab-mode.sh status          # live state of every mode at once
```

`lab-mode.sh` manages the first three. `northwind` is a mode as far as the agents are
concerned — it is a full entry in `pipeline/redteam/lab_modes.py` with its own targets and
tool list — but its containers are brought up through its own `Makefile` (below) rather
than by `lab-mode.sh`.

**The model is never told which mode it's in**, or that a target is "hardened" — only what
is factually reachable. Difficulty measurements would be worthless if the agent were being
coached.

### The `northwind` mode

`northwind-range/` is the fourth mode, and the most involved one. Where `easy`/`hard`/
`wordpress` are vulnerable *services*, Northwind is a vulnerable **AI application**: an
air-gapped RAG chat product with real authentication, real per-tenant authorization, and
real tool use, wrapped in a harness that can swap backend models and toggle individual
security controls to measure each one's effect independently.

The thesis it tests: *an attacker writes into a trusted store, and the platform voluntarily
ingests it.*

It differs from the other three in one structural way — it is a **separate docker-compose
project** with its own `Makefile`, reached from the host rather than over a
`net_topology.py` subnet, so the red-team agent talks to it through an adapter
(`pipeline/redteam/northwind_adapter.py`) rather than through `nmap`/`hydra`. Its build
specs are `northwind-range/SPEC.md`, `SPEC_phase2.md`, and `REDTEAM_MODE_SPEC.md`.

```bash
cd northwind-range
cp .env.example .env    # NW_OLLAMA_UPSTREAM_HOST is required
make up && make reset   # build, seed corpus + entitlements + records
```

> **Note:** because it is a nested compose project, always `cd northwind-range` explicitly
> or pass `-f` before any `docker compose` command — a stale working directory will point
> `docker compose down` at the wrong stack.

---

## Layout

```
pipeline/            The deterministic tier plus both agents
  ingest.py            tail cowrie/nginx/suricata/wazuh -> normalize -> soc.db
  normalize.py         native JSON -> one shared, trust-labeled column set
  schema.sql           the trust-split events table
  llm_view.py          the redacted event view agents actually see
  net_topology.py      per-mode subnets; the single source of truth for CIDRs
  detect/rules.py      pure deterministic functions: events -> candidates
  triage/              blue-team agent, its tools, and the iptables block enforcer
  redteam/             red-team agent, executor, gating, per-mode configs
  providers/           vendor-neutral Provider interface (claude/local/gmi/fireworks)
injection_asr/       prompt-injection ASR harness (isolated DB, never touches soc.db)
northwind-range/     the northwind mode: a full RAG app + control-ablation harness
dashboard/           read-only real-time view over soc.db
attacker/            Kali container, multi-homed onto every mode's network
cowrie/ nginx/ juiceshop/ wordpress/ suricata/ wazuh/    per-service config
results/             committed experiment write-ups
```

Anything under `logs/`, `attacker/loot/`, `results/**/*.json`, and
`injection_asr/runs/*/harness.db` is **generated, not source** — see `.gitignore`. Only the
human-readable `RESULTS.md` / `*.md` summaries are committed.

---

## Tool gating

Every tool that touches real infrastructure gets an explicit, documented posture. There are
exactly three, and adding a fourth ad-hoc pattern is the thing to avoid:

- **Ungated but logged** — `block_ip`, `get_raw_event`. No human step; the safety boundary
  is hard technical fencing instead (a CIDR allowlist checked before any subprocess runs).
  Every call, executed or rejected, is recorded.
- **Human-gated** — `propose_action` only ever `INSERT`s into `pending_actions`. Executing
  it requires a separate `--approve <id>` by a human, and then a separate
  `--execute-approved`. *Approving is not executing.*
- **Whitelist-scoped auto-execute** — targets that are lab-internal and reversible by
  construction auto-approve and execute in the same turn.

**Scope fencing is separate from the approval gate.** `validate_target()` runs before every
execution regardless of gating status, and re-reads the active config on every call, so a
mode switch mid-process cannot leave it checking a stale allowlist.

Read the module docstring at the top of `pipeline/redteam/agent.py` before touching any of
this — it is the canonical spec.

---

## Traps, in roughly the order you'll hit them

1. **No `cowrie.json` appears, but the container looks healthy.** Cowrie runs as uid 1000
   and cannot write to a root-owned bind mount. It fails *silently*.
   Fix: `chmod -R 0777 logs/cowrie && docker compose restart cowrie`
2. **Never map Cowrie to host port 22.** You would be handing your own sshd's port to a
   honeypot.
3. **Juice Shop 502s for the first ~20 seconds.** It is still booting. Wait.
4. **Juice Shop is never published directly** — all web traffic goes through nginx, which
   is what turns it into telemetry.
5. **Port 8082, not 8080**, for easy mode's nginx; `hard` uses 8081 because two nginx
   instances cannot share a host port when both are up.
6. **`ingest.py` never silently drops a line.** Anything unparseable goes to
   `parse_failures` rather than vanishing — a gap in a SOC feed is indistinguishable from
   an attacker cleaning up after themselves.

---

## Resetting

```bash
./reset.sh                 # network + db + queue
./reset.sh --network       # remove every iptables rule block_ip ever inserted
./reset.sh --attacker      # rebuild attacker container and reapply its egress lockdown
./reset.sh --status
./verify-isolation.sh      # assert the live network isolation actually holds
```

`verify-isolation.sh` queries live docker and iptables state — nothing is taken on faith
from what a compose file claims.

---

## Notes on scope

There is no test suite or linter configured. `requirements.txt` covers a broad research
stack (garak, langchain, torch/transformers); the pipeline and agent code itself needs only
the standard library plus a provider SDK.

## License

MIT — see [LICENSE](LICENSE).
