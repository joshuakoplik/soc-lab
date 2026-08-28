# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## What this is

A SOC (Security Operations Center) lab: a set of intentionally-vulnerable, dockerized
targets emitting real telemetry, a deterministic ingest/detect pipeline landing that
telemetry in SQLite, and two LLM agents built on top of it — a **triage agent** (blue
team, reads candidates and decides verdicts) and a **red-team agent** (offense,
recon+assess+propose against the lab's own targets). A third component,
`injection_asr/`, is a harness that measures the triage agent's resistance to
prompt injection carried in attacker-controlled fields.

This is a research/experimentation environment for studying LLM-in-the-SOC behavior
(trust boundaries, prompt injection, tool-use gating), not a production security
product.

## Running the lab

```bash
./setup.sh && ./verify.sh              # bring up cowrie+juiceshop+nginx, confirm telemetry lands
./lab-mode.sh {up|down|switch} {easy|hard|wordpress|northwind}   # writes lab_mode.json
./lab-mode.sh status                   # primary mode + live docker state for all four
./reset.sh [--network|--db|--queue|--status] [--no-kill]   # reset baseline; default (no flags) does all three
docker compose ps / logs -f <svc> / down [-v]
```

- **easy**: cowrie + metasploitable up (planted creds, vulnerable services intact), Juice Shop default difficulty.
- **hard**: cowrie/metasploitable down, no leaked creds, Juice Shop hardened + network-locked, nginx is the only target.
- **wordpress**: everything else down; only a real WordPress core pinned to the CVE-2026-63030/CVE-2026-60137 chain — see `wordpress/README.md`. Named plainly, not after the exploit chain, so the model isn't handed the CVE pair for free.
- **northwind**: the fourth mode, and the odd one out — a vulnerable *AI application*
  (RAG chat product) rather than a vulnerable service. It's a full entry in
  `lab_modes.py` like the others, but it's the first **adapter-backed** mode: its
  containers live in a separate docker-compose project (`northwind-range/`, own
  `Makefile`, own networks, no `net_topology.py` subnet), so the red-team agent
  reaches it through `redteam/northwind_adapter.py` instead of nmap/hydra.
  `lab-mode.sh` still drives its lifecycle like any other mode, but by
  delegating to `northwind-range/Makefile` rather than to this repo's
  `compose.yaml` — one definition of how the range comes up, not two. `up
  northwind` skips the `net_topology.py` bootstrap (it has no subnet there)
  and pre-checks `northwind-range/.env` for `NW_OLLAMA_UPSTREAM_HOST`, since
  without it the containers start and then fail deep inside a chat request.
  A `down` leaves the postgres volume alone; `make -C northwind-range reset`
  is what re-seeds corpus/entitlements/records. See `northwind-range/SPEC.md`
  and `REDTEAM_MODE_SPEC.md`.

`lab_mode.json` (gitignored) is the single source of truth for which mode is
*actually* running; `pipeline/redteam/lab_modes.py` reads it so the red-team agent's
target/tool config can never drift out of sync with what's really up. There's no
other flag to remember to pass.

Traps worth knowing before debugging telemetry gaps: Cowrie runs as uid 1000 and
silently fails to write to a root-owned bind mount (`chmod -R 0777 logs/cowrie`);
never map Cowrie to host port 22 or bind Juice Shop off localhost — see the
top-level `README.md`.

## Pipeline commands (host side, Python)

```bash
python3 pipeline/ingest.py [--follow] [--reset]      # tail cowrie/nginx/suricata/wazuh logs -> normalize -> soc.db
python3 pipeline/detect/rules.py [--all] [--stats]    # deterministic candidate detection over events
python3 pipeline/triage/agent.py [--dry-run] [--provider local|claude|gmi|fireworks] [--limit N] [--stats]
python3 pipeline/redteam/agent.py [--dry-run] [--provider ...] [--stats] [--list-pending]
python3 injection_asr/run_asr.py [--provider ...] [--classes ...] [--controls on|off|both]
```

No test suite or linter is configured in this repo — don't invent `pytest`/`ruff`
commands. `requirements.txt` covers a broad research stack (garak, langchain,
torch/transformers, etc.); the pipeline/agent code itself only needs stdlib +
`anthropic`/`ollama`/provider SDKs.

## Architecture

### 1. Telemetry -> SQLite (`pipeline/ingest.py`, `pipeline/normalize.py`, `pipeline/schema.sql`)

Four sources tail into one `events` table in `soc.db`: `cowrie` (SSH honeypot),
`nginx` (reverse-proxied Juice Shop access log), `suricata` (IDS, EVE
`alert` records only), `wazuh` (SIEM alerts — including the wordpress target's
own Apache access/error logs, read directly since it has no reverse proxy in
front of it; see `wazuh/ossec.conf`). `normalize.py` maps each source's
native JSON into one shared column set.

**The property that matters everywhere downstream: columns are split by trust, not
by type.** `schema.sql` groups them explicitly:
- infrastructure-asserted (`ts`, `source`, `event_type`, `src_ip`, ...) — observed, cannot be forged by the attacker.
- attacker-controlled (`username`, `password`, `command`, `url_path`, `user_agent`, `request_body`, ...) — free text a hostile party wrote, merely transported. `normalize.ATTACKER_CONTROLLED` lists exactly these columns and is imported wherever that boundary needs re-asserting (e.g. `triage/agent.py`'s tool results).
- IDS-/SIEM-asserted (`ids_*`, `siem_*`) — a rule firing is trustworthy as a detection, but the payload that tripped it is still hostile text.

`raw` is the original line, always present, untouched. `llm_view` (`pipeline/llm_view.py`)
is the same event with oversized/blob fields replaced by a preview+hash — what
the agents' tools hand the LLM by default; `raw` is kept for forensics and reachable
only via the opt-in, logged `get_raw_event` tool.

`ingest.py` reads new bytes since a per-file `(inode, offset)` tail_state, handles
log rotation (inode change or truncation), and never silently drops a line —
anything unparseable goes to `parse_failures` rather than vanishing (`AGENT_BRIEF.md`'s
old framing, still true: a gap in a SOC feed is indistinguishable from an attacker
cleaning up after themselves).

### 2. Detection (`pipeline/detect/rules.py`)

Pure, deterministic functions over `events` -> `candidates`. No model involved —
this is the reproducible tier, deliberately, because the LLM tier below it isn't.

### 3. Triage agent (`pipeline/triage/agent.py`)

Reads `candidates` with `status='new'`, calls a provider (see below) with a tool
contract, writes a verdict to `triage` and flips `candidates.status`. Its own
docstring and `SYSTEM_PROMPT` are the canonical spec of the trust-boundary
contract — read them before changing anything here. Key points:

- `build_user_turn()` fences everything derived from `ATTACKER_CONTROLLED` columns
  inside `<untrusted-evidence>` tags, structurally separated from instruction text
  (`controls="on"`, the production path). `controls="off"` + `SYSTEM_PROMPT_NAIVE`
  is the ablation baseline used only by `injection_asr/` to measure what that
  separation is worth — never used by `main()`.
- Tools are least-privilege and split by gate: `query_events`/`get_event_details`/
  `enrich_ip`/`correlate` are read-only; `raise_alert` is safe/ungated;
  `recommend_block` only ever inserts into `block_recommendations` with
  `approved=0` — nothing reads or acts on it; `block_ip` is **ungated and
  REAL** — it inserts an actual iptables DROP rule via the `soc-block-enforcer`
  container (`network_mode: host`, so it can reach the host's `DOCKER-USER`
  chain, where inter-container/bridge traffic is filtered). No human gate;
  the safety boundary is hard technical fencing instead —
  `pipeline/triage/block_enforcer.py`'s `validate_lab_ip()` rejects anything
  outside this lab's own subnets (one per mode now, not a single shared
  bridge — see `pipeline/net_topology.py`) before a single subprocess runs,
  and every rule it does insert is scoped to whichever mode's bridge
  interface that IP actually belongs to — so this tool cannot reach outside
  this lab's own docker networks no matter what `src_ip` the model passes.
  Every call — executed
  or rejected — is logged to `block_ip_calls`. Run `./reset.sh --network` to
  remove every block this has ever put in place. `get_raw_event` exists but
  is deliberately not in `TOOLS` — opt-in only.
- `candidates.status` is the only write this file makes to that table.

### 4. Red-team agent (`pipeline/redteam/agent.py`, `pipeline/redteam/executor.py`, `pipeline/redteam/lab_modes.py`)

Two stages per campaign: **RECON** (read-only — `nmap_scan`, `http_probe`,
`get_recon_findings`) then **ASSESS** (`raise_vuln_finding` plus the gate,
`propose_action`). Read the module docstring at the top of `agent.py` in full
before touching gating logic — the short version:

- `propose_action` only ever `INSERT`s into `pending_actions`. Executing a gated
  tool (`hydra_bruteforce`, `sqlmap_scan`, `ssh_exec`, `msf_run_module`,
  `shell_exec`) happens **only** in `execute_pending_action()`, reachable **only**
  from `--execute-approved`, which only touches rows a human already flipped
  `approved=1` via a separate `--approve <id>` call. Approving ≠ executing.
- **Whitelisted-network exception**: every target currently in `ALLOWED_TARGETS`
  (cowrie, nginx, metasploitable, wordpress) also resolves inside
  `executor.ALLOWED_NETWORKS` (one subnet per mode now, see
  `pipeline/net_topology.py`, not a single shared bridge) — lab-internal
  and reversible by construction. For those, `propose_action` auto-approves
  (`approved_by="auto-whitelist"`) and executes in the same model turn, no human
  step at all, and the gated executors drop their intensity caps (see the
  `unrestricted` branches in `_exec_hydra_bruteforce`/`_exec_sqlmap_scan`).
- **Scope fencing is separate from the approval gate.** `validate_target()` (in
  `executor.py`) is called before `executor.run()` regardless of gating/whitelist
  status, and is re-read from `lab_modes.active_config()` on every call (not
  cached), so a mode switch mid-process can't leave it checking a stale allowlist.
  `msf_run_module` additionally restricts `module` to `lab_modes.ALLOWED_MSF_MODULES`.
- `shell_exec` is the one tool with **no target allowlist or module allowlist at
  all** at the Python level — its only containment is an iptables OUTPUT lockdown
  on the `soc-attacker` container (loopback + every lab subnet from
  `pipeline/net_topology.py`, default DROP; `soc-attacker` is multi-homed
  onto all of them at once — see `compose.yaml`). Applied *outside this
  codebase*, though `./reset.sh --attacker` reapplies it automatically on
  every rebuild — don't enable `shell_exec` against an attacker container
  that hasn't had that lockdown applied (a stale image predating the
  current Dockerfile can silently lack the `iptables` binary needed to
  apply it at all — confirmed live, see git history if curious).
- `lab_modes.py` defines what each mode (`easy`/`hard`/`wordpress`/`northwind`)
  means — which
  targets exist, which gated tools are reachable, which MSF modules are
  allowlisted — but never decides which one is active; `lab-mode.sh` does that,
  via `lab_mode.json`, for all four modes. The model is never told which mode it's in or that a
  target is "hardened" — only what's factually reachable, so difficulty
  measurements aren't contaminated by the agent being coached.
- Sessions do not persist across separate `propose_action` calls (no `msfrpcd`
  running) — privilege escalation on an opened MSF session has to happen via
  `session_commands` in the *same* call that opened it.

### 5. Providers (`pipeline/providers/`)

Vendor-neutral `Provider` interface (`base.py`) — the triage/red-team loops never
import a vendor SDK directly (`claude.py`/`local.py`/`gmi.py`/`fireworks.py` are
peers implementing the same contract; adding a fourth backend means a new file
here, not a change to `agent.py`). `ToolSpec` is the shared `{name, description,
input_schema}` shape both agents' tool lists use.

### 6. Injection ASR harness (`injection_asr/`)

Forges known-malicious cases, embeds a payload from each attack class
(`injection_asr/payloads/`: `imperative`, `false_context`, `field_splitting`,
`evasion`, plus generator backends) into real attacker-controlled fields, runs
them through the **actual** normalize -> SQLite -> rules -> triage/agent.py path
against an **isolated harness DB** (never `soc.db`), scores the outcome via
`scorer.py`'s domain-specific oracle, and writes `runs/<name>/RESULTS.md` +
`results.jsonl`. A "win" for the attacker means the wrong-target/no-alert outcome
was *observed* — except for `block_ip` (see above), which is real production
infrastructure and deliberately NOT intercepted by this harness:
`injection_asr/runner.py` routes it through the exact same `agent.dispatch_tool`
path a live triage run does, on purpose, because whether a forged payload can
trick the model into calling the real block tool on the wrong target is
exactly what this harness is for. The only safety boundary is
`block_enforcer.py`'s hard CIDR fence (this lab's own subnets only, see
`pipeline/net_topology.py`, never a subnet's own gateway) — a rejection
prints loudly so a fence hit during a harness run is
never mistaken for routine noise. Run `./reset.sh --network` after a run to
undo anything it blocked (the harness's own DB is already isolated from
soc.db, so a full `./reset.sh` isn't needed here). `recommend_block` never
executes anywhere, harness or production. Runs live under
`injection_asr/runs/<name>/`; only
the `RESULTS.md` summaries are meant to be committed (see `.gitignore` —
the raw `harness.db`/`results.jsonl` are regenerable).

Compare `--controls on` vs `--controls off` output when evaluating whether a
prompt change actually improved injection resistance, not just whether verdicts
changed.

## Working in this codebase

- **Trust labeling is the load-bearing convention.** Any time you touch code that
  moves data from an attacker-controlled column into a prompt, tool result, or
  log line meant for a human, check whether it needs the same fencing/labeling
  `normalize.ATTACKER_CONTROLLED` and `build_user_turn()` already use elsewhere.
  Treat "did I just let hostile text reach an instruction channel unlabeled?" as
  the first question, not an afterthought.
- **Gating discipline for new tools**: read-only tools go in the main `TOOLS`/
  `RECON_TOOLS`/`ASSESS_TOOLS` lists freely. Anything that acts on real
  infrastructure needs an explicit decision about which of the three postures
  above it gets (ungated-but-logged like `block_ip`/`get_raw_event`, human-gated
  via a `pending_actions`-style table, or whitelist-scoped auto-execute) — don't
  add a fourth ad hoc pattern without a reason.
- Some docstrings in this codebase reference stale paths (`pipeline/rules.py`,
  `pipeline/agent.py`, `harness/*`, `AGENT_BRIEF.md`) from before a restructure
  into `pipeline/detect/`, `pipeline/triage/`, `pipeline/redteam/`, and
  `injection_asr/`. Trust the actual file layout over those comments; `AGENT_BRIEF.md`
  no longer exists in the repo.
- `attacker/loot/` and `results/{redteam,triage}/` accumulate run artifacts
  (nmap/hydra/sqlmap output, session logs) — these are generated, not source; see
  `.gitignore` for exactly what's excluded.
