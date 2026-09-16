# `labctl` — the lab manager

`labctl` is the SOC lab's orchestration layer: the one component allowed to know
lab *meta* — which mode is up, which agents/infra are running, whether an attack
run just finished. It sets up and tears down targets, NPC flocks, and the LLM
agents; keeps the DB clean, the dashboard connected, and telemetry flowing; and
enforces token-conservation policy (stop the idle hunter; stop the hunter once an
attack run finishes) so the individual components stay free of artificial
cross-agent constraints.

## The load-bearing invariant

labctl reads signals the agents **already** emit into `soc.db` and observes OS
process state. It changes **no agent internals**. In particular the threat hunter
never learns what an "attack run" is — that cross-agent lifecycle concern lives
here, in the supervisor, not in the hunter. Signals consumed:

- **hunter idle** → `hunt_sessions.status` (`running`/`idle`/`stopped`) + `chunk_count` + `feed_cursor_id`
- **attack run finished** → `redteam_sessions.status != 'running'`
- **graceful hunter stop** → SIGTERM (the hunter finishes its in-flight chunk, compacts a handoff note, exits)

## Complement, not replace

labctl calls the canonical scripts via subprocess (cwd pinned to the repo root)
and never reimplements them. `lab-mode.sh`, `reset.sh`, `npcctl.py`/`make -C
npc-range`, and `reset_lab.py` all still work standalone.

## Stdlib-only

The manager itself imports nothing outside the stdlib (like `pipeline/ingest.py`),
so it runs without the venv. It *launches* the dashboard with the venv interpreter
and the agents with whatever interpreter `./labctl` picked (the venv, when
present — it carries the provider SDKs).

## Commands

```
# lab state (delegates to lab-mode.sh / reset.sh / npc-range)
./labctl up <mode> [dealer-target]      ./labctl down [mode]
./labctl switch <mode>                  ./labctl posture [remote|insider]
./labctl reset [reset.sh flags] [--confirm]     # --confirm required for --db/--all
./labctl clean [--db|--hunt] [--confirm]
./labctl flock up <template> [--network N] | down [flock|--all] | status

# process control (labctl owns the PID registry in .labctl/state.json)
./labctl start hunter|attacker|ingest|dashboard [--provider P --model M -- extra...]
./labctl stop <name>                    ./labctl restart <name>

# whole-lab view / supervisor
./labctl status [--json] [--no-docker]
./labctl watch [--once] [--stop-agents]
```

## The supervisor (`watch`)

A foreground loop (background it like the other daemons). Each tick, cfg is
re-read so the dashboard can flip a policy live:

1. **Keep infra alive** — ensure `ingest --follow` and the dashboard stay up.
2. **Auto-run detect** — one-shot `detect/rules.py` every `detect_interval` (there is no in-repo cron).
3. **Auto-stop idle hunter** — SIGTERM after `idle_timeout` of real idleness (`status='idle'` + empty feed + no chunk progress).
4. **Stop on attack-finish, with drain** — when a red-team run finishes, arm a drain: keep the hunter running so it catches up and finishes its analysis, then stop it once the post-attack feed goes idle, bounded by `attack_drain_max`.

The loop **never auto-starts** the hunter or attacker — spending tokens on a hunt
is an operator decision. It only keeps cheap infra alive and stops agents per
policy.

## Configuration

Defaults ← `labctl.toml` (repo root, gitignored) ← `LABCTL_*` env vars (later
wins). Keys: `poll_interval`, `detect_interval`, `idle_timeout`,
`attack_drain_max`, `stop_timeout`, `hunter_provider`, `hunter_model`, and the
`policy_keep_infra` / `policy_auto_detect` / `policy_idle_hunter` /
`policy_attack_finish` toggles. See `config.py`.

## State & reconciliation

`.labctl/state.json` is the process registry (`{name: {pid, argv, log, started,
adopted}}`); logs go to `.labctl/logs/`. Both are per-checkout and gitignored.
Every invocation runs `state.reconcile()`, which prunes dead/mismatched PIDs
(checked via `/proc/<pid>/cmdline`, requiring a python argv[0] so a shell wrapper
that merely mentions a script path isn't mistaken for the process) and **adopts**
live matching processes it didn't launch — so a hand-started hunter or the
dashboard that `reset.sh` relaunched from `/proc` is still seen and controllable.
labctl tolerates `reset.sh`'s `pkill -f` killing agents behind its back; the next
reconcile makes the registry honest again.

## Modules

- `config.py` — knobs + repo-relative paths.
- `state.py` — the `/proc`-reconciled process registry.
- `procman.py` — launch/stop/keep-alive (detached, `start_new_session`).
- `signals.py` — read-only `soc.db` reads (`mode=ro`).
- `orchestrate.py` — the single implementation of every lab action + composite `status`.
- `supervisor.py` — the `watch` policy loop.
- `__main__.py` — the CLI.
