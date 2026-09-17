"""The `labctl watch` supervisor loop -- where the four token-conservation
policies live. This is the ONLY place that knows about cross-agent lifecycle;
the hunter and attacker remain ignorant of each other and of "attack runs".

Each tick (poll_interval), with cfg re-read every tick so the dashboard can flip
a policy live by rewriting labctl.toml:

  1. Keep infra alive        -- ensure ingest --follow and the dashboard are up.
  2. Auto-run detect         -- one-shot detect/rules.py every detect_interval.
  3. Auto-stop idle hunter   -- SIGTERM (graceful drain) after idle_timeout of
                                real idleness (status='idle' + empty feed +
                                chunk_count not advancing).
  4. Stop on attack-finish   -- when a red-team run finishes, DON'T kill the
                                hunter immediately; arm a drain so it catches up
                                and finishes its analysis, then stop it once the
                                post-attack feed goes idle, bounded by
                                attack_drain_max as a hard ceiling.

The loop never auto-STARTS the hunter or attacker -- spending tokens on a new
hunt is an operator decision. It only keeps the cheap infra (ingest/dashboard)
alive and stops agents per policy.
"""

import signal
import sys
import time

from . import config, models, orchestrate, procman, signals, state

_stop = False
_stop_agents_on_exit = False


def _log(msg):
    print(f"[labctl watch {time.strftime('%H:%M:%S')}] {msg}", flush=True)


def _install_signals():
    def handler(signum, frame):
        global _stop
        _stop = True
        _log(f"received signal {signum}; finishing tick then exiting")
    signal.signal(signal.SIGINT, handler)
    signal.signal(signal.SIGTERM, handler)


def run(once=False, stop_agents_on_exit=False):
    global _stop_agents_on_exit
    _stop_agents_on_exit = stop_agents_on_exit
    _install_signals()

    cfg = config.load()
    # Baseline: only react to attack runs that FINISH after we start watching.
    last_seen_redteam_id = signals.max_redteam_id()
    idle_since = None            # when the hunter first looked truly idle
    last_chunk_count = None      # to detect chunk progress
    drain_armed = False
    drain_since = None
    last_detect = 0.0
    last_models = 0.0

    _log(f"starting; policies="
         f"{{infra:{cfg['policy_keep_infra']}, detect:{cfg['policy_auto_detect']}, "
         f"idle:{cfg['policy_idle_hunter']}, attack:{cfg['policy_attack_finish']}}} "
         f"idle_timeout={cfg['idle_timeout']}s attack_drain_max={cfg['attack_drain_max']}s "
         f"redteam_baseline_id={last_seen_redteam_id}")

    while not _stop:
        cfg = config.load()
        now = time.time()
        state.reconcile()

        # 1. keep infra alive
        if cfg["policy_keep_infra"]:
            if procman.ensure("ingest", cfg=cfg):
                _log("ingest was down -> relaunched (ingest.py --follow)")
            if procman.ensure("dashboard", cfg=cfg):
                _log("dashboard was down -> relaunched (venv python, SOC_DASHBOARD_DB set)")

        # 2. auto-run detect
        if cfg["policy_auto_detect"] and (now - last_detect) >= cfg["detect_interval"]:
            res = orchestrate.detect_once()
            last_detect = now
            if res["rc"] != 0:
                _log(f"detect run rc={res['rc']}: {res['stderr'].strip()[:200]}")

        # 2b. refresh the model catalog on a long interval (models rarely change)
        if (now - last_models) >= cfg["models_refresh_interval"]:
            try:
                cat = models.refresh_catalog()
                counts = {p: len(v) for p, v in cat.get("providers", {}).items()}
                _log(f"refreshed model catalog: {counts}")
            except Exception as e:  # noqa: BLE001 - never let a refresh kill the loop
                _log(f"model catalog refresh failed: {e}")
            last_models = now

        # 3/4. hunter idle + attack-finish drain
        hs = signals.hunter_state()
        hunter_up = procman.is_up("hunter") is not None

        # detect a just-finished attack run -> arm drain
        if cfg["policy_attack_finish"]:
            finished, hw = signals.newly_finished_runs(last_seen_redteam_id)
            if finished:
                ids = ", ".join(f"#{r['id']}({r['status']})" for r in finished)
                last_seen_redteam_id = hw
                if hunter_up and not drain_armed:
                    drain_armed = True
                    drain_since = now
                    _log(f"attack run(s) finished [{ids}]; arming hunter drain "
                         f"(let it catch up, then stop when idle or after "
                         f"{cfg['attack_drain_max']}s)")
                elif not hunter_up:
                    _log(f"attack run(s) finished [{ids}]; hunter not running, nothing to drain")

        # idleness bookkeeping (only meaningful while the hunter is up)
        is_idle = False
        if hunter_up and hs is not None:
            chunk = hs.get("chunk_count")
            progressed = (last_chunk_count is not None and chunk != last_chunk_count)
            last_chunk_count = chunk
            pending = signals.pending_feed_count(hs.get("feed_cursor_id"))
            is_idle = (hs.get("status") == "idle") and pending == 0 and not progressed
            if is_idle:
                if idle_since is None:
                    idle_since = now
            else:
                idle_since = None
        else:
            idle_since = None
            last_chunk_count = None

        idle_for = (now - idle_since) if idle_since is not None else 0.0

        # decide whether to stop the hunter this tick
        stop_reason = None
        if hunter_up:
            if cfg["policy_idle_hunter"] and idle_for >= cfg["idle_timeout"]:
                stop_reason = f"idle {int(idle_for)}s >= idle_timeout"
            elif drain_armed:
                active = signals.active_attack_runs()
                if idle_for >= cfg["idle_timeout"] and not active:
                    stop_reason = f"post-attack drain complete (idle {int(idle_for)}s, no active runs)"
                elif drain_since is not None and (now - drain_since) >= cfg["attack_drain_max"]:
                    stop_reason = f"post-attack drain ceiling {int(now - drain_since)}s reached"

        if stop_reason:
            _log(f"stopping hunter: {stop_reason} (SIGTERM -> graceful drain)")
            procman.stop("hunter", cfg=cfg)
            idle_since = None
            last_chunk_count = None
            drain_armed = False
            drain_since = None

        if once:
            break
        # interruptible sleep
        slept = 0.0
        step = 0.5
        while slept < cfg["poll_interval"] and not _stop:
            time.sleep(step)
            slept += step

    _log("stopped")
    if _stop_agents_on_exit:
        for name in ("hunter", "analyst", "attacker"):
            if procman.is_up(name):
                _log(f"--stop-agents: stopping {name}")
                procman.stop(name)
    return 0
