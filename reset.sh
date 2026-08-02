#!/usr/bin/env bash
# Reset the lab back to a clean baseline: undo every block_ip firewall rule,
# wipe soc.db, and/or reseed the ingest queue so old log backlog doesn't
# flood back in as "new" candidates. Successor to network-reset.sh, which
# only ever did the network part -- everything it did is still here under
# --network.
#
#   ./reset.sh                    -- reset everything: network + db + queue + attacker + target (default)
#   ./reset.sh --network          -- only undo block_ip rules
#   ./reset.sh --db               -- only wipe soc.db and recreate empty schema
#   ./reset.sh --queue            -- only reseed tail_state to each log's current EOF
#   ./reset.sh --attacker         -- only rebuild soc-attacker and clear attacker/loot
#   ./reset.sh --target           -- only rebuild the active lab-mode's target container(s)
#   ./reset.sh --network --queue  -- combine any subset
#   ./reset.sh --status           -- report current state of all three, change nothing
#   ./reset.sh --no-kill          -- modifier: don't kill running pipeline processes first
#
# --db and --queue are independent on purpose (see pipeline/reset_lab.py's
# docstring for why a --db wipe without --queue leaves the next `ingest.py
# --follow` about to replay the entire on-disk log history back in as a
# fresh backlog) but the default (no flags) always does all five together,
# so plain `./reset.sh` always leaves the lab in a state where nothing is
# blocked, the db is empty, the queue is caught up, the attacker box is
# back to a clean image, AND the target itself is back to a clean install
# -- see --attacker and --target below for why those last two matter as
# much as the other three, not just a nice-to-have.
#
# --attacker: soc-attacker (compose.yaml) has no volume over /tmp, /root,
# or anywhere else in its own filesystem -- only /scripts (ro) and /loot
# are mounted -- so its writable layer just accumulates forever across
# EVERY campaign ever run against it, "fresh" or not: old exploit scripts,
# extracted hashes, wordlists, partially-cracked credential files, all
# still sitting in /tmp for a later session to stumble onto and reuse.
# Observed live: a session credited with independently rebuilding a whole
# exploit chain had actually grepped a hash out of a wp2shell_extract2.py
# file left over from a session three days earlier -- silently
# contaminating how much of that "success" was actually earned fresh vs.
# recycled. `docker compose up -d --force-recreate attacker` throws away
# that writable layer and starts clean from the image; attacker/loot is a
# HOST bind mount, not part of the container's own filesystem, so
# recreating the container alone doesn't touch it -- cleared explicitly
# too (loot is generated/regenerable by design, see .gitignore).
#
# --target: the mirror-image bug, on the TARGET side. Most targets here
# (cowrie, metasploitable, juiceshop, nginx) have no named volume either,
# so a plain `--force-recreate` already resets them fully -- done here for
# consistency, not because they were ever actually a problem. wordpress
# mode is the real case: wordpress-html and wordpress-db-data ARE named
# volumes (compose.yaml), so they survive a force-recreate exactly like
# soc-attacker's writable layer used to -- any webshell uploaded, plugin
# installed, or database row changed by an attacker session (a cracked
# admin password, injected content via the SQLi chain) is still there for
# the next "fresh" session to find. Confirmed live: the wordpress
# container was still the SAME one from 9 hours and several "reset and
# start from scratch" campaigns earlier, because nothing before this flag
# ever actually removed it. --target reads lab_mode.json (same source of
# truth lab-mode.sh writes and pipeline/redteam/lab_modes.py reads) so it
# rebuilds whichever target is actually active without needing a separate
# flag to remember to pass, same reasoning as lab_mode.json's own role
# elsewhere in this codebase. For wordpress specifically this removes the
# wordpress/wordpress-db/wordpress-netlock containers AND the two named
# volumes, then rebuilds the image and re-runs wordpress-init -- a truly
# fresh WP install, fresh DB, fresh admin password, fresh flags, every
# time, not just a fresh container wrapped around old state.
#
# --db/--queue reset while ingest.py/detect/rules.py/triage/agent.py/
# redteam/agent.py are still running would race their open connections
# against the file being removed out from under them, so any db-touching
# reset kills those process patterns first, unless --no-kill is passed.
#
# dashboard/server.py is different from the four processes above: it's meant
# to be left running continuously across many resets, not restarted by hand
# each time -- but a --db wipe unlinks-and-recreates soc.db (see
# pipeline/reset_lab.py's reset_db()), which strands its long-lived poll
# loop's read connection on the old, now-detached file (dashboard/server.py's
# _db_identity() is supposed to catch this and reconnect on its own, but a
# process that's lived through many resets in a row has been observed to end
# up in a state where that stops actually broadcasting new rows even though
# _db_identity() itself isn't flapping -- root cause unresolved, a restart
# reliably clears it). So --db kills and relaunches it too, if one was
# already running, preserving whatever SOC_DASHBOARD_* env it was started
# with (host/port/db path) by reading them straight out of /proc before
# killing it, rather than guessing or dropping back to defaults.
set -euo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")"

PY="${PYTHON:-python3}"
if [ -x .venv/bin/python3 ]; then
  PY=".venv/bin/python3"
fi

DO_NETWORK=0
DO_DB=0
DO_QUEUE=0
DO_ATTACKER=0
DO_TARGET=0
DO_STATUS=0
KILL_FIRST=1
ANY_FLAG=0

for arg in "$@"; do
  case "$arg" in
    --network)  DO_NETWORK=1;  ANY_FLAG=1 ;;
    --db)       DO_DB=1;       ANY_FLAG=1 ;;
    --queue)    DO_QUEUE=1;    ANY_FLAG=1 ;;
    --attacker) DO_ATTACKER=1; ANY_FLAG=1 ;;
    --target)   DO_TARGET=1;   ANY_FLAG=1 ;;
    --all)      DO_NETWORK=1; DO_DB=1; DO_QUEUE=1; DO_ATTACKER=1; DO_TARGET=1; ANY_FLAG=1 ;;
    --status)   DO_STATUS=1 ;;
    --no-kill)  KILL_FIRST=0 ;;
    *)
      echo "usage: $0 [--all] [--network] [--db] [--queue] [--attacker] [--target] [--status] [--no-kill]" >&2
      exit 1
      ;;
  esac
done

if [ "$DO_STATUS" = "1" ]; then
  if docker inspect -f '{{.State.Running}}' soc-block-enforcer >/dev/null 2>&1; then
    echo "[reset] currently blocked:"
    "$PY" pipeline/triage/block_enforcer.py --list
  else
    echo "[reset] soc-block-enforcer isn't running -- can't report block status" >&2
  fi
  echo
  "$PY" pipeline/reset_lab.py --status
  exit 0
fi

if [ "$ANY_FLAG" = "0" ]; then
  DO_NETWORK=1
  DO_DB=1
  DO_QUEUE=1
  DO_ATTACKER=1
  DO_TARGET=1
fi

if [ "$KILL_FIRST" = "1" ] && { [ "$DO_DB" = "1" ] || [ "$DO_QUEUE" = "1" ] || [ "$DO_ATTACKER" = "1" ] || [ "$DO_TARGET" = "1" ]; }; then
  echo "[reset] stopping any running pipeline processes first..."
  for pattern in "pipeline/ingest.py" "pipeline/detect/rules.py" "pipeline/triage/agent.py" "pipeline/redteam/agent.py"; do
    pkill -f "$pattern" 2>/dev/null && echo "    killed: $pattern" || true
  done
fi

if [ "$DO_ATTACKER" = "1" ]; then
  echo "[reset] rebuilding soc-attacker (clears its own filesystem -- old exploit"
  echo "        scripts, extracted hashes, wordlists, anything a prior session left"
  echo "        in /tmp) and clearing attacker/loot..."
  find attacker/loot -mindepth 1 -delete 2>/dev/null || true
  # --build, not just --force-recreate: force-recreate alone reuses whatever
  # image is already on disk, which silently goes stale the moment
  # attacker/Dockerfile changes -- confirmed live, an image built hours
  # before a Dockerfile edit came back missing iptables entirely on
  # recreate, with no error, no warning.
  docker compose build attacker
  docker compose up -d --force-recreate attacker
  # Neither the provisioned toolkit (nmap/hydra/sqlmap/msf/curl/python3/...,
  # see provision.sh) nor the egress lockdown below survive a recreate --
  # both live only in the container's own writable layer/netns, on purpose
  # (see attacker/README's "Egress lockdown" section), which means a fresh
  # container is BOTH unprovisioned AND unlocked until both of these run,
  # in this exact order (provision needs real egress; the lockdown then
  # removes it). Skipping this step was a real, silent bug here before:
  # a session ran for hours against a container with no toolkit at all
  # (reduced to raw bash /dev/tcp for everything) that was ALSO not
  # actually locked down the whole time, since neither step ever ran.
  echo "[reset] provisioning soc-attacker's toolkit (nmap/hydra/sqlmap/msf/curl/python3/...)..."
  docker exec soc-attacker bash /scripts/provision.sh
  echo "[reset] reapplying soc-attacker's egress lockdown (loopback + every lab subnet only)..."
  # One ACCEPT per lab network now, not the single 10.211.0.0/24 this used
  # to be -- soc-attacker is multi-homed across all three (see
  # pipeline/net_topology.py, compose.yaml). Reads the subnet list from
  # net_topology.py rather than hardcoding it a second time here.
  docker exec soc-attacker iptables -F OUTPUT
  docker exec soc-attacker iptables -A OUTPUT -o lo -j ACCEPT
  while read -r subnet; do
    docker exec soc-attacker iptables -A OUTPUT -d "$subnet" -j ACCEPT
  done < <("$PY" pipeline/net_topology.py --subnets)
  docker exec soc-attacker iptables -A OUTPUT -m state --state RELATED,ESTABLISHED -j ACCEPT
  docker exec soc-attacker iptables -A OUTPUT -j DROP
  # Verify rather than trust -- a silent failure here is exactly the
  # "shell_exec has no other containment" scenario CLAUDE.md warns about.
  # curl exits nonzero (28) on the timeout a working lockdown produces, which
  # is the EXPECTED outcome here, not a failure -- `|| true` only silences
  # set -e for that expected nonzero status; it must not echo anything,
  # since curl's -w already printed "000" to stdout on its own and a
  # fallback echo would concatenate onto it (confirmed live: an earlier
  # version of this check read "000FAIL" and reported the lockdown broken
  # when it was actually working correctly).
  REAL_NET="$(docker exec soc-attacker curl -m 5 -s -o /dev/null -w '%{http_code}' http://1.1.1.1/ 2>/dev/null)" || true
  # No single "is the lab still reachable" spot check here anymore -- which
  # target is up is mode-dependent under coexistence (see lab-mode.sh),
  # unlike the single always-there wordpress check this used to be able to
  # assume. --target below (or lab-mode.sh status) is the place to confirm
  # a specific mode's own reachability.
  if [ "$REAL_NET" != "000" ]; then
    echo "    [!] EGRESS LOCKDOWN NOT WORKING: real internet returned http_code=$REAL_NET (expected 000/hang)" >&2
    exit 1
  fi
  echo "[reset] soc-attacker rebuilt, provisioned, and locked down (real internet: $REAL_NET); attacker/loot cleared"
fi

if [ "$DO_TARGET" = "1" ]; then
  LAB_MODE="$("$PY" -c "
import json
try:
    print(json.load(open('lab_mode.json'))['mode'])
except Exception:
    print('unknown')
" 2>/dev/null || echo unknown)"
  case "$LAB_MODE" in
    wordpress)
      echo "[reset] rebuilding the wordpress target clean -- wordpress-html and"
      echo "        wordpress-db-data are named volumes, so unlike a stateless"
      echo "        target a plain force-recreate would leave whatever the last"
      echo "        session uploaded, installed, or changed in the DB still there..."
      docker compose --profile wordpress rm -sf wordpress wordpress-init wordpress-netlock wordpress-db
      docker volume rm -f soc-lab_wordpress-html soc-lab_wordpress-db-data >/dev/null 2>&1 || true
      docker compose --profile wordpress up -d --build --force-recreate \
        wordpress-db wordpress wordpress-init wordpress-netlock
      echo "[reset] wordpress target rebuilt clean: fresh image layer, fresh DB, fresh WP install"
      ;;
    easy)
      echo "[reset] recreating easy-mode target containers (no named volumes on"
      echo "        these -- force-recreate alone is already a full reset, done"
      echo "        here for consistency with --attacker/--target above)..."
      docker compose --profile easy up -d --force-recreate --remove-orphans \
        cowrie metasploitable juiceshop-easy nginx-easy
      ;;
    hard)
      echo "[reset] recreating hard-mode target containers (no named volumes on"
      echo "        these -- force-recreate alone is already a full reset, done"
      echo "        here for consistency with --attacker/--target above)..."
      docker compose --profile hard up -d --force-recreate --remove-orphans \
        juiceshop-hard nginx-hard juiceshop-netlock
      ;;
    *)
      echo "[reset] lab_mode.json missing or unrecognized ($LAB_MODE) -- skipping target rebuild" >&2
      echo "  (run ./lab-mode.sh {easy|hard|wordpress} first)" >&2
      ;;
  esac
fi

if [ "$DO_NETWORK" = "1" ]; then
  if ! docker inspect -f '{{.State.Running}}' soc-block-enforcer >/dev/null 2>&1; then
    echo "[reset] soc-block-enforcer isn't running -- skipping network reset" >&2
    echo "  (docker compose up -d block-enforcer to bring it up)" >&2
  else
    echo "[reset] removing every block_ip rule..."
    "$PY" pipeline/triage/block_enforcer.py --unblock-all
    remaining="$("$PY" pipeline/triage/block_enforcer.py --list)"
    if [ "$remaining" = "[block_enforcer] nothing currently blocked" ]; then
      echo "[reset] confirmed: network back to baseline, nothing blocked"
    else
      echo "[reset] WARNING: still showing as blocked after reset:" >&2
      echo "$remaining" >&2
      exit 1
    fi
  fi
fi

if [ "$DO_DB" = "1" ]; then
  echo "[reset] wiping soc.db..."
  "$PY" pipeline/reset_lab.py --db

  DASH_PID="$(pgrep -f 'dashboard/server\.py' | head -1 || true)"
  if [ -n "$DASH_PID" ]; then
    echo "[reset] dashboard server is running (pid $DASH_PID) -- its live-push connection"
    echo "        goes stale across a db wipe, restarting it with the same env AND the"
    echo "        same interpreter it had -- NOT necessarily this worktree's own \$PY:"
    echo "        the dashboard is commonly launched from a different checkout's venv"
    echo "        (e.g. the main checkout's .venv, which has fastapi/uvicorn installed)"
    echo "        pointed at THIS worktree's soc.db via SOC_DASHBOARD_DB. Re-deriving"
    echo "        \$PY fresh here instead of reusing the original process's own"
    echo "        interpreter silently launches a python3 that's missing fastapi and"
    echo "        dies instantly with nothing captured (output was going to /dev/null) --"
    echo "        observed live. argv[0] from /proc/<pid>/cmdline is what was actually"
    echo "        invoked -- NOT /proc/<pid>/exe, which resolves through the venv's"
    echo "        bin/python3 symlink to the bare system interpreter and loses the"
    echo "        venv's sys.path entirely (also observed live, while fixing this)."
    DASH_ENV="$(tr '\0' '\n' < "/proc/$DASH_PID/environ" 2>/dev/null | grep '^SOC_DASHBOARD_' || true)"
    DASH_PY="$(tr '\0' '\n' < "/proc/$DASH_PID/cmdline" 2>/dev/null | head -1 || true)"
    if [ ! -x "$DASH_PY" ]; then
      echo "    [!] couldn't read the original interpreter from /proc -- falling back to \$PY ($PY)" >&2
      DASH_PY="$PY"
    fi
    pkill -f 'dashboard/server\.py' 2>/dev/null && echo "    killed: dashboard/server.py" || true
    sleep 1
    env $DASH_ENV nohup "$DASH_PY" dashboard/server.py > /dev/null 2>&1 &
    disown
    echo "    dashboard server restarted (pid $!, interpreter: $DASH_PY)"
  fi
fi

if [ "$DO_QUEUE" = "1" ]; then
  echo "[reset] reseeding ingest queue..."
  "$PY" pipeline/reset_lab.py --queue
fi
