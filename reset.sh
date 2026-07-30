#!/usr/bin/env bash
# Reset the lab back to a clean baseline: undo every block_ip firewall rule,
# wipe soc.db, and/or reseed the ingest queue so old log backlog doesn't
# flood back in as "new" candidates. Successor to network-reset.sh, which
# only ever did the network part -- everything it did is still here under
# --network.
#
#   ./reset.sh                    -- reset everything: network + db + queue (default)
#   ./reset.sh --network          -- only undo block_ip rules
#   ./reset.sh --db               -- only wipe soc.db and recreate empty schema
#   ./reset.sh --queue            -- only reseed tail_state to each log's current EOF
#   ./reset.sh --network --queue  -- combine any subset
#   ./reset.sh --status           -- report current state of all three, change nothing
#   ./reset.sh --no-kill          -- modifier: don't kill running pipeline processes first
#
# --db and --queue are independent on purpose (see pipeline/reset_lab.py's
# docstring for why a --db wipe without --queue leaves the next `ingest.py
# --follow` about to replay the entire on-disk log history back in as a
# fresh backlog) but the default (no flags) always does both together, plus
# --network, so plain `./reset.sh` always leaves the lab in a state where
# nothing is blocked, the db is empty, and the queue is caught up.
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
DO_STATUS=0
KILL_FIRST=1
ANY_FLAG=0

for arg in "$@"; do
  case "$arg" in
    --network) DO_NETWORK=1; ANY_FLAG=1 ;;
    --db)      DO_DB=1;      ANY_FLAG=1 ;;
    --queue)   DO_QUEUE=1;   ANY_FLAG=1 ;;
    --all)     DO_NETWORK=1; DO_DB=1; DO_QUEUE=1; ANY_FLAG=1 ;;
    --status)  DO_STATUS=1 ;;
    --no-kill) KILL_FIRST=0 ;;
    *)
      echo "usage: $0 [--all] [--network] [--db] [--queue] [--status] [--no-kill]" >&2
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
fi

if [ "$KILL_FIRST" = "1" ] && { [ "$DO_DB" = "1" ] || [ "$DO_QUEUE" = "1" ]; }; then
  echo "[reset] stopping any running pipeline processes first..."
  for pattern in "pipeline/ingest.py" "pipeline/detect/rules.py" "pipeline/triage/agent.py" "pipeline/redteam/agent.py"; do
    pkill -f "$pattern" 2>/dev/null && echo "    killed: $pattern" || true
  done
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
    echo "        goes stale across a db wipe, restarting it with the same env it had..."
    DASH_ENV="$(tr '\0' '\n' < "/proc/$DASH_PID/environ" 2>/dev/null | grep '^SOC_DASHBOARD_' || true)"
    pkill -f 'dashboard/server\.py' 2>/dev/null && echo "    killed: dashboard/server.py" || true
    sleep 1
    env $DASH_ENV nohup "$PY" dashboard/server.py > /dev/null 2>&1 &
    disown
    echo "    dashboard server restarted (pid $!)"
  fi
fi

if [ "$DO_QUEUE" = "1" ]; then
  echo "[reset] reseeding ingest queue..."
  "$PY" pipeline/reset_lab.py --queue
fi
