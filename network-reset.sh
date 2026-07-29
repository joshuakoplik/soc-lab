#!/usr/bin/env bash
# Undo every block the defender's block_ip tool has ever put in place,
# restoring the soclab network to its unblocked baseline.
#
# block_ip (pipeline/triage/agent.py) is a REAL, ungated firewall action --
# see block_enforcer.py's docstring for the hard fencing that keeps it
# confined to this lab's own docker subnet. This script is the undo button:
# it removes every DOCKER-USER rule tagged with block_enforcer.RULE_COMMENT
# (and only those -- it will not touch anything else that might coexist in
# that chain) via the soc-block-enforcer container, then confirms nothing
# is left blocked.
#
#   ./network-reset.sh          -- remove every block, print what was removed
#   ./network-reset.sh --status -- just list what's currently blocked, change nothing
set -euo pipefail
cd "$(dirname "$0")"

PY="${PYTHON:-python3}"
if [ -x .venv/bin/python3 ]; then
  PY=".venv/bin/python3"
fi

if ! docker inspect -f '{{.State.Running}}' soc-block-enforcer >/dev/null 2>&1; then
  echo "[network-reset] soc-block-enforcer isn't running -- nothing to reset" >&2
  echo "  (docker compose up -d block-enforcer to bring it up)" >&2
  exit 1
fi

if [ "${1:-}" = "--status" ]; then
  echo "[network-reset] currently blocked:"
  "$PY" pipeline/triage/block_enforcer.py --list
  exit 0
fi

echo "[network-reset] removing every block_ip rule..."
"$PY" pipeline/triage/block_enforcer.py --unblock-all

echo "[network-reset] verifying baseline..."
remaining="$("$PY" pipeline/triage/block_enforcer.py --list)"
if [ "$remaining" = "[block_enforcer] nothing currently blocked" ]; then
  echo "[network-reset] confirmed: network back to baseline, nothing blocked"
else
  echo "[network-reset] WARNING: still showing as blocked after reset:" >&2
  echo "$remaining" >&2
  exit 1
fi
