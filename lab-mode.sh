#!/usr/bin/env bash
# Bring lab modes up and down. Since each mode now lives on its own network
# (see pipeline/net_topology.py) instead of one shared bridge, modes can
# coexist -- this is no longer just a "switch to X" toggle.
#
#   ./lab-mode.sh bootstrap        -- idempotent: create the 3 per-mode networks if missing.
#                                      Every verb below runs this first on its own; call it
#                                      directly only if you want the networks up with nothing
#                                      else changed.
#   ./lab-mode.sh up <mode>        -- bring that mode's target containers up. Other modes'
#                                      containers, if any are running, are left alone. Also
#                                      sets lab_mode.json's PRIMARY mode -- the one
#                                      pipeline/redteam/lab_modes.py gates tool access against.
#   ./lab-mode.sh down <mode>      -- tear that mode's target containers down. Other modes
#                                      untouched. Warns loudly (doesn't refuse) if you tear
#                                      down the current primary mode -- lab_mode.json still
#                                      points at it, so the red-team agent's target allowlist
#                                      would be pointing at nothing running until you `up`
#                                      something else.
#   ./lab-mode.sh switch <mode>    -- down every OTHER mode, then up <mode> -- today's old
#                                      mutually-exclusive behavior, kept as a convenience.
#   ./lab-mode.sh easy|hard|wordpress
#                                   -- bare aliases for `switch <mode>`, for backward
#                                      compatibility with existing muscle memory/docs.
#   ./lab-mode.sh status           -- lab_mode.json's primary mode, plus live docker state
#                                      for ALL three modes (not just the primary one).
#
# modes: easy (cowrie + metasploitable + juiceshop-easy + nginx-easy, planted creds),
#        hard (juiceshop-hard + nginx-hard, hardened + network-locked, no leaked creds),
#        wordpress (real WordPress core pinned to CVE-2026-63030/CVE-2026-60137 -- see
#                   wordpress/README, a single-target scenario, not a difficulty rung).
#
# Writes lab_mode.json (gitignored), which pipeline/redteam/lab_modes.py reads so the
# red-team agent's target/tool config always matches whichever mode is PRIMARY -- there's
# no separate flag to remember to pass, and no way for the agent to drift out of sync with
# that. lab_mode.json only ever names ONE primary mode even when multiple are physically
# running -- the agent still targets exactly one mode's targets per campaign; coexistence is
# about the underlying INFRASTRUCTURE not being mutually exclusive anymore, not about a
# single campaign attacking multiple modes at once (a separate, bigger feature this doesn't
# attempt).
set -euo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")"

PY="${PYTHON:-python3}"
if [ -x .venv/bin/python3 ]; then
  PY=".venv/bin/python3"
fi

STATE_FILE="lab_mode.json"
VERB="${1:-status}"
MODE="${2:-}"

write_state() {
  printf '{"mode": "%s", "switched_at": "%s"}\n' "$1" "$(date -u +%Y-%m-%dT%H:%M:%SZ)" > "$STATE_FILE"
}

current_mode() {
  if [ -f "$STATE_FILE" ]; then
    "$PY" -c "import json; print(json.load(open('$STATE_FILE')).get('mode','unknown'))" 2>/dev/null || echo unknown
  else
    echo "(none set -- lab_mode.json has never been written)"
  fi
}

bootstrap() {
  "$PY" pipeline/net_topology.py --bootstrap
}

mode_up() {
  case "$1" in
    easy)
      docker compose --profile easy up -d cowrie metasploitable juiceshop-easy nginx-easy
      ;;
    hard)
      docker compose --profile hard up -d juiceshop-hard nginx-hard juiceshop-netlock
      ;;
    wordpress)
      docker compose --profile wordpress up -d wordpress-db wordpress wordpress-init wordpress-netlock
      ;;
    *)
      echo "usage: $0 up {easy|hard|wordpress}" >&2
      exit 1
      ;;
  esac
}

mode_down() {
  case "$1" in
    easy)
      docker compose --profile easy rm -sf cowrie metasploitable juiceshop-easy nginx-easy
      ;;
    hard)
      docker compose --profile hard rm -sf juiceshop-hard nginx-hard juiceshop-netlock
      ;;
    wordpress)
      docker compose --profile wordpress rm -sf wordpress wordpress-init wordpress-netlock wordpress-db
      ;;
    *)
      echo "usage: $0 down {easy|hard|wordpress}" >&2
      exit 1
      ;;
  esac
}

case "$VERB" in
  bootstrap)
    bootstrap
    echo "[*] all three per-mode networks exist (soclab-easy/hard/wordpress)"
    ;;
  up)
    [ -n "$MODE" ] || { echo "usage: $0 up {easy|hard|wordpress}" >&2; exit 1; }
    bootstrap
    echo "[*] bringing $MODE mode up (other modes, if running, are left alone)"
    mode_up "$MODE"
    write_state "$MODE"
    echo "[*] $MODE mode up; lab_mode.json primary mode set to $MODE"
    ;;
  down)
    [ -n "$MODE" ] || { echo "usage: $0 down {easy|hard|wordpress}" >&2; exit 1; }
    echo "[*] tearing $MODE mode down (other modes, if running, are left alone)"
    mode_down "$MODE"
    if [ "$(current_mode)" = "$MODE" ]; then
      echo "[!] $MODE was the PRIMARY mode -- lab_mode.json still points at it, so the" >&2
      echo "    red-team agent's target allowlist now points at nothing running. Run" >&2
      echo "    '$0 up <mode>' to set a new primary before starting a campaign." >&2
    fi
    echo "[*] $MODE mode down"
    ;;
  switch)
    [ -n "$MODE" ] || { echo "usage: $0 switch {easy|hard|wordpress}" >&2; exit 1; }
    bootstrap
    echo "[*] switching to $MODE mode (tearing down every other mode first)"
    for other in easy hard wordpress; do
      [ "$other" = "$MODE" ] && continue
      mode_down "$other" 2>/dev/null || true
    done
    mode_up "$MODE"
    write_state "$MODE"
    echo "[*] $MODE mode active (exclusively)"
    ;;
  easy|hard|wordpress)
    # Bare mode name: back-compat alias for `switch <mode>`.
    exec "$0" switch "$VERB"
    ;;
  status)
    echo "primary mode: $(current_mode)"
    echo
    docker compose --profile easy --profile hard --profile wordpress ps --format "table {{.Name}}\t{{.Status}}"
    ;;
  *)
    echo "usage: $0 {bootstrap|up|down|switch|status|easy|hard|wordpress} [mode]" >&2
    exit 1
    ;;
esac
