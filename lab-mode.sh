#!/usr/bin/env bash
# Switch the lab between difficulty modes.
#
#   ./lab-mode.sh easy    -- cowrie + metasploitable up, nginx serving planted
#                             credentials, Juice Shop at default difficulty
#   ./lab-mode.sh hard    -- cowrie + metasploitable down, no leaked creds,
#                             Juice Shop hardened + network-locked, nginx is
#                             the only target
#   ./lab-mode.sh status  -- show the active mode and what's actually running
#
# Writes lab_mode.json (gitignored), which pipeline/redteam/lab_modes.py
# reads so the red-team agent's target/tool config always matches whatever
# lab-mode.sh actually brought up -- there's no separate flag to remember to
# pass, and no way for the agent to drift out of sync with reality.
set -euo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")"

MODE="${1:-status}"
STATE_FILE="lab_mode.json"
HARD_FILES=(-f compose.yaml -f compose.hard.yml)

write_state() {
  printf '{"mode": "%s", "switched_at": "%s"}\n' "$1" "$(date -u +%Y-%m-%dT%H:%M:%SZ)" > "$STATE_FILE"
}

case "$MODE" in
  easy)
    echo "[*] switching to EASY mode"
    docker compose up -d --force-recreate --remove-orphans nginx juiceshop
    docker compose --profile easy up -d cowrie metasploitable
    write_state easy
    echo "[*] easy mode active: cowrie + metasploitable up, nginx serving planted creds, Juice Shop at default difficulty"
    ;;
  hard)
    echo "[*] switching to HARD mode"
    docker compose --profile easy rm -sf cowrie metasploitable
    docker compose "${HARD_FILES[@]}" up -d --force-recreate juiceshop nginx juiceshop-netlock
    write_state hard
    echo "[*] hard mode active: cowrie + metasploitable down, no leaked creds, Juice Shop hardened + network-locked, nginx is the only target"
    ;;
  status)
    if [ -f "$STATE_FILE" ]; then
      cat "$STATE_FILE"
    else
      echo '{"mode": "unknown -- lab-mode.sh has never been run, lab is in its original (easy) config"}'
    fi
    echo
    docker compose --profile easy ps --format "table {{.Name}}\t{{.Status}}"
    ;;
  *)
    echo "usage: $0 {easy|hard|status}" >&2
    exit 1
    ;;
esac
