#!/usr/bin/env bash
# Switch the lab between difficulty modes.
#
#   ./lab-mode.sh easy     -- cowrie + metasploitable up, nginx serving planted
#                             credentials, Juice Shop at default difficulty
#   ./lab-mode.sh hard     -- cowrie + metasploitable down, no leaked creds,
#                             Juice Shop hardened + network-locked, nginx is
#                             the only target
#   ./lab-mode.sh wordpress -- everything else down, only the wordpress target
#                             (WordPress core pinned to the CVE-2026-63030 /
#                             CVE-2026-60137 chain) up -- see
#                             wordpress/README. A single-target
#                             scenario, not a rung on the easy/hard ladder.
#   ./lab-mode.sh status   -- show the active mode and what's actually running
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
  wordpress)
    echo "[*] switching to WORDPRESS mode"
    docker compose --profile easy rm -sf cowrie metasploitable
    docker compose rm -sf nginx juiceshop
    docker compose --profile wordpress up -d wordpress-db wordpress wordpress-init wordpress-netlock
    write_state wordpress
    echo "[*] wordpress mode active: only the wordpress target is up -- reach it from soc-attacker as http://wordpress. See wordpress/README."
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
    echo "usage: $0 {easy|hard|wordpress|status}" >&2
    exit 1
    ;;
esac
