#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")"

# Host bindings come from .env (see .env.example) so this script always
# prints/probes the ports compose.yaml actually published. LAB_BIND_IP may be
# 0.0.0.0 (bind-all), which is not a connectable address -- use loopback to
# talk to it in that case.
set -a; [ -f .env ] && . ./.env; set +a
LAB_BIND_IP="${LAB_BIND_IP:-127.0.0.1}"
LAB_NGINX_EASY_PORT="${LAB_NGINX_EASY_PORT:-8082}"
LAB_COWRIE_SSH_PORT="${LAB_COWRIE_SSH_PORT:-2222}"
case "$LAB_BIND_IP" in 0.0.0.0|::|"") LAB_HOST=127.0.0.1 ;; *) LAB_HOST="$LAB_BIND_IP" ;; esac

echo "[*] Ensuring per-mode lab networks exist (soclab-easy/hard/wordpress)..."
python3 pipeline/net_topology.py --bootstrap

echo "[*] Creating log directories..."
mkdir -p logs/cowrie logs/nginx

# The classic Cowrie-in-Docker trap: the container runs as uid 1000 ("cowrie")
# and will silently fail to write its logs to a root-owned bind mount. If you
# skip this, everything looks healthy and no cowrie.json ever appears.
echo "[*] Fixing log dir ownership for Cowrie (container runs as uid 1000)..."
chmod -R 0777 logs/cowrie

echo "[*] Pulling images..."
docker compose pull

echo "[*] Starting lab (baseline infra + easy mode)..."
# --profile easy: nginx/juiceshop are always-defined per-mode services now
# (see compose.yaml, lab-mode.sh), each gated by its own profile -- a bare
# `docker compose up -d` with no profile brings up only the always-on
# baseline (attacker/block-enforcer/suricata/wazuh), no targets at all.
# `./lab-mode.sh up hard`/`up wordpress` bring up the other modes
# alongside this one; `./lab-mode.sh switch <mode>` replaces it entirely.
docker compose --profile easy up -d

echo
echo "[*] Waiting for services to settle (Juice Shop takes ~20s to boot)..."
sleep 25
docker compose ps
echo
echo "    Juice Shop (via nginx):  http://${LAB_HOST}:${LAB_NGINX_EASY_PORT}"
echo "    Cowrie SSH:              ssh -p ${LAB_COWRIE_SSH_PORT} root@${LAB_HOST}   (any password, after a few tries)"
echo
echo "[*] Now run ./verify.sh to confirm telemetry is actually landing on disk."
