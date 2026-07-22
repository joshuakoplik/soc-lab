#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")"

echo "[*] Creating log directories..."
mkdir -p logs/cowrie logs/nginx

# The classic Cowrie-in-Docker trap: the container runs as uid 1000 ("cowrie")
# and will silently fail to write its logs to a root-owned bind mount. If you
# skip this, everything looks healthy and no cowrie.json ever appears.
echo "[*] Fixing log dir ownership for Cowrie (container runs as uid 1000)..."
chmod -R 0777 logs/cowrie

echo "[*] Pulling images..."
docker compose pull

echo "[*] Starting lab..."
docker compose up -d

echo
echo "[*] Waiting for services to settle (Juice Shop takes ~20s to boot)..."
sleep 25
docker compose ps
echo
echo "    Juice Shop (via nginx):  http://localhost:8080"
echo "    Cowrie SSH:              ssh -p 2222 root@localhost   (any password, after a few tries)"
echo
echo "[*] Now run ./verify.sh to confirm telemetry is actually landing on disk."
