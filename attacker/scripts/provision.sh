#!/usr/bin/env bash
# msfdb/postgres startup only -- the actual attack toolkit (nmap, hydra,
# sqlmap, metasploit-framework, curl, python3, ...) is baked into the image
# at build time now (see attacker/Dockerfile), not fetched here at runtime.
# soc-attacker has no internet access at all once it's up (internal: true
# per-mode networks, see pipeline/net_topology.py), so runtime apt-get was
# never going to work reliably here going forward anyway.
set -e

# postgres + schema, needed for full metasploit-framework functionality
# (db_nmap, hosts/services/creds tracking, msf's own vuln tracking). Runs
# every boot, independent of anything else: apt packages baked into the
# image survive a container restart, but there's no init system here to
# bring postgres back up on its own, so it needs restarting (cheap,
# idempotent) every time regardless.
#
# msfdb's own `status`/`start` subcommands are unreliable here: they expect
# to track postgres via systemd or a PID file THEY created, so a postgres
# instance we start with `service postgresql start` reads as "no network
# service running" even though it's genuinely up (confirmed live: `pg_isready`
# says accepting connections, `ps aux` shows the postmaster, `msfdb status`
# still says otherwise). Checking directly with pg_isready and the presence
# of msf's own database.yml sidesteps msfdb's broken self-detection instead
# of trusting it.
if ! pg_isready -q 2>/dev/null; then
  echo "[provision] starting postgresql for msfdb..."
  service postgresql start >/dev/null 2>&1
  for i in $(seq 1 15); do
    pg_isready -q 2>/dev/null && break
    sleep 1
  done
fi

if [ ! -f /usr/share/metasploit-framework/config/database.yml ]; then
  echo "[provision] initializing msfdb (first run since container creation)..."
  msfdb init >/dev/null 2>&1
  echo "[provision] msfdb ready"
fi
