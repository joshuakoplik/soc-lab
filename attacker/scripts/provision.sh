#!/usr/bin/env bash
# Install the attack toolkit. Idempotent: skips if already present, so it's
# cheap to re-run and safe to call at the top of every attack script.
set -e

if command -v nmap >/dev/null 2>&1 && command -v sqlmap >/dev/null 2>&1 \
   && command -v hydra >/dev/null 2>&1 && command -v msfconsole >/dev/null 2>&1; then
  echo "[provision] toolkit already present"
else
  echo "[provision] installing attack toolkit (first run, a few minutes)..."
  export DEBIAN_FRONTEND=noninteractive
  apt-get update -q

  # Deliberately NOT kali-linux-large (multi-GB). Just what the lab uses:
  #   nmap    - discovery / port + service scan
  #   hydra   - SSH brute force against Cowrie
  #   sqlmap  - SQLi against Juice Shop
  #   metasploit-framework - real exploit/privesc modules against metasploitable,
  #                           plus the ssh_login brute module and general console
  #   lsof    - metasploit-framework depends on it for its own (unreliable in
  #             this non-systemd container -- see below) service detection
  #   curl/jq/hping3/netcat - glue and manual pokes
  #   python3/bc - any real attacker box has these; leaving them out isn't a
  #                realism choice, it's just friction. sqlmap already pulls
  #                python3 in transitively, but listing it explicitly means
  #                it's guaranteed present even if that changes -- observed
  #                live: a session that never got provisioned at all (see
  #                reset.sh's --attacker handling) had none of this, spent
  #                hours reimplementing basic HTTP/crypto in raw bash
  #                because python3/curl looked withheld on purpose rather
  #                than just missing.
  apt-get install -y --no-install-recommends \
    nmap hydra sqlmap metasploit-framework lsof \
    curl jq hping3 netcat-traditional seclists sshpass ca-certificates \
    python3 bc

  echo "[provision] done: $(nmap --version | head -1)"
fi

# --- msfdb: postgres + schema, needed for full module functionality
# (db_nmap, hosts/services/creds tracking, msf's own vuln tracking). This
# runs every time, independent of the package-install check above: apt
# packages survive a plain container restart, but there's no init system
# here to bring postgres back up on its own, so it needs restarting (cheap,
# idempotent) regardless of whether the packages were already present.
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
