# kalilinux/kali-rolling is genuinely minimal -- confirmed live, the bare
# image has no curl, no iptables, no ip/ifconfig, nothing beyond apt itself
# (~95 packages). Everything soc-attacker needs (nmap, hydra, sqlmap,
# metasploit, curl, ...) is baked in here at BUILD time, not fetched at
# runtime by provision.sh the way it used to be.
#
# That used to be a chicken-and-egg problem: the container's own runtime
# egress lockdown (applied via iptables inside this container's netns)
# meant apt-get couldn't reach the internet once it was up, so only
# iproute2/iptables (needed to build/apply that lockdown at all) got baked
# in here, and everything else had to be fetched at runtime BEFORE the
# lockdown went up, in a specific order the old comments here warned about
# getting backwards. That ordering hazard doesn't exist anymore: soc-attacker
# now lives entirely on `internal: true` per-mode networks (see
# pipeline/net_topology.py) -- egress is blocked structurally at the network
# layer, permanently, with nothing runtime-applied to get sequenced around.
# `docker build` still runs on the HOST via the docker daemon's own network
# access, independent of whatever lab networks the eventual container joins,
# so this is still the one place internet access is available at all -- now
# used for the whole toolkit instead of just two packages.
#
# Recreating this container (docker compose up --force-recreate, or any
# rebuild) wipes anything provision.sh used to install at runtime -- that's
# no longer a concern for the toolkit itself (it's part of the image now),
# only for msfdb/postgres state, which provision.sh still (cheaply,
# idempotently) reinitializes every boot -- see that script.
# john + a PLAINTEXT rockyou are here because the red-team agent's background
# hash-cracking jobs (pipeline/redteam/jobs.py) run `john --wordlist=...` inside
# this container -- advertised in the agent's prompt all along, but the binary
# was never actually installed until this. `wordlists` ships rockyou GZIPPED at
# /usr/share/wordlists/rockyou.txt.gz; jobs.py defaults to the decompressed
# path, so gunzip it once at build time (the container is air-gapped at runtime,
# so this can't be a lazy first-run step). A rebuild (./reset.sh --attacker) is
# required to pick john up.
FROM kalilinux/kali-rolling:latest
RUN apt-get update && \
    apt-get install -y --no-install-recommends \
      iproute2 iptables \
      nmap hydra sqlmap metasploit-framework lsof john wordlists \
      curl jq hping3 netcat-traditional seclists sshpass ca-certificates \
      python3 python3-pip bc && \
    ( [ -f /usr/share/wordlists/rockyou.txt ] || \
      gunzip -kf /usr/share/wordlists/rockyou.txt.gz 2>/dev/null || true ) && \
    rm -rf /var/lib/apt/lists/*
