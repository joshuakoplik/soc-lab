# kalilinux/kali-rolling is genuinely minimal -- confirmed live, the bare
# image has no curl, no iptables, no ip/ifconfig, nothing beyond apt itself
# (~95 packages). Everything soc-attacker actually uses day to day (nmap,
# hydra, sqlmap, metasploit, curl, ...) comes from attacker/scripts/provision.sh
# at container runtime instead, on purpose -- see that script's own comments.
#
# iproute2 and iptables are the two exceptions, baked in at BUILD time here
# rather than left to provision.sh, because of a chicken-and-egg problem:
# the container's own runtime egress lockdown (loopback + 10.211.0.0/24
# only -- see CLAUDE.md, applied via `iptables` right in this container's
# netns, NOT the host's) means that once it's in place, apt-get can't reach
# the internet to install anything at all. iproute2 (`ip addr` -- needed by
# rotate_ip(), pipeline/redteam/executor.py) and iptables (the lockdown
# tool itself) both have to already exist before that lockdown goes up.
# `docker build` runs on the HOST via the docker daemon's own network
# access, entirely before the eventual container (and its egress lock)
# exists, so this is the one place both can land reliably.
#
# IMPORTANT: recreating this container (docker compose up --force-recreate,
# or any full rebuild) wipes BOTH the egress lockdown (lives in this
# container's own netns, not persisted anywhere) AND the provisioned
# toolkit (installed into the writable layer at runtime by provision.sh,
# also not persisted). After any recreation: run
# `docker exec -it soc-attacker /scripts/provision.sh` first (needs the
# still-open egress from a fresh container), THEN reapply the lockdown --
# see attacker/README's "Egress lockdown" section for the exact commands.
# Doing it in the other order locks out provisioning entirely.
FROM kalilinux/kali-rolling:latest
RUN apt-get update && \
    apt-get install -y --no-install-recommends iproute2 iptables && \
    rm -rf /var/lib/apt/lists/*
