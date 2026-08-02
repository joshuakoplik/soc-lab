#!/bin/sh
set -e
# nw_ops is this compose project's one non-internal network (needed so its
# host port can publish -- see docker-compose.yml's comment on the harness
# service). That means containers attached to it get a real default route
# out unless something blocks it here. Lock egress to loopback + this
# range's own subnets only, same per-container-iptables pattern the parent
# soc-lab uses for soc-attacker.
iptables -A OUTPUT -o lo -j ACCEPT
iptables -A OUTPUT -d 172.28.0.0/16 -j ACCEPT
iptables -A OUTPUT -j DROP
exec "$@"
