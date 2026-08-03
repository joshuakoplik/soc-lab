#!/bin/sh
set -e
# edge-nginx is dual-homed onto nw_ops (non-internal, needed so its
# operator-requested Tailscale port publish actually works -- Docker
# doesn't forward published ports for a container whose only networks are
# internal:true, confirmed empirically). Same per-container iptables
# allow-list shape as harness/entrypoint.sh and services/postgres/
# entrypoint.sh, plus one addition those two don't need: the
# ESTABLISHED,RELATED rule, so *replies* to inbound connections on the
# published Tailscale port can actually leave (that return traffic exits
# via the tailscale0 interface, not loopback or 172.28.0.0/16 -- without
# this rule the container answers nothing and every published-port
# connection just times out, confirmed empirically). This does not weaken
# "no egress": a brand-new outbound connection this container tries to
# *initiate* still starts in NEW state, which only the 172.28.0.0/16 rule
# below can match -- everything else still hits the default DROP.
iptables -A OUTPUT -o lo -j ACCEPT
iptables -A OUTPUT -m state --state ESTABLISHED,RELATED -j ACCEPT
iptables -A OUTPUT -d 172.28.0.0/16 -j ACCEPT
iptables -A OUTPUT -j DROP
exec /docker-entrypoint.sh "$@"
