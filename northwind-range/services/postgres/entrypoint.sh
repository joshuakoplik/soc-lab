#!/bin/sh
set -e
# Same nw_ops egress-lock rationale as harness/entrypoint.sh -- postgres is
# the other container dual-homed onto the one non-internal network.
iptables -A OUTPUT -o lo -j ACCEPT
iptables -A OUTPUT -d 172.28.0.0/16 -j ACCEPT
iptables -A OUTPUT -j DROP
exec docker-entrypoint.sh "$@"
