#!/bin/sh
set -e
# Deliberate, narrow exception to SPEC.md §0.1 -- see SPEC.md §4 for the
# rationale. llm-backend is the only container in this stack with any real
# egress at all, and even it can reach exactly one destination: the
# operator-configured remote Ollama host. Everything else (loopback, this
# range's own subnets for its nw_app leg) is the same allow-list shape as
# harness/entrypoint.sh and services/postgres/entrypoint.sh.
iptables -A OUTPUT -o lo -j ACCEPT
iptables -A OUTPUT -d 172.28.0.0/16 -j ACCEPT
iptables -A OUTPUT -d "${OLLAMA_UPSTREAM_HOST}" -p tcp --dport "${OLLAMA_UPSTREAM_PORT}" -j ACCEPT
iptables -A OUTPUT -j DROP
exec /docker-entrypoint.sh "$@"
