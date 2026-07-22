#!/usr/bin/env bash
# Full run: web + SSH from one source IP, close enough in time that the
# cross_source_activity rule correlates them into a single high-severity
# candidate. This is the money demo for the agent.
set -e
/scripts/provision.sh
echo "############ WEB ############";  /scripts/attack-web.sh
echo "############ SSH ############";  /scripts/attack-cowrie.sh
echo
echo "Both phases done from one attacker IP. On the host:"
echo "  python3 pipeline/ingest.py && python3 pipeline/rules.py --all"
echo "Then look for a cross_source_activity candidate spanning all four sources."
