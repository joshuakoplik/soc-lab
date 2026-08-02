#!/usr/bin/env bash
# SPEC.md §0.3: no known-vulnerable dependency versions in any Phase 1
# image -- stronger than "the vuln chain is disabled." Runs on the host
# against already-built images (not from inside the isolated containers),
# same posture as `docker build` itself needing egress during the
# build-time bridge window.
set -uo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")/.."

if ! command -v trivy >/dev/null 2>&1; then
  echo "[FAIL] trivy is not installed. Install it first:"
  echo "  https://aquasecurity.github.io/trivy/latest/getting-started/installation/"
  echo "  (e.g. on Debian/Ubuntu: see the apt install instructions at that link)"
  exit 1
fi

IMAGES="northwind-range-edge-nginx northwind-range-chat-web northwind-range-portal-api \
northwind-range-llm-backend northwind-range-retrieval-svc northwind-range-tool-svc \
northwind-range-ingest-svc northwind-range-postgres northwind-range-harness \
northwind-range-litellm redis:7"

FAIL=0
for image in $IMAGES; do
  echo "=== $image ==="
  if trivy image --exit-code 1 --severity HIGH,CRITICAL --ignore-unfixed --quiet "$image"; then
    echo "  [PASS] no HIGH/CRITICAL fixable CVEs"
  else
    echo "  [FAIL] HIGH/CRITICAL CVEs found -- see above"
    FAIL=1
  fi
  echo
done

if [ "$FAIL" -eq 0 ]; then
  echo "=== Result: all images clean ==="
else
  echo "=== Result: at least one image has known-vulnerable dependencies -- fix before declaring this milestone done ==="
fi
exit $FAIL
