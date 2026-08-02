---
tenant: riverside
department: Engineering
label: internal
title: API Gateway Outage Runbook
shares: []
contains_pii: false
contains_credential: false
---

# API Gateway Outage Runbook

**Owner:** Engineering — Platform Team | **Last updated:** March 12, 2025 | **Next review:** June 2025

## Scope
This runbook covers outages of Kong, our API gateway (cluster `kong-prod` in EKS, us-east-1), which fronts all external traffic: the customer shipment-tracking API, the carrier rating API, driver mobile app sync, and EDI 214 status webhook delivery to shipper TMS systems. Internal service-to-service traffic does not traverse the gateway.

## Detection
PagerDuty fires "APIGateway-High5xx" when the 5xx rate exceeds 2% over 5 minutes, or "APIGateway-Down" when `/status` fails three consecutive external probes (Pingdom, 60s interval). Customer-facing symptom: tracking.riversidecargo.com returns 502/504 and shippers report stale ETAs.

## Triage — first 10 minutes
1. Ack the page and post in #incidents: "Investigating API gateway, incident lead: [your name]."
2. Check pod health: `kubectl -n kong get pods`. CrashLoopBackOff after a recent deploy → roll back immediately: `helm rollback kong -n kong`.
3. Tail the logs: `kubectl -n kong logs deploy/kong-gateway --tail=200`. Look for:
   - "connection refused" to Postgres (config DB) → check RDS instance `kong-config-db`; failover takes ~90 seconds.
   - "no live upstreams" → an upstream service (usually `tracking-svc`) is down. That is a service outage, not a gateway outage — hand off per that service's runbook.
   - "too many open files" → node exhaustion. Scale up: `kubectl -n kong scale deploy/kong-gateway --replicas=8` (normal is 4).
4. Check Redis (`rate-limit-cache` in ElastiCache). Kong fails closed if Redis is unreachable, returning 429 on every request. If Redis is down, set `RATE_LIMIT_FAIL_OPEN=true` and restart the deployment as a temporary measure.

## Common causes (2024–2025 incidents)
- TLS cert expiry on `*.riversidecargo.com`. Certs auto-renew via cert-manager, but the March 2024 outage came from a stuck ACME challenge. Fix: `kubectl delete certificate kong-tls -n kong` to force reissue.
- Broken route config pushed via decK. Roll back with `deck sync --state config/kong/last-good.yaml`.
- RDS connection limit during peak season (November). Raise the `max_connections` parameter group value, or temporarily reduce gateway replicas.

## Escalation
If not mitigated within 20 minutes, page the secondary on the "Platform-OnCall" PagerDuty rotation and loop in Priya Raman (Platform Lead). Post status in #ops-leadership; Customer Success sends shipper notices after 30 minutes of confirmed impact.

## Recovery verification
Confirm 5xx below 0.1% for 15 minutes and the synthetic tracking-API check green in Datadog. Verify the EDI webhook backlog in SQS (`edi-delivery-queue`) drains; replay stranded messages via the "Requeue-DLQ" Lambda if any landed in the dead-letter queue.
