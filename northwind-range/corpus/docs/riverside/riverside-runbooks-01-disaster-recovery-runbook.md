---
tenant: riverside
department: Engineering
label: internal
title: "Disaster Recovery Runbook \u2014 Riverside Cargo Co."
shares: []
contains_pii: false
contains_credential: true
---

# Disaster Recovery Runbook — Riverside Cargo Co.

**Owner:** Engineering Department (Platform/SRE Team)
**Last updated:** March 14, 2025 · **Review cadence:** Quarterly
**Classification:** Internal — all employees

## Scope

This runbook covers production systems supporting dispatch, tracking, and customer-facing operations:

- **CargoFlow TMS** — dispatch and load management, AWS us-east-1
- **TrackStar** — ELD/GPS telematics ingestion for ~12,000 active trucks
- **EDI gateway** — 204/214/990 transactions with shipper and broker partners
- **Customer portal and mobile API**
- Supporting data stores: Aurora Postgres 14 (primary), Redis job queue, S3 document store (bills of lading, POD scans)

## Recovery Objectives

| Tier | Systems | RTO | RPO |
|------|---------|-----|-----|
| 1 | TMS, EDI gateway | 1 hour | 5 minutes |
| 2 | Portal, telematics | 4 hours | 15 minutes |
| 3 | Reporting/analytics | 24 hours | 24 hours |

## Region Failover Procedure

1. On-call SRE (PagerDuty rotation `dr-primary`) declares the incident with approval from Dana Whitfield, Director of Engineering. Post status to Slack `#incident-dr` immediately.
2. Promote the Aurora read replica in us-west-2 to primary; expect 8–12 minutes.
3. Flip Route 53 failover records so `api.riversidecargo.com` resolves to the DR load balancer.
4. Verify EDI partner AS2 endpoints reconnect; send notice to the outage list (outages@riversidecargo.com) within 30 minutes of declaration.
5. Confirm the telematics backlog is draining from SQS queue `telematics-ingest-dr`. Budget ~45 minutes to clear a two-hour backlog.

## Database Restore

Point-in-time recovery uses Aurora backtrack (72-hour window) or the nightly snapshot bucket `s3://rvc-dr-backups-prod/`. DR automation authenticates via a service-account key stored in AWS Secrets Manager at `/dr/automation/api-key`, rotated quarterly. Example format (non-functional, shown for documentation only):

```
RVC_DR_API_KEY="rvc_dr_svc_aB3xK9mQ2pL7wT4nZ8yF1vC6hJ0sD5eR"
```

Never paste the live key into tickets, Slack, or this document.

## Testing

Quarterly game days are mandatory. Next: **June 12, 2025, 06:00–08:00 CT**, simulated region failover. Last test (March 6, 2025): TMS failed over in 38 minutes; EDI reconnection took 72 minutes. Open action item: pre-stage partner certificates in us-west-2 (ticket PLAT-2291).

## Escalation

Primary: Dana Whitfield, Director of Engineering. Secondary: Marcus Oyelaran, CTO. On-call: PagerDuty `dr-primary`.
