---
tenant: riverside
department: Engineering
label: internal
title: On-Call Escalation Runbook
shares: []
contains_pii: false
contains_credential: false
---

# On-Call Escalation Runbook

**Owner:** Engineering Department · **Doc owner:** Maria Delgado, Engineering Manager
**Last updated:** March 14, 2025 · **Review cadence:** Quarterly

## Purpose

This runbook defines how Riverside Cargo engineering responds to production incidents affecting our Transportation Management System (TMS), EDI pipelines, customer tracking portal, and carrier integrations. It applies to all engineers on the on-call rotation.

## Rotation & Coverage

- Weekly rotation, handed off Mondays at 09:00 CT via PagerDuty schedule **RC-Eng-Primary**.
- A secondary backup is assigned each week (schedule **RC-Eng-Backup**). Primaries must confirm backup availability at handoff.
- Handoff notes go in **#eng-oncall** Slack: open incidents, recurring alerts, and any vendor maintenance windows.

## Severity Levels

- **SEV1:** TMS unavailable, EDI pipeline halted (204 tenders not flowing), or tracking portal down. Revenue-impacting; customers calling dispatch.
- **SEV2:** Degraded service — e.g., Samsara GPS pings delayed >15 minutes, a single carrier integration failing (C.H. Robinson 214 statuses stuck), dock scheduler timing out.
- **SEV3:** Minor bugs, internal tooling issues, no customer impact. Handle during business hours.

## Escalation Path

1. Page fires to primary. **Acknowledge within 15 minutes** via PagerDuty app or phone call.
2. If unacknowledged after 15 minutes, PagerDuty auto-escalates to secondary.
3. If unresolved after 30 minutes, or if the incident is SEV1, notify **Maria Delgado (EM)** directly.
4. SEV1 lasting >60 minutes: escalate to **Tom Okafor, VP Engineering**, who owns executive and customer comms approval.
5. SEV1 requires an incident commander (usually the EM) and a status page update at status.riversidecargo.com within 30 minutes of declaration.

## Common Scenarios — First Steps

- **EDI backlog:** Check the Sterling B2B Integrator queue depth dashboard. If backlog >500 transactions, restart the `edi-poller` service on `edi-prod-02` and watch for 997 acknowledgments resuming.
- **Tracking portal 5xx spike:** Check RDS `tms-primary` CPU and connection count. If >80% connections used, fail over to the read replica per the DB failover runbook (RC-DB-04).
- **Carrier integration failure:** Verify credentials in the project44 dashboard; token rotation failures are the usual culprit. Re-auth via the Integrations admin panel.
- **Samsara GPS gap:** Confirm Samsara's status page before touching our ingest workers; do not replay events older than 24 hours.

## Communication & Follow-Up

- Open a thread in **#incident-response** for every SEV1/SEV2; log timeline as you go.
- Dispatch and customer ops monitor **#eng-status** — post updates every 30 minutes during SEV1.
- Blameless post-incident review within 3 business days; Maria schedules.
- Vendor contacts: AWS TAM (case severity "urgent" for SEV1), Samsara support line in 1Password under "Vendor Support."
