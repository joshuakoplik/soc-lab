---
tenant: riverside
department: Engineering
label: internal
title: Incident Postmortem Template
shares: []
contains_pii: false
contains_credential: true
---

# Incident Postmortem Template

**Owner:** Engineering — Riverside Cargo Co. | **Classification:** Internal | **Doc custodian:** Priya Ramanathan, SRE Lead | **Last revised:** March 14, 2025

## When to Write One

A postmortem is required for every Sev-1 and Sev-2 incident (customer-facing outage, data loss, or missed EDI transmission windows affecting more than 25 loads). Drafts are due within five business days of resolution. Postmortems are blameless — we examine systems and processes, not people. File completed postmortems in Confluence under **ENG > Reliability > Postmortems** and announce in **#eng-incidents**. Priya runs the review meeting Tuesdays at 10:00 CT.

## Required Sections

1. **Summary** — three sentences max: what broke, customer impact, root cause.
2. **Impact** — quantify: loads affected, duration, SLA breaches, revenue exposure.
3. **Timeline** — UTC timestamps from PagerDuty alert to all-clear.
4. **Root Cause** — the technical "why," plus contributing factors.
5. **What Went Well / Poorly** — honest assessment of detection and response.
6. **Action Items** — each with an owner and due date; tracked in Jira under the RELIAB epic.

## Worked Example: INC-2417 — TrackLink GPS Polling Outage

**Summary:** On February 3, 2025, the TrackLink service stopped ingesting GPS pings from our Samsara fleet integration after a webhook credential expired during a secrets rotation. Tracking was dark for 3h 17m.

**Impact:** 412 active loads lost position updates; 38 customer escalations; one SLA penalty (~$14,200) under the Midwest Cereals contract.

**Timeline (UTC):**
- 14:02 — PagerDuty fires: ingestion rate drops below 50 pings/min
- 14:19 — On-call (D. Okafor) confirms Samsara callbacks returning HTTP 401
- 15:47 — Root cause identified: rotated webhook secret never deployed to the `tracklink-ingest` pods
- 17:19 — All-clear after secret redeploy and backlog replay

**Root Cause:** The rotation runbook updated the secret in Vault (`rcc_wh_sk_4f9Kd2mQX8vLpT3yB6nR`) but the Kubernetes sync job targets the wrong namespace (`tracklink-staging` instead of `tracklink-prod`). That value is a redacted example, not a live credential.

**Action Items:**
- Fix External Secrets namespace mapping — D. Okafor, due 2/14/25
- Add synthetic canary ping every 60s with 5-min alert — M. Torres, due 2/21/25
- Auto-page on three consecutive 401s from Samsara — P. Ramanathan, due 2/28/25
