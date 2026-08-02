---
tenant: riverside
department: Engineering
label: confidential
title: Production Deploy Runbook
shares: []
contains_pii: false
contains_credential: false
---

# Production Deploy Runbook

**Owner:** Engineering — Platform Team
**Doc ID:** ENG-RB-014 | **Version:** 3.2 | **Last updated:** 2025-09-18
**Classification:** Confidential — Internal Only. Do not share outside Riverside Cargo Co.

## Scope

Covers production deployments for CargoTrack TMS, RateEngine API, DriverLink mobile backend, and the EDI gateway (204/210/214 message flows). Does not cover warehouse scanner firmware — see ENG-RB-021.

## Deploy Windows

- Standard: Tuesdays and Thursdays, 10:00–12:00 CT.
- **Never deploy 14:00–17:00 CT** — that's our peak quoting window; RateEngine carries ~60% of daily volume in those hours.
- **Peak season freeze: Nov 15 – Jan 5.** Emergency fixes only, with written approval from VP Eng (Sandra Okafor) in the deploy ticket.

## Pre-Deploy Checklist

1. Green CI on `main` (GitHub Actions, all 4 test suites + contract tests against mock EDI partners).
2. DB migrations reviewed by Priya Raghavan (DBA). Migrations must follow expand/contract — **no destructive changes** without a signed migration plan.
3. Staging soak of at least 24h on `rcp-staging` with the same flag configuration.
4. Announce in **#deploys** at T-30 min; confirm on-call is watching.

## Deploy Procedure

1. Merge release PR; tag `vYYYY.MM.DD-seq`.
2. ArgoCD sync to `rcp-prod-01` (us-east-2). Canary at 10% traffic for 15 min.
3. Watch the "Prod — Deploy Watch" Grafana folder: error rate < 0.5%, RateEngine p99 < 800ms, EDI ack latency < 4s.
4. Promote to 100% if clean. Full rollout takes ~20 min.

## Rollback

- App: `argocd app rollback cargotrack <revision>` — completes in ~4 min. Helm charts and prior images retained 30 days in ECR.
- DB: restore-from-replica is a last resort; escalate before touching it. Point-in-time recovery via RDS snapshots (retained 35 days).

## Post-Deploy Verification

- Run synthetic booking flow (scripts in `deploy-tools/smoke/`).
- Confirm EDI heartbeat with test partners Schneider-TEST and JBH-TEST; a silent EDI gateway has burned us twice (see INC-2025-041).
- Monitor 30 min, then close the deploy ticket and post the summary in #deploys.

## Escalation

PagerDuty: primary on-call → secondary → Eng Manager (Marcus Delgado) → VP Eng (Sandra Okafor). If customer-facing impact exceeds 15 min, open an incident per ENG-RB-001 and loop in #eng-incidents.

Credentials and deploy tokens: Vault path `kv/prod/deploy/`. Access requests via IT ticket, manager approval required.
