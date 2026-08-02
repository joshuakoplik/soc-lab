---
tenant: riverside
department: Engineering
label: confidential
title: Database Failover Runbook
shares: []
contains_pii: false
contains_credential: true
---

# Database Failover Runbook

**Owner:** Engineering — Database Reliability
**Classification:** Confidential — Internal Only
**Last reviewed:** April 2, 2025 (P. Nair) · **Next live drill:** June 19, 2025

## Scope

Covers the **cargo-core** PostgreSQL 15 cluster backing the TMS (load board, dispatch assignments, ELD ping ingest). Primary: `pg-core-01` (us-east-1, db.r6g.2xlarge). Synchronous standby: `pg-core-02` (us-east-1b). Async DR replica: `pg-core-dr` (us-west-2). Targets: **RPO 5 min, RTO 15 min.** Customer-facing ETA API degrades gracefully; dispatch does not — prioritize accordingly.

## Detection & Authority

PagerDuty alert `cargo-core-primary-unreachable` fires after 3 failed health checks (~90 sec). Before acting, check replication lag on `pg-core-dr` — if lag exceeds 60 sec, note the expected data-loss window in the incident channel *before* promoting.

Promotion may be authorized only by the on-call DBA (PagerDuty rotation `db-primary`) or Priya Nair. If neither responds within 10 minutes, Marcus Webb (SRE lead) may proceed.

## Failover Procedure

1. **Confirm the primary is truly down.** Office VPN traffic shares the same NAT gateway as the app tier — verify from `bastion-02.rsvcargo.internal`, not your laptop. Rule out a network partition.
2. Post in **#eng-incidents**: "cargo-core failover starting." Pause the Buildkite pipeline `tms-prod-deploy` — no schema migrations mid-failover.
3. On `pg-core-02`: `pg_ctl promote -D /var/lib/postgresql/15/main`. Promotion requires the break-glass token from Vault at `secret/prod/cargo-core/failover`. Format example (this one is revoked and shown for reference only): `rvc_fo_tok_4Kd8Wm2PxQ7zL9jN3bT6`.
4. Repoint PgBouncer (`pgb-core`) at the new primary and issue `RELOAD`. **Do not restart PgBouncer** — a restart drops pooled connections and dispatch sees ~30 sec of hard errors (see incident INC-2291, Feb 2025).
5. Update the Route53 CNAME `db.cargo-core.internal` (TTL 30s). Verify propagation with `dig` from two app hosts before declaring success.
6. Run the TMS smoke suite: load-board read/write, ELD ingest queue draining, and confirm `shipment_events` writes landing on `pg-core-02`.
7. Repoint `pg-core-dr` recovery config to follow the new primary.

## Post-Failover

- The old primary must **never** rejoin as primary. Rebuild it as a standby via `pg_basebackup`; Dana Kowalski signs off before it takes traffic.
- Rotate the Vault failover token after every real (non-drill) promotion.
- Incident write-up due within 24 hours; attach lag metrics and timeline.

**Escalation:** On-call DBA via PagerDuty → Priya Nair → Dana Kowalski, ext. 4117.
