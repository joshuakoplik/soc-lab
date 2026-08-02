---
tenant: riverside
department: Engineering
label: internal
title: Backup Restoration Runbook
shares: []
contains_pii: false
contains_credential: false
---

# Backup Restoration Runbook

**Owner:** Engineering Department
**Last reviewed:** March 4, 2025 (next review: June 2025)
**Applies to:** Production systems supporting Riverside Cargo dispatch, EDI, and customer-facing services

## Scope & Backup Inventory

This runbook covers restoration of the systems below. Backups run nightly at 02:00 UTC via Veeam Backup & Replication 12 to S3 bucket `rvc-backups-prod` (us-east-1), with cross-region replication to us-west-2. RDS PostgreSQL 14 clusters also take automated snapshots every 6 hours.

| System | Tier | RTO | RPO |
|---|---|---|---|
| RC-Dispatch (TMS) + `dispatch-db` | 1 | 2 hrs | 15 min |
| EDI gateway (214/210/204 messages) | 2 | 8 hrs | 4 hrs |
| Customer portal + document store | 2 | 8 hrs | 4 hrs |
| Reporting/analytics warehouse | 3 | 48 hrs | 24 hrs |

## Restoration Procedure

1. **Declare and approve.** On-call engineer opens a PagerDuty incident and gets restore approval from the on-duty Engineering Manager. For data-corruption restores (not full outages), also get sign-off from Dispatch Operations.
2. **Identify the restore point.** Pull the backup manifest from Veeam (`Backups > rvc-prod-nightly > Restore Points`). Confirm the timestamp with the requester — for corruption incidents, use the last known-good point *before* the event, not the latest backup.
3. **Notify.** Post in `#ops-incidents`: system, restore point, expected RTO. Update status.riversidecargo.com for Tier 1/2 outages.
4. **Database restore.** For `dispatch-db`: create a new RDS instance from the chosen snapshot (`aws rds restore-db-instance-from-db-snapshot`), then replay WAL archives from `rvc-backups-prod/wal/` to reach the target point-in-time. Never restore in place over the production instance.
5. **Application restore.** Restore app server volumes from the Veeam backup to replacement EC2 instances in the `prod-restore` subnet. Verify SHA-256 checksums against the manifest before boot.
6. **Smoke test.** Run `scripts/post-restore-check.sh`. It must pass: DB connectivity, load count reconciliation vs. the manifest, one test EDI 214 outbound, and portal login with the `svc-restore-test` account.
7. **Cutover.** Update the Route 53 records only after smoke tests pass. TTL is 60s; expect full propagation within 5 minutes.
8. **Validate with the business.** Have a dispatcher confirm the last 24 hours of loads, assignments, and POD documents look correct before declaring resolution.

## Contacts

- Infra Lead: Priya Raman — priya.raman@riversidecargo.com
- DBA: Marcus Webb — marcus.webb@riversidecargo.com
- After-hours: PagerDuty rotation `eng-oncall-primary`

## Testing

Full restore drills run quarterly (last: February 12, 2025 — passed in 1 hr 40 min against the 2-hr RTO). Log every restore, drill or real, in the Engineering wiki under "Restore History."
