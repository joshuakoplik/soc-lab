---
tenant: fenwick
department: Engineering
label: internal
title: Data Infrastructure Backup Restoration Runbook
shares: []
contains_pii: false
contains_credential: false
---

# Data Infrastructure Backup Restoration Runbook

**Document Owner:** Engineering Department  
**Last Updated:** October 14, 2023  
**Status:** Active  

### Overview
This runbook provides the standardized procedure for restoring data from our primary backups in the event of accidental deletion or database corruption. Fenwick Analytics utilizes a tiered backup strategy: hourly snapshots for the production PostgreSQL cluster (RDS) and daily archival dumps stored in AWS S3 (Glacier Instant Retrieval).

### Recovery Time Objectives (RTO)
*   **Critical Production DB:** 2 hours
*   **Analytics Warehouse (Snowflake):** 4 hours
*   **Internal Tooling/Staging:** 24 hours

### Restoration Procedures

#### 1. PostgreSQL Production Cluster (RDS)
For point-in-time recovery (PITR) to resolve data corruption:
1.  Log into the AWS Management Console and navigate to **RDS > Databases**.
2.  Select the `fenwick-prod-db` instance.
3.  Choose **Actions > Restore to Point in Time**.
4.  Select the specific timestamp immediately preceding the incident (e.g., 2023-10-12 14:05 UTC).
5.  Provision the restored instance as a new DB instance named `fenwick-prod-db-recovery`. **Do not** overwrite the existing production instance until the data is verified.
6.  Once active, update the application connection strings in the Vault secret manager to point to the recovery instance for validation by the QA lead.

#### 2. Cold Storage S3 Archives
For restoring historical datasets older than 35 days:
1.  Access the `fenwick-backup-archives` bucket via the CLI using the `recovery-admin` IAM role.
2.  Locate the required `.tar.gz` dump based on the date naming convention (`YYYY-MM-DD_dataset_v1`).
3.  Initiate a restore request from Glacier to the S3 Standard tier (estimated retrieval time: 3–5 hours).
4.  Once available, stream the backup directly into the staging environment using:
    `aws s3 cp s3://fenwick-backup-archives/2023-01-15_client_metrics.tar.gz .`
5.  Extract and load via `pg_restore`.

### Verification & Sign-off
Before promoting a restored instance to production:
*   **Integrity Check:** Run the `verify_checksums.py` script located in the `/ops/scripts` directory.
*   **Row Count Validation:** Compare row counts for the `client_events` table against the last known healthy telemetry report.
*   **Approval:** Obtain a sign-off from the On-Call Engineering Lead via the #ops-alerts Slack channel.

### Escalation Path
If restoration fails or data is missing, immediately page the Infrastructure Lead (Sarah Jenkins) and open a P1 incident ticket in Jira.
