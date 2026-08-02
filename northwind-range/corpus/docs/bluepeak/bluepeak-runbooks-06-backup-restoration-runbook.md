---
tenant: bluepeak
department: Engineering
label: internal
title: Database and Application Backup Restoration Runbook
shares: []
contains_pii: false
contains_credential: false
---

# Database and Application Backup Restoration Runbook

**Document Owner:** Engineering Department  
**Last Updated:** October 14, 2023  
**Classification:** Internal Use Only

## Overview
This runbook provides the standardized procedure for restoring Bluepeak Retail Group’s core production environments. This process is to be triggered only upon confirmation of data corruption or total site failure by the Site Reliability Engineering (SRE) lead.

## Recovery Point Objectives (RPO)
*   **Transactional Database (PostgreSQL):** 15 minutes.
*   **Product Catalog/Static Assets (S3):** 24 hours.
*   **Configuration State (Redis):** No guaranteed recovery (rebuild from DB).

## Restoration Procedures

### 1. Transactional Data Recovery (AWS RDS)
Bluepeak utilizes Point-in-Time Recovery (PITR) for the `bp-prod-db` instance.
1.  Log into the AWS Management Console and navigate to **RDS > Databases**.
2.  Select the `bp-prod-db` instance and choose **Actions > Restore to Point in Time**.
3.  Select the "Custom" time window. Coordinate with the Incident Commander to identify the exact timestamp immediately preceding the corruption event.
4.  Provision the restored instance as `bp-prod-db-recovery`. **Do not** overwrite the existing production instance until a checksum validation is performed.
5.  Once available, update the application connection string in AWS Secrets Manager to point to the recovery endpoint for validation testing.

### 2. Static Asset Recovery (S3 Versioning)
For corrupted product images or pricing manifests in the `bluepeak-assets-prod` bucket:
1.  Enable **Bucket Versioning** view via the S3 Console.
2.  Identify the affected prefix (e.g., `/catalog/seasonal-promos/`).
3.  Use the AWS CLI to roll back specific objects:
    `aws s3api list-object-versions --bucket bluepeak-assets-prod --prefix /catalog/`
4.  Delete the current corrupted version to automatically promote the previous healthy version to "Latest."

### 3. Validation Checklist
Before redirecting live traffic to a restored instance, the on-call engineer must verify:
*   **Connectivity:** Application pods in the EKS cluster can reach the new DB endpoint.
*   **Integrity:** Run the `health_check_query.sql` script located in the `/ops/scripts` repo to ensure table consistency.
*   **Latency:** Confirm that read latency is under 50ms for the primary product index.

## Escalation Path
If restoration fails or data loss exceeds the RPO, escalate immediately via PagerDuty to:
*   **Primary:** Marcus Thorne (Director of Infrastructure)
*   **Secondary:** Sarah Jenkins (Lead Database Administrator)
