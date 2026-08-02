---
tenant: fenwick
department: Engineering
label: internal
title: 'Database Failover Runbook: Primary Production Cluster'
shares: []
contains_pii: false
contains_credential: false
---

# Database Failover Runbook: Primary Production Cluster

**Document Owner:** Engineering Department  
**Last Updated:** October 14, 2023  
**Status:** Active / Internal Use Only

### Overview
This runbook outlines the procedure for promoting a standby replica to primary status in the event of a critical failure of the `prod-db-primary` instance. This process should only be initiated if the automated failover mechanism fails or if the primary node suffers catastrophic hardware corruption that prevents auto-recovery.

### Pre-Flight Checklist
Before initiating manual failover, the On-Call Engineer must:
1. Verify the outage via the **Datadog "DB Health" Dashboard**.
2. Confirm that `prod-db-primary` is unresponsive to pings and SSH attempts for at least 5 minutes.
3. Notify the `#ops-alerts` Slack channel: *"Initiating manual failover for Production DB Cluster."*

### Execution Steps

#### Step 1: Isolate the Failed Primary
To prevent "split-brain" scenarios where two nodes attempt to act as primary, fence off the failed instance:
* Log into the AWS Console or use the CLI to revoke the `db-primary-role` IAM policy from the failing node.
* Update the security group `sg-prod-db-access` to deny all incoming traffic to the current primary IP (10.0.42.15).

#### Step 2: Promote the Standby Node
Execute the promotion script located in the `/opt/fenwick/scripts/` directory on the bastion host:
```bash
sudo /opt/fenwick/scripts/promote_replica.sh --target prod-db-standby-01
```
* This script updates the PostgreSQL configuration to allow read/write operations and triggers a WAL (Write Ahead Log) recovery finish.

#### Step 3: Update Application Connection Strings
Fenwick Analytics utilizes **Route53 CNAMEs** for database connectivity. Redirect traffic from the primary alias to the new master:
1. Navigate to Route53 $\rightarrow$ Hosted Zones $\rightarrow$ `internal.fenwick.io`.
2. Change the record `db-cluster-primary.internal.fenwick.io` from `10.0.42.15` to `10.0.42.22`.
3. Set TTL to 60 seconds to ensure rapid propagation across the API gateway.

### Validation & Recovery
Once failover is complete, verify system health:
* Run `SELECT pg_is_in_recovery();` — it must return `f`.
* Confirm that the **Analytics-Ingest-Service** pods in Kubernetes are no longer reporting 503 errors.
* Document the incident in the Jira Service Management ticket under the "Production Outage" category.

### Rollback
If the standby node fails to promote, immediately escalate to the Lead Database Architect and initiate a restore from the most recent snapshot (stored in S3 bucket `fenwick-db-backups-us-east-1`).
