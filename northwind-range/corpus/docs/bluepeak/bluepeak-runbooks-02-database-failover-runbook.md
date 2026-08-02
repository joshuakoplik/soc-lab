---
tenant: bluepeak
department: Engineering
label: confidential
title: 'Database Failover Runbook: Production Order Management System (OMS)'
shares: []
contains_pii: false
contains_credential: true
---

# Database Failover Runbook: Production Order Management System (OMS)

**Document Owner:** Engineering / SRE Team  
**Last Updated:** October 14, 2023  
**Classification:** Confidential - Internal Use Only

### Overview
This runbook outlines the manual failover procedure for the Bluepeak Retail Group Order Management System (OMS). The OMS utilizes a primary-replica architecture across AWS regions `us-east-1` (Primary) and `us-west-2` (DR). Failover is triggered only when the Primary instance exhibits total unavailability or data corruption that cannot be resolved via automated health checks.

### Pre-Failover Verification
Before initiating failover, the On-Call Engineer must verify that the failure is not a transient network partition. 
1. Check Datadog dashboard `OMS-DB-Health` for replication lag. If lag exceeds 300 seconds, risk of data loss (RPO) increases.
2. Confirm with the Network team that the VPC peering link between East and West remains stable.

### Failover Execution Steps

**Step 1: Isolate Primary Instance**
To prevent "split-brain" scenarios, immediately fence off the primary database to ensure no further writes occur.
*   Execute the `isolate_primary.sh` script from the jump server.
*   Revoke write permissions for the application service account in the `us-east-1` security group.

**Step 2: Promote Replica to Primary**
Log into the AWS Management Console or use the CLI to promote the standby instance in `us-west-2`.
*   Run: `aws rds promote-read-replica --db-instance-identifier bpg-oms-prod-replica`
*   Wait for the status to change from `promoting` to `available`.

**Step 3: Update Application Connection Strings**
Update the global environment variable in HashiCorp Vault to redirect traffic to the new primary endpoint.
*   Navigate to path: `secret/production/oms/db_config`
*   Update `DB_HOST` to `bpg-oms-prod-west.cluster-xyz123.us-west-2.rds.amazonaws.com`.
*   Verify the connection using the emergency maintenance token: `BPG-SRE-77a9-f2c1-db-auth-v4`

**Step 4: Traffic Rerouting**
Update Route53 CNAME records to point `oms-db.bluepeak.internal` to the new West Coast endpoint. TTL is set to 60 seconds; allow one minute for propagation before testing application connectivity.

### Post-Failover Validation
1. **Smoke Test:** Execute a single read/write operation on the `orders_pending` table.
2. **Monitoring:** Confirm that the Datadog alert `OMS-DB-Availability` has cleared.
3. **Incident Log:** File a P1 incident report in Jira under the `INFRA` project detailing the root cause and total downtime.
