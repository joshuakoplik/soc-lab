---
tenant: fenwick
department: Engineering
label: internal
title: Critical Infrastructure Disaster Recovery Runbook
shares: []
contains_pii: false
contains_credential: false
---

# Critical Infrastructure Disaster Recovery Runbook

**Document Owner:** Engineering Department  
**Last Updated:** October 14, 2023  
**Status:** Active / Internal Only

### 1. Scope and Trigger Criteria
This runbook outlines the recovery procedures for Fenwick Analytics' core data pipeline and client-facing dashboard API. This protocol is triggered only when a "Severity 1" incident is declared by the On-Call Engineer or if the primary AWS region (`us-east-1`) experiences an outage exceeding 15 minutes.

### 2. Recovery Time Objective (RTO) & Recovery Point Objective (RPO)
*   **RTO:** 4 hours to restore core API functionality.
*   **RPO:** 1 hour maximum data loss (based on asynchronous RDS snapshots).

### 3. Execution Steps

#### Phase I: Failover Initialization
1.  **DNS Pivot:** The Infrastructure Lead will update the Route53 health checks to divert traffic from the primary `us-east-1` load balancer to the standby environment in `us-west-2`.
2.  **Database Promotion:** 
    *   Promote the Aurora Read Replica in `us-west-2` to a standalone primary cluster.
    *   Verify that the `fenwick-prod-db` endpoint is reachable via the internal VPC peering connection.
3.  **State Store Recovery:** Trigger the restoration of the Redis cache from the most recent snapshot stored in the S3 cross-region bucket (`fenwick-dr-backups`).

#### Phase II: Application Deployment
1.  **Kubernetes Scaling:** Scale the EKS node groups in `us-west-2` from 2 standby nodes to 12 active nodes using the `terraform apply -var="env=dr"` command.
2.  **Service Verification:** Deploy the current stable image (v2.4.1) across the following microservices:
    *   `ingestion-engine`
    *   `analytics-aggregator`
    *   `client-api-gateway`

#### Phase III: Data Integrity Validation
1.  **Checksum Audit:** Run the `dr-verify.py` script located in the `/ops/scripts` repository to compare record counts between the promoted DB and the last known successful backup log.
2.  **Smoke Test:** Execute the Postman collection "DR-Health-Check" to verify that authenticated requests return a 200 OK response within <500ms.

### 4. Communication Plan
*   **Internal:** All updates must be posted every 30 minutes to the `#incident-response` Slack channel.
*   **External:** The Customer Success Manager will update the public status page (`status.fenwickanalytics.com`) using the "Degraded Performance" template until full restoration is confirmed.

### 5. Failback Procedure
Failback to `us-east-1` shall only occur during a scheduled maintenance window (Sunday 02:00 UTC) to prevent double-entry data collisions.
