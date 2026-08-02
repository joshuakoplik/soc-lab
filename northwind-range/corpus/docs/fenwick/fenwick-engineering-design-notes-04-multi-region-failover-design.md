---
tenant: fenwick
department: Engineering
label: confidential
title: 'Multi-Region Failover Architecture: US-East-1 to US-West-2'
shares: []
contains_pii: false
contains_credential: false
---

# Multi-Region Failover Architecture: US-East-1 to US-West-2

**Owner:** Engineering / Infrastructure Team  
**Status:** Draft for Review (v0.4)  
**Last Updated:** October 14, 2023  
**Confidentiality:** Internal Only – Restricted Distribution

### Overview
To mitigate the recurring instability of our primary AWS `us-east-1` region and meet the updated SLA requirements for Fenwick’s Enterprise tier (99.99% availability), we are transitioning from a cold-standby to a Warm-Standby failover model in `us-west-2`. This design ensures that critical ingestion pipelines and the Analytics API remain operational during a regional outage with a target Recovery Time Objective (RTO) of < 15 minutes.

### Data Replication Strategy
The core challenge remains the latency of our PostgreSQL cluster (Fenwick-DB-Main). We will implement asynchronous streaming replication to the west coast. To prevent write-drift, we are implementing a "Circuit Breaker" logic in the Application Layer:
*   **Primary:** `us-east-1` handles all Read/Write traffic.
*   **Secondary:** `us-west-2` maintains a read-replica. In the event of a failover, the replica is promoted to primary via a Terraform-triggered script.
*   **S3 Buckets:** We will enable Cross-Region Replication (CRR) for the `fenwick-client-data-prod` bucket. Versioning must be enabled to prevent accidental deletions from replicating across regions.

### Traffic Routing & Failover Trigger
We are moving away from manual DNS updates. We will implement AWS Route 53 Health Checks targeting our `/health/deep` endpoint. 
*   **Trigger:** If the health check fails for three consecutive 30-second intervals, Route 53 will automatically shift traffic to the `us-west-2` Application Load Balancer (ALB).
*   **The "Split-Brain" Risk:** To avoid data corruption during partial outages, we are implementing a mandatory manual confirmation step via PagerDuty before promoting the DB replica. Automatic DNS failover will only route traffic to the read-only API until the DB promotion is confirmed by an on-call engineer.

### Resource Scaling
To manage costs, `us-west-2` will run at 20% capacity (t3.medium instances) during normal operations. Upon failover trigger, a Lambda function will trigger an Auto Scaling Group (ASG) update to scale the API fleet to m5.large instances to handle the full production load of ~45k concurrent requests per second.

### Testing Schedule
Chaos engineering drills (Region-Down simulations) are scheduled for the staging environment on November 2nd, with a production dry-run slated for Q1 2024.
