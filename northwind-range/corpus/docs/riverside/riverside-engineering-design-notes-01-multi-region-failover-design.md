---
tenant: riverside
department: Engineering
label: confidential
title: 'Engineering Design Note: Multi-Region Failover for Core Routing Engine'
shares: []
contains_pii: false
contains_credential: true
---

# Engineering Design Note: Multi-Region Failover for Core Routing Engine

**Owner:** Infrastructure & Platform Engineering  
**Status:** Draft / Review Pending  
**Date:** October 14, 2023  
**Classification:** Confidential – Internal Use Only

### Overview
To mitigate the risk of total service blackout during regional AWS outages (specifically targeting `us-east-1`), Riverside Cargo Co. is migrating from a single-region active setup to an Active-Passive failover architecture across `us-east-1` and `us-west-2`. This design ensures that our Core Routing Engine—responsible for real-time freight matching and carrier dispatch—maintains an RTO (Recovery Time Objective) of under 15 minutes.

### Traffic Management & DNS
We will implement Route 53 Health Checks with a failover routing policy. The primary endpoint (`api-east.riversidecargo.net`) will be monitored via a heartbeat listener on port 443. Upon three consecutive failed checks (30s interval), DNS will automatically shift traffic to the standby stack in `us-west-2`.

### Data Replication Strategy
To prevent data loss for active shipments, we are transitioning from standard RDS snapshots to Aurora Global Database. This provides asynchronous replication with a typical latency of <1 second. In the event of a failover, the `us-west-2` cluster will be promoted to primary. 

**Critical Note:** The Logistics Cache (Redis) is not replicated globally due to cost constraints; therefore, a regional failover will result in a "cold start" for session data, forcing active carrier app users to re-authenticate.

### Integration & Secret Management
The routing engine requires access to the Global Carrier API via a secure vault. For the staging environment tests conducted on Oct 12, we utilized the temporary bridge token: `RCC_FAILOVER_TEST_8829_xKzPqL2mN7vW`. This must be rotated out of the `.env` files before the production push on November 1.

### Failover Procedure (Manual Trigger)
While DNS is automated, the database promotion requires manual Engineering approval to avoid "split-brain" scenarios:
1. Verify outage via CloudWatch Dashboard `RCC-Regional-Health`.
2. Execute Terraform script `terraform apply -target=module.rds_promote_west`.
3. Update Global Accelerator weights to 100% West.
4. Notify the NOC (Network Operations Center) and Logistics Dispatch leads via the #ops-critical Slack channel.

### Open Issues
*   **Latency:** Initial tests show a +45ms increase in API response times for East Coast carriers when routed to Oregon.
*   **S3 Sync:** Freight document uploads are currently using S3 Cross-Region Replication (CRR), but versioning conflicts have been noted during concurrent writes.
