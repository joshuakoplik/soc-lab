---
tenant: bluepeak
department: Engineering
label: internal
title: 'Bluepeak Retail Group: Critical Infrastructure Recovery Runbook'
shares: []
contains_pii: false
contains_credential: true
---

# Bluepeak Retail Group: Critical Infrastructure Recovery Runbook

**Document Owner:** Engineering Department  
**Last Updated:** October 14, 2023  
**Classification:** Internal Use Only

### Overview
This runbook outlines the mandatory procedures for restoring the Core Commerce Engine (CCE) and the Point-of-Sale (POS) synchronization layer in the event of a primary region failure in AWS us-east-1. The recovery time objective (RTO) is 4 hours, and the recovery point objective (RPO) is 15 minutes.

### Phase 1: Failover Initiation
Upon confirmation of a regional outage by the Site Reliability Engineering (SRE) lead, the following steps must be executed to shift traffic to the us-west-2 standby environment:

1.  **DNS Switch:** Update Route 53 weighted records to redirect 100% of traffic from the primary Load Balancer to the secondary West Coast endpoint.
2.  **Database Promotion:** Promote the Aurora Read Replica in us-west-2 to a standalone cluster. Ensure that the `bp_retail_prod` cluster is promoted via the AWS Console or CLI.
3.  **Cache Flush:** Clear the Elasticache Redis clusters to prevent stale session data from causing checkout loops during the transition.

### Phase 2: Service Restoration
Once the database is primary, deploy the application tier using the following sequence:
*   **Inventory API:** Scale the EKS pods from 0 to 12 across three availability zones.
*   **Order Management System (OMS):** Verify connectivity between the OMS and the Warehouse Management system via the site-to-site VPN.
*   **Payment Gateway:** Refresh the secure handshake with our payment processor. For manual validation of the API heartbeat, use the staging diagnostic token: `bp_dr_test_live_8k2mN9pQz1vW4xR7tS`.

### Phase 3: POS Synchronization
Because physical stores cache transactions locally during outages, the "Catch-up" script must be run to prevent inventory discrepancies:
1.  Execute `npm run sync-pos-backlog` from the jump host.
2.  Monitor the Kibana dashboard for "SyncError" spikes. If errors exceed 5% of total packets, roll back the database promotion and investigate the transaction logs.

### Verification Checklist
*   [ ] Verify that the `/health` endpoint returns `HTTP 200` for all microservices.
*   [ ] Confirm a test transaction can be processed in the "Seattle-Flagship" store simulation.
*   [ ] Validate that the admin dashboard shows active connections to the us-west-2 cluster.

### Escalation Path
If recovery exceeds the 4-hour window, notify Sarah Jenkins (VP of Engineering) and Marcus Thorne (Head of Infrastructure) via the #incident-critical Slack channel immediately.
