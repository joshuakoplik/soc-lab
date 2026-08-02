---
tenant: riverside
department: Engineering
label: internal
title: Proposal for Automated Storage Tiering Implementation
shares: []
contains_pii: false
contains_credential: false
---

# Proposal for Automated Storage Tiering Implementation

**Owner:** Engineering Department  
**Date:** October 14, 2023  
**Status:** Draft / For Review  
**Document ID:** ENG-2023-ST04

### Overview
Riverside Cargo Co. currently stores all shipment telemetry and historical manifest data in a high-performance PostgreSQL cluster on NVMe drives. As our volume of IoT sensor pings from the North American fleet has increased by 40% over the last two quarters, we are seeing significant cost spikes and degradation in query performance for long-term auditing. This document proposes a tiered storage architecture to move cold data to lower-cost S3-compatible object storage.

### Technical Specification
We will implement a three-tier lifecycle policy based on the "Age of Record" (AoR):

1.  **Hot Tier (0–30 Days):** All active shipments and telemetry stay in the primary PostgreSQL instance using SSDs for sub-second retrieval. This ensures that dispatchers have real-time visibility into current cargo movements.
2.  **Warm Tier (31–90 Days):** Data is migrated to a compressed columnar format (Apache Parquet) stored on managed block storage. Access will be routed through a Presto/Trino query layer, allowing analysts to run reports with a latency overhead of 2–5 seconds.
3.  **Cold Tier (91+ Days):** Records are offloaded to AWS S3 Glacier Instant Retrieval. Data in this tier is strictly for regulatory compliance and annual audits.

### Implementation Plan
The migration will be handled by a new Go-based service, `tier-manager`, which will execute the following logic every 24 hours at 02:00 UTC:
*   Scan the `shipment_logs` table for records where `timestamp < NOW() - INTERVAL '30 days'`.
*   Batch export these records into Parquet files partitioned by `region_id` and `date`.
*   Verify checksums in S3 before issuing a `DELETE` command to the Hot Tier.

### Expected Impact
By moving 75% of our total data volume to the Cold Tier, we project a monthly reduction in cloud infrastructure spend of approximately $4,200. Furthermore, we expect an improvement in primary database vacuuming times and a 15% increase in transaction throughput for the active dispatch dashboard.

### Next Steps
*   **Validation:** Engineering will run a shadow migration on the `test-west` cluster starting November 1st.
*   **Approval:** Pending sign-off from the Infrastructure Lead regarding S3 bucket versioning policies.
