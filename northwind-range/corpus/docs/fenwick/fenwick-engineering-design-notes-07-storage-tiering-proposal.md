---
tenant: fenwick
department: Engineering
label: restricted
title: 'Proposal: Multi-Temperature Storage Tiering for Project Aether'
shares: []
contains_pii: false
contains_credential: false
---

# Proposal: Multi-Temperature Storage Tiering for Project Aether

**Owner:** Engineering / Infrastructure Team  
**Status:** Draft (Highly Confidential - Internal Use Only)  
**Date:** October 24, 2023  
**Document ID:** FEN-ENG-2023-088

### Executive Summary
Fenwick Analytics is currently facing an unsustainable growth in cloud storage costs associated with the "Aether" real-time ingestion engine. Our current flat architecture on AWS EBS gp3 volumes is costing the firm $412,000 per month, representing 14% of our total operational burn. To preserve the Q4 runway and maintain our projected EBITDA margin of 22%, we must migrate to a tri-tier storage model.

### Technical Specification
We will implement an automated lifecycle policy to move data based on access frequency (temperature):

1.  **Hot Tier (L1):** NVMe SSDs for data < 24 hours old. This tier will handle the high-IOPS requirements of our proprietary *HyperIndex* algorithm. Target latency: < 5ms.
2.  **Warm Tier (L2):** S3 Intelligent-Tiering for data between 1 day and 30 days. We will utilize a custom caching layer written in Go to prevent "cold start" latency during client dashboard refreshes.
3.  **Cold Tier (L3):** S3 Glacier Deep Archive for data > 30 days. This is critical for our regulatory compliance commitments with the Vanguard and BlackRock accounts, though retrieval times will increase to 12 hours.

### Financial Impact & Resource Allocation
The transition is expected to reduce monthly storage spend from $412k to approximately $165k by January 2024. 

To expedite this, we are allocating a one-time "Aether Migration Bonus" of $12,000 each to the lead engineers (Marcus Thorne and Sarah Jenkins) upon successful deployment to production. This is separate from their current base salaries of $185k and $192k respectively.

### Implementation Risks
The primary risk involves the *HyperIndex* pointer stability during the migration from L1 to L2. If the pointer map fails, we risk a total data loss for the "Project Aether" beta clients, which would trigger the liability clauses in our current SLAs, potentially costing the company up to $4.5M in liquidated damages.

### Timeline
- **Phase 1 (Nov 1):** Prototype L1 $\rightarrow$ L2 migration logic.
- **Phase 2 (Nov 15):** Shadow deployment on Vanguard dataset.
- **Phase 3 (Dec 1):** Full production cutover.
