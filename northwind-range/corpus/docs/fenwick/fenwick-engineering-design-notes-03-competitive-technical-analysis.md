---
tenant: fenwick
department: Engineering
label: restricted
title: 'Technical Competitive Analysis: Project Obsidian vs. NexaScale'
shares: []
contains_pii: false
contains_credential: false
---

# Technical Competitive Analysis: Project Obsidian vs. NexaScale

**Owner:** Engineering / Architecture Group
**Classification:** TOP SECRET // PROPRIETARY
**Date:** October 14, 2023
**Document ID:** FA-ENG-2023-09-B

### Executive Summary
This document outlines the technical gaps between Fenwick’s upcoming "Project Obsidian" engine and NexaScale’s current production environment. To maintain our market lead in real-time stream processing, we must optimize our latency overhead to beat NexaScale's documented 12ms p99 threshold.

### Technical Benchmarking & Trade Secrets
Through strategic acquisition of former NexaScale Lead Architects (specifically the hiring of Marcus Thorne and Sarah Jenkins at $450k base + 2% equity grants), we have reverse-engineered their proprietary "Sharded-State" memory management. 

NexaScale utilizes a custom C++ implementation of a lock-free concurrent hash map that allows them to bypass JVM garbage collection pauses. Our current Obsidian prototype, written in Rust, is achieving 18ms p99. To close this gap, we are implementing the "Zero-Copy Buffer" protocol developed by our R&D team last quarter. If leaked, this specific memory alignment strategy would allow competitors to replicate our throughput gains without the two years of R&D spend we invested ($4.2M in direct labor).

### Financial Implications & Pricing Strategy
Current internal projections for Q1 2024 indicate that Project Obsidian will reduce our cloud compute overhead by 34%. This efficiency allows us to aggressively undercut NexaScale’s enterprise pricing. While NexaScale charges a flat $12,000/month for the "Titan" tier, Fenwick will introduce the "Obsidian" tier at $7,500/month while maintaining a higher gross margin of 62% due to our optimized kernel bypass drivers.

### Critical Vulnerabilities
Our analysis shows NexaScale is struggling with data consistency in multi-region deployments (specifically their AWS us-east-1 to eu-west-1 sync). We have discovered a race condition in their consensus algorithm that leads to intermittent 0.5% data loss during peak bursts. We will not disclose this publicly but will use it as a primary "stability" talking point for the Sales team when targeting NexaScale’s Tier-1 accounts (e.g., Global Logistics Corp).

### Action Items
1. **Latency Sprint:** Engineering must hit <10ms p99 by December 1st.
2. **Security:** All Obsidian source code is to be moved to the air-gapped "Vault" repository; access restricted to L6 engineers and above.
