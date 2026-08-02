---
tenant: bluepeak
department: Engineering
label: internal
title: Incident Postmortem & Root Cause Analysis Template
shares: []
contains_pii: false
contains_credential: false
---

# Incident Postmortem & Root Cause Analysis Template

**Document Owner:** Engineering Department / Site Reliability Team  
**Last Updated:** October 14, 2023  
**Classification:** Internal Use Only

## Purpose
This document provides the standardized framework for conducting post-incident reviews at Bluepeak Retail Group. The goal is not to assign blame, but to identify systemic failures in our retail stack—specifically regarding the Checkout API and Inventory Sync services—to prevent recurrence.

## Postmortem Requirements
A formal postmortem must be initiated by the On-Call Engineer for any "Severity 1" or "Severity 2" incident (e.g., total checkout failure, latency > 5s for point-of-sale transactions, or data corruption in the Loyalty Points database). The document must be completed and shared via the `#eng-incidents` Slack channel within 72 hours of resolution.

## Required Content Sections

### 1. Executive Summary
A high-level overview for stakeholders. Include:
*   **Incident Date:** (e.g., November 12, 2023)
*   **Duration:** Total downtime in minutes.
*   **Impact:** Specific metrics (e.g., "Estimated 4,500 failed transactions across the Northeast region").
*   **Resolution:** The immediate action that restored service.

### 2. Detailed Timeline
A chronological log of events using UTC timestamps. Map out:
*   **Detection:** When did the Datadog alert trigger? Who acknowledged it?
*   **Diagnosis:** The steps taken to isolate the issue (e.g., "14:05 UTC: Identified memory leak in `inventory-sync-service` pod").
*   **Mitigation:** The exact moment service was restored (e.g., "14:22 UTC: Rolled back deployment v2.4.1 to v2.4.0").

### 3. Root Cause Analysis (The "5 Whys")
Avoid superficial answers like "human error." Drill down into the architecture. If a developer pushed a bad config, ask *why* the CI/CD pipeline didn't catch it or *why* the canary deployment didn't trigger an automatic rollback.

### 4. Corrective Action Items
List specific Jira tickets created to prevent recurrence. Every action item must have an assigned owner and a due date. Examples include:
*   **Immediate:** Update Prometheus alerts for `heap_memory_usage` on the Checkout cluster.
*   **Long-term:** Implement circuit breakers in the Payment Gateway wrapper to prevent cascading failures during third-party outages.

## Review Process
The Engineering Lead will host a "Blameless Postmortem" meeting every Thursday at 2:00 PM to review all incidents from the previous week and ensure action items are being tracked toward completion.
