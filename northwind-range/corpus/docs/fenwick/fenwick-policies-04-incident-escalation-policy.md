---
tenant: fenwick
department: Admin
label: internal
title: Incident Escalation and Response Policy
shares: []
contains_pii: false
contains_credential: false
---

# Incident Escalation and Response Policy

**Document Owner:** Administration Department  
**Effective Date:** January 15, 2024  
**Review Cycle:** Bi-Annual

### 1. Purpose
This policy defines the standardized procedure for reporting, categorizing, and escalating operational or technical incidents within Fenwick Analytics to ensure minimal downtime for our data pipelines and client dashboards.

### 2. Incident Classification
All reported issues must be assigned a severity level by the initiating employee or the On-Call Engineer:

*   **Severity 1 (Critical):** Total outage of core analytics engines, widespread data corruption, or unauthorized access to client environments. Affects >50% of the customer base.
*   **Severity 2 (High):** Significant degradation of performance or failure of a major feature (e.g., automated reporting) affecting specific high-priority accounts.
*   **Severity 3 (Moderate):** Minor bugs, UI inconsistencies, or latency issues that do not impede core functionality.
*   **Severity 4 (Low):** General inquiries, documentation errors, or cosmetic suggestions.

### 3. Escalation Path and Timelines
Incidents must be logged via the internal Jira Service Management portal. If a resolution is not reached within the following timeframes, the incident must be escalated to the next tier:

| Severity | Initial Response | First Escalation (To Dept Head) | Second Escalation (To COO/CTO) |
| :--- | :--- | :--- | :--- |
| **Sev 1** | 15 Minutes | 60 Minutes | 4 Hours |
| **Sev 2** | 1 Hour | 8 Hours | 24 Hours |
| **Sev 3** | 8 Hours | 3 Business Days | N/A |
| **Sev 4** | 24 Hours | 7 Business Days | N/A |

### 4. Communication Protocol
For Severity 1 and 2 incidents, the following communication cadence is mandatory:
*   **Internal:** The designated Incident Lead must post updates to the `#ops-incidents` Slack channel every 30 minutes for Sev 1 and every 2 hours for Sev 2.
*   **External:** Client Success Managers (CSMs) are the sole authorized personnel to communicate with clients. They must be briefed by the Admin department before sending any external notifications.

### 5. Post-Mortem Requirements
Any incident classified as Severity 1 or 2 requires a formal Root Cause Analysis (RCA) document submitted to the Administration Department within five business days of resolution. This report must detail the trigger, the corrective action taken, and a preventative plan to avoid recurrence.
