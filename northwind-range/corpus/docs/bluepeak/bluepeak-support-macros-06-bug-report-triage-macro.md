---
tenant: bluepeak
department: Support
label: internal
title: Bug Report Triage & Response Macros
shares: []
contains_pii: false
contains_credential: false
---

# Bug Report Triage & Response Macros

**Document Owner:** Support Operations Team  
**Last Updated:** October 14, 2023  
**Scope:** Internal Use Only – Bluepeak Retail Group Support Staff

This document provides standardized response macros for the triage phase of technical issues reported via the Merchant Portal or internal store managers. To ensure consistent data collection for our Engineering team, please use these exact templates before escalating tickets to Jira.

### Macro 1: Initial Acknowledgement & Data Request
*Use this when a bug is first reported but lacks specific environmental details.*

"Hello, thank you for reporting this issue with the Bluepeak Inventory Sync tool. I have opened a tracking ticket (Ref: BP-TECH) for this behavior. To help our developers reproduce this quickly, please provide the following:
1. The specific Store ID where this is occurring.
2. A screenshot of the error message or a description of the expected vs. actual result.
3. Whether this is happening on the handheld Zebra scanners or the back-office desktop terminals.
4. The approximate time (including timezone) when the error first occurred."

### Macro 2: Intermittent Issue / "Cannot Reproduce"
*Use this when a report is vague or the Support Lead cannot trigger the bug in the staging environment.*

"We have attempted to reproduce the reported lag in the Point-of-Sale checkout flow using the parameters provided, but the system is currently performing within normal latency thresholds (under 200ms). Because this appears to be intermittent, we would like to monitor your specific terminal. Please provide the MAC address of the affected POS register and let us know if there is a specific SKU or payment method that consistently triggers the slowdown."

### Macro 3: Escalation to Engineering (Tier 3)
*Use this to notify the user once the ticket has been moved to the Development backlog.*

"I have successfully escalated this issue to our Engineering team. It has been logged in Jira as a Priority 2 bug affecting the Q4 Logistics Module. While they work on a permanent patch, please use the manual CSV upload workaround detailed in the Store Manager Handbook (Page 12). We will notify you via this thread as soon as a fix is deployed in the weekly Tuesday sprint update."

**Triage Guidelines:**
*   **P1 (Critical):** Total outage of POS or Payment Gateway. Escalate immediately to the On-Call Lead via Slack (#ops-critical).
*   **P2 (High):** Feature broken with no workaround. 24-hour turnaround for triage.
*   **P3 (Normal):** Minor bug/UI glitch with an existing workaround.
