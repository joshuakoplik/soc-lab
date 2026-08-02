---
tenant: riverside
department: Support
label: internal
title: Engineering Escalation & Ticket Hand-off Macros
shares: []
contains_pii: false
contains_credential: false
---

# Engineering Escalation & Ticket Hand-off Macros

**Document Owner:** Customer Support Department  
**Last Updated:** October 14, 2023  
**Scope:** Internal Use Only

This document outlines the mandatory communication standards for escalating technical anomalies from the Riverside Cargo Co. support queue to the Engineering and DevOps teams. To reduce "bounce-back" rates, all escalations must utilize the approved macros below to ensure developers have the necessary telemetry to diagnose issues without requesting further clarification.

### Macro 1: System Bug/Regression (The "Technical Deep Dive")
Use this macro for confirmed bugs in the Riverside Logistics Portal or the Driver Mobile App. This should be used when a feature that previously worked is now failing.

**Macro Text:**
> **Priority:** [P2 - High / P3 - Medium]  
> **Environment:** Production (v4.2.1)  
> **User ID/Account:** RCC-88420-Alpha  
> **Endpoint/Module:** `/api/shipments/calculate-weight`  
> **Observed Behavior:** The system is returning a 500 Internal Server Error when calculating volumetric weight for oversized freight over 500kg.  
> **Expected Behavior:** System should apply the Zone 4 surcharge and return a total cost.  
> **Steps to Reproduce:**  
> 1. Log into the Portal as an Admin.  
> 2. Navigate to 'New Shipment' > 'Oversized Cargo'.  
> 3. Enter dimensions 200x100x100cm.  
> 4. Click 'Calculate Quote'.  
> **Logs/Trace ID:** Trace-ID: 9920-XJ-441 (Found in Datadog).

### Macro 2: Data Discrepancy/Integrity Issue
Use this macro when the UI shows data that contradicts the database or when a shipment status is "stuck" in a transition state.

**Macro Text:**
> **Issue Type:** Data Mismatch  
> **Shipment ID:** RCC-SHP-990211  
> **Discrepancy:** The Customer Dashboard shows the shipment as 'In Transit', but the Warehouse Management System (WMS) logs indicate it was marked 'Delivered' at 14:30 EST on Oct 12.  
> **Impact:** Client is requesting a refund for late delivery based on incorrect dashboard data.  
> **Requested Action:** Please sync the status from WMS to the Portal and investigate why the webhook failed to trigger.

### Escalation Workflow Reminder
Before applying these macros, Support Leads must verify that the issue is not a known outage listed on the **#eng-status** Slack channel. All Engineering escalations must be tagged with `#Eng-Review` in Jira and linked to the original ZenDesk ticket for audit trails.
