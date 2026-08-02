---
tenant: fenwick
department: Support
label: public
title: Engineering Escalation & Bug Reporting Macros
shares: []
contains_pii: false
contains_credential: false
---

# Engineering Escalation & Bug Reporting Macros

**Owner:** Support Department  
**Last Updated:** October 14, 2023  
**Scope:** Internal Guidelines for High-Priority Technical Escalations

This document provides the standardized communication templates used by Fenwick Analytics Support Specialists when moving a ticket from the Frontline Support queue to the Engineering and DevOps teams. To ensure rapid resolution and minimize back-and-forth, all escalations must follow these specific macros.

### Macro 1: Critical System Regression (P0/P1)
*Use this macro for total service outages or data corruption affecting multiple tenants.*

**Subject:** ESCALATION: [Priority Level] - [Client Name] - [Brief Error Summary]

**Body:**
Engineering Team, we have a critical regression impacting the production environment. 

- **Incident ID:** FA-99201
- **Impacted Feature:** Real-time Stream Processor / API Gateway
- **Observed Behavior:** Users are receiving 504 Gateway Timeout errors when executing queries larger than 5GB.
- **Reproduction Steps:** Authenticate via the Fenwick Dashboard > Navigate to 'Advanced Analytics' > Run the 'Quarterly Aggregation' report for any dataset exceeding 10 million rows.
- **Logs Attached:** See attached `.log` files from the CloudWatch instance (Instance ID: i-04f29a).

Please acknowledge receipt of this ticket and provide an estimated time to resolution (ETR) within 30 minutes.

---

### Macro 2: Feature Bug / Edge Case (P2/P3)
*Use this macro for non-blocking bugs that impact specific workflows or a small subset of users.*

**Subject:** BUG REPORT: [Feature Name] - Unexpected Behavior in [Version Number]

**Body:**
Hi Engineering, we have identified a recurring bug in the latest v4.2 update regarding the Data Visualization module.

- **User Account:** Client ID 8842 (Enterprise Tier)
- **Issue:** The 'Heatmap' visualization is failing to render when the Z-axis contains null values, resulting in a blank canvas rather than a filtered view.
- **Expected Result:** The system should ignore nulls or display a "No Data" warning per the v4.0 specification.
- **Environment:** Chrome 118 / MacOS Ventura.

I have verified that this is not a configuration error on the client side. Please move this to the Engineering backlog for the next sprint cycle.

---

### Submission Protocol
All escalations must be logged in Jira under the "Support-to-Eng" project before sending these macros via Slack or Email. Ensure that the "Environment" field is correctly tagged as either *Production*, *Staging*, or *Sandbox*.
