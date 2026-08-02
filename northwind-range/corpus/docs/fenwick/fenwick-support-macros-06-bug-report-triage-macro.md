---
tenant: fenwick
department: Support
label: internal
title: Bug Report Triage & Response Macros
shares: []
contains_pii: false
contains_credential: false
---

# Bug Report Triage & Response Macros

**Owner:** Support Department  
**Last Updated:** October 14, 2023  
**Scope:** Internal use for Tier 1 and Tier 2 Support Engineers

This document outlines the standardized macros used when triaging incoming bug reports within the Fenwick Analytics platform. To maintain consistency in our SLAs, please ensure that every bug report is acknowledged within 4 business hours using the appropriate macro below.

### Macro 1: Initial Receipt & Data Request
**Trigger:** `!bug-receipt`  
**Usage:** Use this when a client reports an anomaly but has not provided the necessary environment details to reproduce the issue.

*“Thank you for bringing this to our attention. I have opened a preliminary investigation ticket (Ref: FA-BUG) for our engineering team. To expedite the triage process, please provide the following:*
1. *The specific Dataset ID or Workspace URL where the error occurred.*
2. *The timestamp of the last failed query execution.*
3. *A screenshot of the full error stack trace from the ‘Developer Console’ tab.*

*Once we have these details, we can determine if this is a localized configuration issue or a systemic platform bug.”*

### Macro 2: Confirmed Bug / Escalation to Engineering
**Trigger:** `!bug-escalate`  
**Usage:** Use this once the Support Engineer has successfully reproduced the bug in the staging environment and moved the ticket to the Jira ‘Backlog’ queue.

*“We have successfully reproduced the behavior you described in our testing environment. This has been escalated to our Product Engineering team as a confirmed defect. While I don't have an immediate ETA for the patch, this is now tracked under internal ticket ENG-8842. We will provide status updates every Tuesday and Thursday until a resolution is deployed to production.”*

### Macro 3: Resolution & Verification
**Trigger:** `!bug-resolved`  
**Usage:** Use this after the QA team has signed off on a hotfix and it has been pushed to the live environment.

*“The fix for the data visualization glitch you reported has been deployed in version 4.2.1. Please clear your browser cache and refresh your dashboard to verify that the metrics are now calculating correctly. If the issue persists, please reply to this thread immediately so we can reopen the investigation.”*

**Triage Reminder:** All bugs must be tagged with a priority level (P0-P3) based on the Fenwick Impact Matrix before being escalated to Engineering.
