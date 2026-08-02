---
tenant: fenwick
department: Engineering
label: internal
title: Engineering On-Call Escalation Runbook
shares: []
contains_pii: false
contains_credential: false
---

# Engineering On-Call Escalation Runbook

**Document Owner:** Engineering Department  
**Last Updated:** October 14, 2023  
**Status:** Active

## Overview
This runbook defines the escalation path for Fenwick Analytics' production environment. The goal is to minimize Mean Time to Resolution (MTTR) by ensuring that critical system failures are routed to the correct subject matter expert (SME) without unnecessary delay.

## Escalation Tiers
All incidents are initiated via PagerDuty alerts triggered by our Datadog monitors.

### Tier 1: Primary On-Call Engineer
The first responder is responsible for initial triage, documenting the incident in the `#incidents-active` Slack channel, and attempting a resolution using existing playbooks. If the issue remains unresolved after 30 minutes, or if it is identified as a "Severity 1" (complete data pipeline outage), they must escalate to Tier 2.

### Tier 2: Domain SMEs
If the Primary Engineer cannot resolve the issue, they should page the specific domain expert based on the affected service:
*   **Ingestion Pipeline / Kafka Clusters:** Page Sarah Jenkins (Infrastructure Lead).
*   **Query Engine / Snowflake Optimization:** Page Marcus Thorne (Data Architect).
*   **Customer Facing API / Dashboard Latency:** Page Elena Rodriguez (Backend Lead).

### Tier 3: Engineering Leadership
If an incident is not mitigated within two hours, or if there is a confirmed data breach or permanent data loss, the Primary Engineer must notify the Director of Engineering, David Chen. At this stage, David will take over communications with the Executive team and Customer Success leads to manage external client expectations.

## Communication Protocols
1.  **Incident Command:** The person who initiates the escalation becomes the Incident Commander (IC). Their sole job is coordination, not coding.
2.  **The War Room:** For Sev-1 issues, the IC will spin up a Zoom bridge (Link: `fenwick.zoom.us/j/eng-warroom`) and pin it to the Slack channel.
3.  **Status Updates:** Every 30 minutes, the IC must post a "TL;DR" update in `#incidents-active` following this format:
    *   **Current Status:** (e.g., Investigating/Mitigating/Resolved)
    *   **Impact:** (e.g., 15% of Enterprise clients seeing 504 errors)
    *   **Next Step:** (e.g., Rolling back deployment v2.4.1)

## Post-Mortem Requirement
Any incident that reaches Tier 2 or higher requires a Blameless Post-Mortem document submitted to the Engineering Wiki within 72 hours of resolution.
