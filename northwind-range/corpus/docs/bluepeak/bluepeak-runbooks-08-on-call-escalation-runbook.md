---
tenant: bluepeak
department: Engineering
label: internal
title: Engineering On-Call Escalation Runbook
shares: []
contains_pii: false
contains_credential: false
---

# Engineering On-Call Escalation Runbook

**Owner:** Engineering Department / Site Reliability Team  
**Last Updated:** October 14, 2023  
**Scope:** This document outlines the protocol for escalating critical incidents affecting Bluepeak Retail Group’s e-commerce platform and Point-of-Sale (POS) synchronization services.

### 1. Incident Severity Levels
Before initiating an escalation, the Primary On-Call Engineer must categorize the incident:
*   **SEV-1 (Critical):** Complete outage of checkout flow or POS payment processing affecting >10% of stores. Immediate escalation required.
*   **SEV-2 (High):** Degraded performance (latency >3s) on product search or failure of loyalty point redemption. Escalation if not resolved within 60 minutes.
*   **SEV-3 (Moderate):** Minor UI bugs or internal reporting delays. Handle during standard business hours.

### 2. The Escalation Path
If a SEV-1 or SEV-2 incident is detected, follow this sequence:

**Level 1: Primary On-Call Engineer**
*   The first responder identified in the PagerDuty rotation.
*   Responsibility: Initial triage, log analysis via Datadog, and mitigation attempt.

**Level 2: Engineering Lead / Area Expert**
*   If the issue is isolated to a specific domain (e.g., Inventory Management or Payment Gateway) and cannot be resolved within 30 minutes, page the Domain Lead.
*   Contact: Use the `#eng-leads` Slack channel or PagerDuty "Escalate" button.

**Level 3: Director of Engineering / VP of Infrastructure**
*   Required for SEV-1 outages lasting longer than 90 minutes or incidents involving data loss/security breaches.
*   Contact: Sarah Jenkins (Director of Eng) via mobile or direct page.

### 3. Communication Protocol
During an active escalation, the Primary On-Call Engineer must perform the following:
1.  **Open an Incident Channel:** Create a Slack channel named `#inc-[YYYYMMDD]-[brief-description]`.
2.  **Initialize the Bridge:** Start a Zoom bridge for real-time coordination; post the link in the channel header.
3.  **Stakeholder Updates:** Every 30 minutes, post a "Status Update" to the `#ops-announcements` channel using this format:
    *   **Current Status:** (Investigating/Mitigating/Resolved)
    *   **Impact:** (e.g., Users cannot complete checkout in the Northeast region)
    *   **Next Step:** (e.g., Rolling back deployment v2.4.1 to v2.4.0)

### 4. Post-Mortem Requirement
All SEV-1 and SEV-2 escalations require a Blameless Post-Mortem document submitted to the Engineering Wiki within 72 hours of resolution.
