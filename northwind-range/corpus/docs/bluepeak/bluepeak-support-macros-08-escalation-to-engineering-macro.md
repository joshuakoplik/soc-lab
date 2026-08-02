---
tenant: bluepeak
department: Support
label: internal
title: Engineering Escalation & Ticket Hand-off Macros
shares: []
contains_pii: false
contains_credential: false
---

# Engineering Escalation & Ticket Hand-off Macros

**Document Owner:** Support Department / Technical Operations  
**Last Updated:** October 14, 2023  
**Scope:** Internal Use Only

This document outlines the standardized macros to be used when escalating a customer issue from Tier 2 Support to the Engineering team. To minimize back-and-forth and reduce resolution time (MTTR), all escalations must follow these specific formats. 

### Macro: ENG_BUG_REPORT
Use this macro for suspected software regressions or functional bugs within the Bluepeak POS or Inventory Management System (IMS).

**Required Fields:**
*   **Environment:** Production, Staging, or Beta.
*   **Version Number:** e.g., v4.2.1-build88.
*   **Steps to Reproduce:** A numbered list of actions taken.
*   **Expected vs. Actual Result:** Clear contrast of what should have happened versus what occurred.

**Example Output:**
*"Escalating to Engineering: Bug found in IMS Module. Environment: Production (v4.2.1). Steps: 1. Navigate to Warehouse Stock > 2. Select 'Bulk Update' > 3. Upload CSV with 50+ SKUs. Result: System returns a 504 Gateway Timeout after 30 seconds. Expected: Bulk update should complete or provide a partial success log."*

### Macro: ENG_API_FAILURE
Use this macro for issues involving third-party integrations (e.g., Shopify Sync, Stripe Payment Gateway).

**Required Fields:**
*   **Request ID/Trace ID:** Found in the logs via Kibana.
*   **Endpoint:** The specific API call being made.
*   **Payload:** Redacted JSON snippet of the request.

**Example Output:**
*"Escalation: Stripe Integration Error. Trace ID: BP-992834-X. Endpoint: /v1/charges. Payload: { "amount": 500, "currency": "usd" }. The API is returning a 402 Request Failed despite valid payment credentials on the merchant account."*

### Escalation Workflow & SLAs
Once the macro is applied, the ticket must be moved to the **"Eng-Pending"** queue and tagged with the appropriate priority level:

1.  **P1 (Critical):** Site down or total loss of payment functionality. Engineering will acknowledge within 1 hour via Slack channel #ops-critical.
2.  **P2 (High):** Major feature broken for a subset of users. Acknowledgment within 4 business hours.
3.  **P3 (Normal):** Minor bug or UI glitch. Reviewed during the weekly Tuesday Triage meeting at 10:00 AM EST.

Failure to include the Trace ID or Version Number will result in the ticket being returned to Support for further investigation.
