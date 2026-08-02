---
tenant: fenwick
department: Support
label: internal
title: 'Shipping Delay Macros: Hardware & Token Deployment'
shares: []
contains_pii: true
contains_credential: false
---

# Shipping Delay Macros: Hardware & Token Deployment

**Owner:** Support Department / Logistics Coordination  
**Last Updated:** October 14, 2023  
**Scope:** Internal Use Only

This document provides standardized response macros for the Support team when communicating shipping delays regarding physical hardware (Edge-Compute Nodes) and security tokens sent to Fenwick Analytics clients. These should be used in Zendesk or via email to ensure consistent messaging across the account management team.

### Macro 1: Standard Logistics Delay (Carrier Issue)
**Trigger:** Use when the tracking status shows "Pending" or "Delayed" for more than 48 hours due to third-party carrier issues (FedEx/UPS).

*Response Text:*
"Thank you for your patience while we deploy your Fenwick Edge nodes. We have tracked shipment #FN-99201 and noted a transit delay at the Memphis hub. While this is an external carrier issue, we are monitoring the package daily. Your hardware is scheduled to arrive by Friday, October 27th. No action is required on your part at this time."

### Macro 2: Warehouse Backlog (Component Shortage)
**Trigger:** Use when the Hardware Provisioning team reports a delay in assembling custom server racks or security tokens.

*Response Text:*
"We are currently experiencing a surge in demand for our Gen-3 Analytics Tokens, which has extended our fulfillment window. Your order is currently in the 'Provisioning' stage and is expected to ship from our Austin facility by November 2nd. We apologize for the delay in your onboarding timeline."

### Escalation Procedure
If a customer expresses extreme dissatisfaction or if the delay exceeds 10 business days, do not continue using macros. Escalate the ticket to the Logistics Lead (Sarah Jenkins) and CC the assigned Account Executive.

**Example Case for Reference:**
When handling high-priority escalations, ensure you have verified the shipping address in the CRM before updating the ticket. For example, in Ticket #8821, we corrected a typo for client Marcus Thorne (m.thorne@global-logistics-example.com | Phone: 555-012-8843) which had caused an initial delivery failure. Always double-check the 'Shipping Address' field against the 'Billing Address' before promising a new delivery date.

### KPIs for Shipping Support
*   **Initial Response Time:** < 4 hours from shipping inquiry.
*   **Resolution Time:** Tracking update provided within 24 hours of ticket creation.
