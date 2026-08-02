---
tenant: riverside
department: Support
label: internal
title: 'Subscription Upgrade Macros: Tier Transitions'
shares: []
contains_pii: false
contains_credential: false
---

# Subscription Upgrade Macros: Tier Transitions

**Document Owner:** Support Department  
**Last Updated:** October 14, 2023  
**Scope:** Internal Use Only

This document provides standardized responses for support agents handling requests to upgrade a client's subscription tier. Per the Q3 Logistics Growth Initiative, our goal is to migrate "Basic" users to "Professional" or "Enterprise" tiers by highlighting API access and automated customs filing features.

### Macro 1: Basic to Professional (Self-Service Guide)
**Trigger:** *upg_basic_pro*  
**Use Case:** Use this when a client asks how to increase their monthly shipment cap from 50 to 250 loads.

"Hello, thanks for reaching out to Riverside Cargo Support. It looks like your current volume has exceeded the Basic Tier limit. To upgrade to the Professional Tier—which increases your capacity to 250 loads per month and unlocks our Real-Time GPS Tracking suite—please follow these steps:
1. Log into the Riverside Portal.
2. Navigate to **Account Settings > Billing & Plans**.
3. Select 'Professional' from the plan menu.
4. Confirm the prorated charge for the remainder of your current billing cycle.

Once confirmed, your new limits will be applied instantly."

### Macro 2: Professional to Enterprise (Lead Handoff)
**Trigger:** *upg_pro_ent*  
**Use Case:** Use this when a client requires the "Global Freight API" or exceeds 1,000 loads per month. Enterprise upgrades cannot be done via the portal and require a contract review by Account Management.

"Thank you for your interest in our Enterprise solutions. Based on your current volume of over 1,000 shipments, you are an ideal candidate for our Enterprise Tier. This tier provides dedicated account management, priority lane access, and full API integration for your internal ERP system.

I have CC’d your Account Manager, Sarah Jenkins, on this thread. Sarah will reach out within one business day to provide a custom quote based on your specific regional lanes and to finalize the service level agreement (SLA)."

### Internal Procedure Notes:
*   **Proration:** All upgrades handled via the portal are automatically prorated by Stripe. Do not manually apply discounts unless authorized by the Billing Lead.
*   **Verification:** Before sending the Enterprise macro, verify that the client has a verified Tax ID on file in the CRM to avoid delays during the handoff to Sarah Jenkins.
