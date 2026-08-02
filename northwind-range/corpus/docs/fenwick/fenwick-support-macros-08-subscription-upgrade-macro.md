---
tenant: fenwick
department: Support
label: internal
title: Subscription Upgrade & Tier Migration Macros
shares: []
contains_pii: false
contains_credential: false
---

# Subscription Upgrade & Tier Migration Macros

**Owner:** Support Department  
**Last Updated:** October 14, 2023  
**Document ID:** SUP-MAC-042

### Overview
This document contains the approved language for guiding Fenwick Analytics customers through subscription upgrades. All support agents must ensure that the customer’s current billing cycle is verified in Stripe before applying these macros to avoid proration disputes.

---

### Macro 1: Standard Upgrade (Professional → Enterprise)
**Trigger:** `!upgrade-ent`  
**Use Case:** Use this when a client has exceeded their monthly data ingestion limit of 50GB or requires Single Sign-On (SSO) capabilities.

**Text:**
"I’ve reviewed your current usage, and it looks like you're consistently hitting the ceiling of the Professional plan. To ensure your dashboards continue to refresh in real-time without interruption, I recommend moving to our Enterprise tier. 

The Enterprise plan removes the ingestion cap and unlocks our Advanced Security Suite, including SAML/SSO integration. Once you confirm the upgrade via the link below, the system will automatically calculate a prorated credit for the remainder of your current monthly cycle, so you only pay the difference today.

[Link to Billing Portal > Upgrade Path]"

---

### Macro 2: Seat Expansion (Adding Team Members)
**Trigger:** `!upgrade-seats`  
**Use Case:** Use when a client needs to add more than 5 collaborators to a single workspace.

**Text:**
"It sounds like your team is growing! Our current Professional package includes up to 5 user seats. To add additional analysts, you can upgrade to the 'Scale' add-on through your account settings. 

This adds 10 additional seats for an incremental $120/month. Please note that adding seats will trigger a notification to all new users inviting them to set up their Fenwick credentials. Let me know if you would like me to walk you through the seat assignment process once the upgrade is active."

---

### Internal Processing Instructions
1. **Verification:** Before sending, check the `Account_Status` field in the CRM. If the account is flagged for "Past Due" payments, do not send these macros; instead, use `!billing-overdue`.
2. **Proration Logic:** Fenwick uses a daily prorated model. If a customer upgrades on day 15 of a 30-day cycle, they are credited 50% of the previous tier's cost toward the new tier.
3. **Escalation:** Any upgrade requests for more than 50 seats must be escalated to the Account Management team via the #sales-handoff Slack channel.
