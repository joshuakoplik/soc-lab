---
tenant: fenwick
department: Support
label: internal
title: Refund Request & Billing Adjustment Macros
shares: []
contains_pii: false
contains_credential: false
---

# Refund Request & Billing Adjustment Macros

**Document Owner:** Support Department / Billing Operations  
**Last Updated:** October 14, 2023  
**Access Level:** Internal Only

This document provides standardized response macros for handling refund requests within the Fenwick Analytics platform. To maintain consistency in our MRR reporting, support agents must follow the specific triggers and approval workflows outlined below before issuing any credits.

### Macro 1: Standard SaaS Subscription Refund (Within 30 Days)
**Trigger:** Customer requests a refund for an annual or monthly seat license within the first 30 days of the billing cycle.
**Procedure:** Verify that the account has not exceeded the "Fair Use" data ingestion limit of 50GB. If usage is under the limit, apply the refund directly via Stripe.

*“Thank you for reaching out. I have processed a full refund for your recent subscription charge of $499.00. You should see these funds return to your original payment method within 5-10 business days. Your access to the Fenwick Dashboard will remain active until the end of the current billing period, after which the account will revert to our Free Tier.”*

### Macro 2: Pro-Rata Credit for Seat Reduction
**Trigger:** Customer is downsizing their team mid-cycle and requests a credit for unused seats.
**Procedure:** Calculate the remaining days in the cycle. Do not issue cash refunds; apply a pro-rated credit to the Fenwick Account Balance for future invoicing.

*“I have adjusted your seat count from 10 users down to 5. Based on the remaining 12 days of your current billing cycle, I have applied a pro-rated credit of $84.20 to your account balance. This amount will be automatically deducted from your next monthly invoice.”*

### Macro 3: Denied Refund (Out of Policy)
**Trigger:** Request falls outside the 30-day window or exceeds data ingestion limits.
**Procedure:** Escalate to the Account Manager if the client is on an Enterprise Plan (Tier 3+). For Standard users, use this macro.

*“While we cannot offer a cash refund for charges incurred beyond our 30-day policy window, we want to ensure you are getting value from the platform. I can offer a one-on-one optimization session with our technical team to help you refine your data pipelines and reduce future costs.”*

**Escalation Path:**
Any refund request exceeding $1,200.00 requires a sign-off from Sarah Jenkins (Head of Billing) via the #billing-approvals Slack channel.
