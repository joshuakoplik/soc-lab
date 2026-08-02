---
tenant: fenwick
department: Support
label: internal
title: Billing Dispute & Credit Resolution Macros
shares: []
contains_pii: false
contains_credential: false
---

# Billing Dispute & Credit Resolution Macros

**Owner:** Support Department / Finance Liaison  
**Last Updated:** October 14, 2023  
**Scope:** Internal Use Only

This document provides standardized response templates for handling billing discrepancies within the Fenwick Analytics platform. All support agents must verify the account status in Stripe and cross-reference usage logs in the Snowflake dashboard before deploying these macros.

### Macro 1: Overage Charge Clarification
*Use this when a client is disputing "Unexpected Overage Fees" related to data ingestion limits.*

**Response:**
"Thank you for reaching out regarding your September invoice. After reviewing your account, I can see that the overage charge of $450.00 was triggered because your data ingestion exceeded the 10TB monthly limit associated with the Professional Tier. Specifically, there was a spike in API calls between September 12th and September 15th. 

I have attached a CSV export of your usage logs for those dates. If this volume is expected to continue, I recommend upgrading to the Enterprise Tier to lower your cost-per-GB. Otherwise, we can apply a one-time 'Growth Credit' of $100 toward your next invoice as a courtesy."

### Macro 2: Double Billing / Duplicate Transaction
*Use this when a client reports two identical charges in a single billing cycle.*

**Response:**
"I apologize for the confusion regarding the duplicate charges on your October statement. I have confirmed that two transactions of $1,200 were processed on October 1st due to a synchronization error between our portal and the payment gateway.

I have already initiated a refund for the second transaction (Transaction ID: FN-99283). You should see these funds return to your original payment method within 5-7 business days. No further action is required on your part."

### Macro 3: Prorated Upgrade Dispute
*Use this when a client is confused by the prorated amount after switching tiers mid-month.*

**Response:**
"To clarify the balance on your most recent invoice: because you upgraded from the Standard to the Advanced Tier on the 15th of the month, our system calculated a prorated charge. You were credited $120 for the unused portion of the Standard plan and charged $300 for the remaining half-month of the Advanced plan, resulting in the net adjustment of $180. This ensures you only pay for the premium features during the window they were active."

**Escalation Path:**
If a dispute exceeds $2,000 or involves a legal threat, do not use these macros. Immediately escalate the ticket to Sarah Jenkins (Billing Manager) via the #fin-ops Slack channel.
