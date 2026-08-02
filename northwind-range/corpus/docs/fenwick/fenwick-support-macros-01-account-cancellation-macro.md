---
tenant: fenwick
department: Support
label: internal
title: Account Cancellation & Offboarding Macros
shares: []
contains_pii: false
contains_credential: false
---

# Account Cancellation & Offboarding Macros

**Owner:** Support Department  
**Last Updated:** October 14, 2023  
**Scope:** Internal Use Only

This document provides standardized response macros for handling account cancellation requests within the Fenwick Analytics platform. To maintain high retention rates, all support agents must follow the "Save Attempt" flow before deploying the final cancellation confirmation.

### Macro 1: The Save Attempt (Initial Response)
*Use this when a client first submits a ticket requesting cancellation via the Support Portal.*

**Macro Name:** `cancel_save_attempt`
**Content:**
"Hello, I can certainly help you with your account status. Before we proceed with the closure, I noticed your team is currently utilizing our Predictive Modeling suite but hasn't yet integrated the real-time API streaming. Many of our clients find that switching to a 'Maintenance Plan' at $49/month allows them to keep their historical data archives intact without paying for full active seats. Would you be open to exploring a downgraded plan, or perhaps a 30-day pause on billing while you reorganize your internal data pipelines?"

### Macro 2: The Final Confirmation (Standard)
*Use this only after the client declines the save attempt or provides a definitive 'No'.*

**Macro Name:** `cancel_final_confirm`
**Content:**
"I have processed the cancellation for your Fenwick Analytics account. Your access to the dashboard will remain active until the end of your current billing cycle on November 30, 2023. After this date, your workspace will be deactivated. Please note that per our Terms of Service, all raw data exports must be completed via the 'Export All' tool in the Settings menu before the cutoff date, as we purge inactive server caches after 60 days."

### Internal Processing Checklist
Before marking the ticket as "Solved," agents must complete the following backend steps:
1. **Billing Sync:** Update the status to `Pending Cancellation` in Stripe to prevent the next auto-renewal.
2. **CRM Tagging:** Add the tag `Churn_Q4_2023` to the account in Salesforce.
3. **Feedback Loop:** If the client provided a reason (e.g., "Too expensive," "Missing feature"), log this specifically in the *Churn Reason* dropdown menu for the Product Team’s monthly review.
4. **Data Warning:** Ensure the user has been notified about the 60-day data purge window to avoid "lost data" escalation tickets in January.
