---
tenant: bluepeak
department: Support
label: internal
title: Account Cancellation & Retention Macros
shares: []
contains_pii: false
contains_credential: false
---

# Account Cancellation & Retention Macros

**Document Owner:** Support Department / Customer Experience Team  
**Last Updated:** October 14, 2023  
**Status:** Active

### Overview
This document provides standardized responses for handling account closure requests across our digital storefronts. Per the Q3 Retainment Strategy, agents must attempt one "Save Offer" before proceeding with final cancellation. All cancellations must be logged in the Zendesk CRM under the category "Churn: Voluntary."

---

### Macro 1: The Initial Save (Soft Retention)
*Use this when a customer first requests a cancellation via chat or email.*

**Response:**
"I am sorry to hear you are looking to close your Bluepeak account. Before we proceed, I noticed you have an active PeakRewards membership. To thank you for your loyalty, I can apply a $20 credit to your balance and provide free expedited shipping on your next three orders if you choose to stay with us. Would you like me to apply these credits to your account now?"

---

### Macro 2: Final Confirmation (Standard)
*Use this once the customer has declined the save offer or requested immediate closure.*

**Response:**
"As requested, I have initiated the cancellation of your Bluepeak Retail Group account. You will receive a confirmation email at your registered address within 24 hours. Please note that any remaining Bluepeak Gift Card balances must be spent prior to today’s date, as these are forfeited upon account closure. Your order history will be archived for 90 days per our data policy before being permanently deleted."

---

### Macro 3: Subscription-Only Cancellation
*Use this for customers who wish to keep their retail account but cancel the 'PeakPass' monthly subscription.*

**Response:**
"I have successfully cancelled your PeakPass monthly subscription. You will continue to have access to your member benefits until the end of your current billing cycle on November 12th. After this date, your account will revert to a Standard Member profile. No further monthly charges will be applied to your card ending in 4402."

---

### Internal Handling Procedures
1. **Verification:** Ensure the user is verified via two-factor authentication or email confirmation before executing Macro 2.
2. **Refunds:** If the customer mentions a double-charge within the last 30 days, escalate the ticket to the Billing Tier 2 team (Slack channel: #billing-escalations) before closing the account.
3. **Feedback:** Always ensure the "Reason for Leaving" dropdown is filled in the CRM (e.g., Pricing, Competitor, Technical Issues).
