---
tenant: bluepeak
department: Support
label: internal
title: Refund Request Response Macros
shares: []
contains_pii: false
contains_credential: false
---

# Refund Request Response Macros

**Document Owner:** Support Department / Billing Team  
**Last Updated:** October 14, 2023  
**Access Level:** Internal - All Staff

This document contains the standardized response macros for handling refund requests across Bluepeak Retail Group’s e-commerce and brick-and-mortar channels. To ensure consistency in our customer experience, please use these scripts exactly as written, unless a manual override is approved by a Shift Lead.

### Macro 1: Standard Return (Within 30 Days)
**Trigger:** `!refund_standard`  
**Use Case:** The item was returned in original packaging and is within the 30-day window from the date of purchase.

"Thank you for contacting Bluepeak Support. I have successfully processed your refund for Order #BP-9921. A credit of $42.50 has been issued to your original payment method. Please note that depending on your financial institution, it typically takes 3 to 5 business days for the funds to appear in your account. You will receive a confirmation email shortly."

### Macro 2: Late Return (31-60 Days)
**Trigger:** `!refund_late`  
**Use Case:** The item is outside the standard window but qualifies for store credit per our Autumn Grace Period policy.

"While this purchase falls outside our standard 30-day refund window, we would like to offer you a one-time exception. We have issued a Bluepeak Digital Gift Card in the amount of $42.50 to your registered email address. This credit does not expire and can be used across all our online stores and physical boutiques."

### Macro 3: Damaged/Defective Item
**Trigger:** `!refund_damage`  
**Use Case:** Customer provided photo evidence of damage via the Support Portal.

"I am very sorry that your order arrived in less-than-perfect condition. I have initiated a full refund for the defective item, including the original shipping fee of $5.99. There is no need to return the damaged product to our warehouse; please dispose of it according to local recycling guidelines. Your total refund of $48.49 should reflect in your account within 5 business days."

### Internal Procedure Reminders:
*   **Approval Limits:** Support Associates may approve refunds up to $100. Any amount exceeding this requires a signature from the Billing Manager via Slack.
*   **Verification:** Always verify that the return tracking number has been marked as "Delivered" in the Logistics Dashboard before triggering Macro 1.
