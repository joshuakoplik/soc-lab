---
tenant: bluepeak
department: Support
label: internal
title: Billing Dispute Response Macros
shares: []
contains_pii: true
contains_credential: false
---

# Billing Dispute Response Macros

**Document Owner:** Support Department / Billing Operations  
**Last Updated:** October 14, 2023  
**Access Level:** Internal – All Staff

### Overview
This document provides standardized response templates for the Bluepeak Retail Group support team to ensure consistency and compliance when handling customer billing inquiries. All agents must verify the account status in the *PeakView CRM* before deploying these macros.

---

### Macro 1: Initial Acknowledgment (Investigation Phase)
**Trigger:** `!bill-investigate`  
**Use Case:** Use this when a customer reports an overcharge or an unknown transaction that requires a manual audit of the transaction logs.

*"Thank you for bringing this to our attention. I have opened a formal billing inquiry ticket (Ref: BP-9920) regarding the discrepancy in your last statement. Our Finance Team typically completes these audits within 3–5 business days. We will notify you via email as soon as the reconciliation is complete."*

### Macro 2: Approved Refund/Credit
**Trigger:** `!bill-refund`  
**Use Case:** Use this once a dispute has been validated and the refund has been triggered in the payment gateway.

*"We have successfully processed a correction for your account. A credit of $42.50 has been applied to your original payment method. Please note that depending on your banking institution, it may take 5–10 business days for these funds to appear in your balance."*

### Macro 3: Dispute Denied (Policy-Based)
**Trigger:** `!bill-deny`  
**Use Case:** Use this when the charge is valid based on the Bluepeak Terms of Service (e.g., missed cancellation window).

*"After reviewing your account and the transaction timestamp, we have determined that the charge is valid. Per our Subscription Agreement dated January 1st, cancellations must be submitted 48 hours prior to the renewal date to avoid automatic billing."*

---

### Escalation Procedure & PII Handling
If a customer provides sensitive documentation (such as bank statements) via email, agents must redact all non-essential information before uploading the file to the internal ticket. 

**Example of correct PII logging in CRM notes:**  
*"Customer Sarah Jenkins (s.jenkins82@emailfake.com | ID: BP-44910) provided a PDF statement showing a double charge on Sept 12th; verified against Stripe logs."*

Any dispute exceeding $500 must be escalated immediately to the Billing Supervisor via the `#support-billing-leads` Slack channel.
