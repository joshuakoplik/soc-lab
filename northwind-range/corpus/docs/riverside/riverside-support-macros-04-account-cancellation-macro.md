---
tenant: riverside
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

This document provides standardized response macros for handling account closure requests within the Riverside Cargo Co. client portal. All support agents must verify that there are no "Active" or "Pending" shipments in the system before triggering these responses. If a shipment is currently in transit, use the **Hold-Until-Delivery** macro instead.

### Macro 1: Standard Cancellation (No Outstanding Balance)
*Use this when the client has requested closure and their ledger is clear.*

"Hello, we have processed your request to close your Riverside Cargo Co. account. Your access to the Logistics Dashboard will remain active until midnight tonight, after which your login credentials will be deactivated. Please note that while your account is closed, we retain shipping manifests and tax invoices for a period of seven years per federal freight regulations. You can download your final statement from the 'Billing' tab before the end of the day. We are sorry to see you go!"

### Macro 2: Pending Shipment Conflict
*Use this when the client has an open BOL (Bill of Lading) or cargo currently at a terminal.*

"We have received your request to close your account; however, our system shows that Shipment #RCC-99201 is currently in transit from the Savannah Terminal to Chicago. To ensure there are no disruptions in delivery or billing disputes, we cannot finalize the cancellation until this shipment reaches 'Delivered' status. We have placed a temporary hold on your account closure. Once the cargo is signed for, our team will automatically trigger the deactivation process."

### Macro 3: Outstanding Balance Required
*Use this when the client owes funds to the billing department.*

"Before we can proceed with the cancellation of your Riverside Cargo Co. account, there is an outstanding balance of $412.50 on your October invoice. Our company policy requires all freight charges and fuel surcharges to be settled before an account can be formally closed. Please remit payment via the Client Portal or contact Sarah Jenkins in the Billing Department at extension 402 to resolve this. Once payment is confirmed, we will finalize your offboarding immediately."

**Internal Procedure Note:** After sending any of the above, agents must update the CRM status to "Pending Closure" and notify the Account Management team via Slack channel #client-churn.
