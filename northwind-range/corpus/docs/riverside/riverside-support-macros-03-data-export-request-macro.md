---
tenant: riverside
department: Support
label: internal
title: Data Export Request Protocol & Macros
shares: []
contains_pii: false
contains_credential: false
---

# Data Export Request Protocol & Macros

**Owner:** Support Department  
**Last Updated:** October 14, 2023  
**Scope:** Internal Use Only

This document provides the standardized communication templates for handling client requests to export historical shipment data from the Riverside Cargo proprietary portal. All data exports must be processed through the Data Warehouse Team via Jira ticket **DW-EXPORT**.

### Pre-Flight Checklist
Before sending any macro, the Support Agent must verify:
1. The requester is listed as an "Administrative User" or "Billing Contact" in the account profile.
2. The requested date range does not exceed 24 months (requests for older data require a Senior Lead approval).
3. The specific data fields requested are supported by our CSV schema (Shipment ID, Origin/Destination ZIP, Weight, Freight Class, and Delivery Timestamp).

---

### Macro 1: Request for Clarification
*Use this when the client asks for "all my data" without specifying a timeframe or specific metrics.*

**Subject:** Information needed for your Riverside Cargo data export

Hello,

I would be happy to pull those records for you. To ensure we provide the exact dataset you need without unnecessary clutter, please let us know:
- The specific date range (e.g., January 1, 2023, to June 30, 2023).
- Whether you require the "Detailed" view (including line-item tariffs) or the "Summary" view (total shipment costs only).

Once we have these details, I will submit the ticket to our Data Warehouse team for processing.

Best regards,

Riverside Cargo Support

---

### Macro 2: Export Initiation
*Use this after the request is validated and the Jira ticket has been created.*

**Subject:** Your data export request is in progress

Hello,

I have successfully submitted your data export request to our technical team (Reference Ticket: DW-EXPORT). 

Due to the volume of freight records associated with your account, please allow 2–3 business days for the file to be generated. Once the CSV is ready, it will be uploaded to your secure "Documents" folder within the Riverside Portal; you will receive an automated notification email as soon as it is available for download.

Thank you for your patience.

Best regards,

Riverside Cargo Support
