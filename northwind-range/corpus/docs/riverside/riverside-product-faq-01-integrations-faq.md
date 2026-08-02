---
tenant: riverside
department: Support
label: internal
title: Riverside Cargo Integrations FAQ
shares: []
contains_pii: false
contains_credential: false
---

# Riverside Cargo Integrations FAQ

**Owner:** Support Department  
**Last Updated:** October 14, 2023  
**Scope:** Internal Use Only

This document provides guidance for Support and Account Management teams regarding the connectivity between our core Logistics Management System (LMS) and third-party partner platforms.

### General Connectivity
**What is the current standard for new integrations?**  
As of Q1 2023, all new partners are onboarded via the Riverside REST API (v3.2). We have deprecated the legacy SOAP interface; any client still using v2.0 must be migrated to v3.2 by March 31, 2024, or they will experience service interruptions.

**How do I verify if a client is successfully syncing data?**  
Navigate to the *Integration Dashboard* in the admin panel and search by Client ID. Check the "Heartbeat" column. A green icon indicates active polling; a yellow icon suggests latency over 300 seconds; red indicates a credential failure or timeout.

### Common Integration Partners
**How does the Shopify-to-Riverside bridge handle customs documentation?**  
The bridge automatically triggers the Commercial Invoice generator when a shipment is flagged as "International." If the client has not mapped their HS Codes in the Shopify product metadata, the order will enter a "Pending Documentation" state. Support should instruct the client to update their SKU mapping in the *Shipping Settings* tab.

**What is the sync frequency for the NetSuite ERP integration?**  
NetSuite data pushes occur every 15 minutes via an asynchronous webhook. If a customer claims a shipment hasn't appeared in NetSuite, wait 20 minutes before escalating to Engineering.

### Troubleshooting & Escalation
**What should I do if a client reports "API Error 403: Forbidden"?**  
This is almost always an expired API Key. Check the *Security* tab in the client profile to see if the token expired. If it has, issue a temporary 24-hour key and instruct the client to regenerate their permanent production key via their portal.

**When should a ticket be escalated to the Integration Engineering team?**  
Escalate only after verifying the following:
1. The API Key is active and valid.
2. The payload format matches the v3.2 documentation.
3. The error persists across multiple different shipments/SKUs.

Include the **Correlation ID** from the logs in all Jira tickets sent to Engineering to reduce resolution time.
