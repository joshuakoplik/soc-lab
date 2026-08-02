---
tenant: riverside
department: Support
label: public
title: Bug Report Triage & Response Macros
shares: []
contains_pii: false
contains_credential: false
---

# Bug Report Triage & Response Macros

**Document Owner:** Support Department  
**Last Updated:** October 14, 2023  
**Version:** 2.1

This document provides standardized response macros for the Riverside Cargo Co. support team when handling technical glitches within the Client Portal and the FleetTrack Mobile App. These macros ensure consistent communication while critical data is gathered for the Engineering team.

### Macro 1: Initial Triage (Information Gathering)
*Use this macro when a client reports a bug that lacks specific reproduction steps or environment details.*

"Thank you for bringing this to our attention. To help our technical team resolve this quickly, please provide the following details:
1. The Bill of Lading (BOL) number associated with the error.
2. A screenshot of the error message or the specific screen where the behavior occurs.
3. The device and browser version you are using (e.g., Chrome v118 on Windows 11).
4. Whether this is affecting a single shipment or all active loads in your dashboard.

Once we have these details, we will escalate this to our Level 2 Technical team for investigation."

### Macro 2: Confirmed Bug / Escalated to Engineering
*Use this macro once the bug has been reproduced internally and a Jira ticket has been created.*

"We have successfully reproduced the issue you reported regarding the automated customs documentation trigger. Our engineering team has logged this as a high-priority bug (Ticket #RCC-4022). 

While they work on a permanent fix, please use the Manual Override toggle in the Shipping menu to push your documents through. We expect a resolution in the next sprint deployment, currently scheduled for Friday at 11:00 PM EST. We will notify you as soon as the patch is live."

### Macro 3: Resolution & Verification
*Use this macro after Engineering confirms a fix and it has been verified in the staging environment.*

"The issue affecting the FleetTrack GPS ping intervals has been resolved in version 4.2.1 of the mobile app. Please visit the App Store or Google Play Store to update your application. 

Once updated, please clear your cache and restart the app. If you continue to see discrepancies in your real-time tracking, please reply to this thread immediately so we can perform a deeper audit of your specific account settings."
