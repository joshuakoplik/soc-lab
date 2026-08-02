---
tenant: riverside
department: Support
label: internal
title: 'Support Macro: Password Reset & Account Recovery'
shares: []
contains_pii: false
contains_credential: false
---

# Support Macro: Password Reset & Account Recovery

**Document Owner:** Support Department / IT Help Desk  
**Last Updated:** October 14, 2023  
**Scope:** Internal Support Staff (Tier 1 and Tier 2)

### Overview
This document provides the approved response templates for handling password reset requests within the Riverside Cargo Co. ecosystem. To maintain security compliance with our current freight forwarding certifications, support agents must verify identity before triggering a reset link.

### Identity Verification Protocol
Before applying any macro, you must confirm the user’s identity using the **Two-Point Check**:
1. Verify the employee's unique Staff ID (e.g., RCC-4052).
2. Confirm their current assigned terminal or warehouse location (e.g., Memphis Hub, Port of Savannah).

If the user cannot provide these, escalate the ticket to the Security Lead via the #it-security Slack channel.

---

### Macro 1: Standard Password Reset
**Use Case:** User is locked out of the Riverside Logistics Portal or the Fleet Management System (FMS).

**Template:**
"Hello, thank you for contacting Riverside Support. I have verified your credentials and triggered a password reset email to your company address. Please check your inbox for a message from 'RCC Systems Admin.' 

Note that this link expires in 30 minutes. When creating your new password, ensure it is at least 12 characters long and does not contain your username or birth year. Once updated, please restart the FMS client to sync your credentials."

---

### Macro 2: Multi-Factor Authentication (MFA) Reset
**Use Case:** User has a new mobile device or lost their authenticator app access.

**Template:**
"I have successfully reset your MFA seed for the Riverside Cargo portal. The next time you log in, the system will prompt you to scan a new QR code using the Microsoft Authenticator app. 

If you are currently operating from one of our remote distribution centers and do not have access to a mobile device, please let me know so I can issue a temporary hardware token via the Logistics Manager on duty."

---

### Internal Processing Notes
*   **Ticket Tagging:** All password resets must be tagged as `#access-mgmt` and `#low-priority`.
*   **SLA:** Password resets should be resolved within 2 hours of ticket creation to avoid delays in cargo manifesting.
*   **Escalation:** If a user reports multiple failed login attempts from an unrecognized IP address, do not reset the password; immediately freeze the account and notify IT Security.
