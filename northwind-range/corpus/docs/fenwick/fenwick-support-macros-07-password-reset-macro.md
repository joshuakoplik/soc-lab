---
tenant: fenwick
department: Support
label: public
title: Password Reset & Account Recovery Macros
shares: []
contains_pii: false
contains_credential: false
---

# Password Reset & Account Recovery Macros

**Document Owner:** Support Department  
**Last Updated:** October 14, 2023  
**Status:** Active / Public Reference

This document outlines the standardized communication macros used by Fenwick Analytics support engineers when assisting clients with credential recovery and password resets for the Fenwick Data Portal. To ensure security compliance and maintain a consistent brand voice, all agents must use these approved scripts.

### Macro: PW-01 | Standard Password Reset
**Trigger:** Client requests a password reset via the support portal or email.  
**Usage:** Use this when the user has access to their registered corporate email address.

*"Hello, thank you for contacting Fenwick Analytics Support. To securely reset your password, please navigate to the login page at portal.fenwickanalytics.com and click the 'Forgot Password' link located below the sign-in fields. You will receive an automated recovery email containing a secure token valid for 24 hours. For security reasons, our support team cannot manually change passwords or send plain-text credentials via email."*

### Macro: PW-02 | MFA Lockout / Token Reset
**Trigger:** Client has lost access to their Multi-Factor Authentication (MFA) device or app.  
**Usage:** Use this when a user is locked out despite having the correct password.

*"It appears you are experiencing an MFA lockout. To restore access to your account, we require a verification request submitted by your organization’s primary Account Administrator. Once the administrator confirms your identity through our Admin Console, we will reset your MFA seed. You will then be prompted to register a new device upon your next successful login. Please coordinate with your internal IT lead to initiate this request."*

### Macro: PW-03 | Expired Credentials
**Trigger:** User is notified that their password has expired per the 90-day security policy.  
**Usage:** Use when users report an 'Expired Credential' error code (Error 402).

*"Your Fenwick Analytics credentials have expired as part of our quarterly security rotation policy. Please follow the prompts on your current login screen to create a new password. Ensure your new password contains at least 12 characters, one uppercase letter, and one special character. If you encounter an error during this process, please provide us with your browser version and operating system."*
