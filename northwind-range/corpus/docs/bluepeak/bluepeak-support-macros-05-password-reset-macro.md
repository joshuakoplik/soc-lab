---
tenant: bluepeak
department: Support
label: internal
title: Password Reset & Account Recovery Macros
shares: []
contains_pii: false
contains_credential: false
---

# Password Reset & Account Recovery Macros

**Department:** Customer Support  
**Document Owner:** Sarah Jenkins, Support Lead  
**Last Updated:** October 14, 2023  
**Access Level:** Internal Only

### Overview
To ensure consistency across our support channels (Zendesk and LiveChat), all agents must use the standardized macros listed below when handling password reset requests. These macros are designed to minimize security risks while maintaining a professional tone for Bluepeak Retail Group customers.

### Macro 1: Standard Password Reset Link
**Trigger:** `password_reset_standard`  
**Use Case:** Use this when a customer reports they have forgotten their password but still has access to their registered email address.

*“Hello, thank you for reaching out to Bluepeak Support. I would be happy to help you get back into your account. For security reasons, we cannot manually change passwords on our end. Please click the ‘Forgot Password’ link on the login page or use this direct link: bluepeakretail.com/account/recovery. You will receive an email with a temporary reset token that expires in 24 hours. If you do not see the email within five minutes, please check your spam folder.”*

### Macro 2: Email Change / No Access to Account
**Trigger:** `password_reset_no_email`  
**Use Case:** Use this when a customer no longer has access to the email address associated with their Bluepeak account.

*“I understand you no longer have access to your registered email. To protect your personal data and payment information, we require identity verification before updating your account details. Please reply to this ticket with a photo of a government-issued ID and your most recent order number from our store. Once our Security Team verifies these details (typically within 2 business days), we will update your primary email address and send you a password reset link.”*

### Macro 3: Locked Account (Too Many Attempts)
**Trigger:** `password_lockout`  
**Use Case:** Use this when a customer is locked out due to five or more failed login attempts.

*“It appears your account has been temporarily locked for security purposes following several unsuccessful login attempts. This lockout lasts for 30 minutes. Please wait until the lockout period expires before attempting another reset. If you continue to experience issues after 30 minutes, please let me know and I can escalate this to our Technical Operations team.”*

### Internal Escalation Path
If a customer claims their account has been compromised (e.g., unauthorized orders), **do not** use these macros. Immediately escalate the ticket to the `Security-Tier2` group via the Zendesk sidebar.
