---
tenant: bluepeak
department: Support
label: public
title: Login & Authentication Support Macros
shares: []
contains_pii: false
contains_credential: false
---

# Login & Authentication Support Macros

**Document Owner:** Support Department  
**Last Updated:** October 14, 2023  
**Scope:** Public-facing resolution scripts for Bluepeak Retail customer accounts.

This document contains the standardized responses used by our support team to resolve authentication failures and account access issues. These macros ensure consistent communication across email and live chat channels.

### Macro: Password Reset Failure
*Use this when a customer reports that the "Forgot Password" link is not sending an email or the reset token has expired.*

"Thank you for reaching out to Bluepeak Support. If you haven't received your password reset email, please check your Junk or Spam folders first. Some providers filter our automated system. If it is still missing after 10 minutes, please verify that the email address on file is correct. For security reasons, we cannot manually send passwords via chat; however, I can trigger a fresh reset link to your registered email address right now. Please let me know if you would like me to proceed."

### Macro: Account Lockout (Security)
*Use this when an account has been locked due to five consecutive failed login attempts.*

"For your protection, the Bluepeak security system has temporarily locked your account following several unsuccessful login attempts. This lockout lasts for 30 minutes. You may attempt to log in again after this window expires. If you are unsure of your credentials, we recommend using the 'Forgot Password' utility on the login page rather than attempting further guesses, as this will reset the lockout timer."

### Macro: Multi-Factor Authentication (MFA) Sync
*Use this when a customer is not receiving the 6-digit SMS verification code.*

"We apologize for the delay in receiving your verification code. Please ensure your device has a stable cellular signal and that you are not using a VPN, as this can sometimes interfere with SMS delivery. If you have waited more than five minutes, please click 'Resend Code.' If the issue persists, please provide the last four digits of the phone number associated with your account so we can verify if there is a carrier block on our sending short-code."

### Macro: Browser Cache & Cookie Conflict
*Use this when the user experiences a 'Looping' login screen where they are prompted to log in repeatedly.*

"It appears your browser may be storing an outdated session cookie. Please clear your browser cache and cookies for bluepeakretail.com, then restart your browser. Alternatively, try logging in via an Incognito or Private window to determine if a browser extension is interfering with the authentication process."
