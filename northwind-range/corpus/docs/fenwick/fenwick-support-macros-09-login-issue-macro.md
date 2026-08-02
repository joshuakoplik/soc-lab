---
tenant: fenwick
department: Support
label: internal
title: Login & Authentication Support Macros
shares: []
contains_pii: false
contains_credential: false
---

# Login & Authentication Support Macros

**Owner:** Support Department  
**Last Updated:** October 14, 2023  
**Scope:** Internal Use Only

This document contains standardized responses for common login-related tickets encountered by Fenwick Analytics clients. When using these macros, ensure you have verified the user's identity via their registered corporate email before modifying account permissions.

### Macro: LGN-01 | Password Reset (Standard)
*Use this when a user reports being locked out or has forgotten their password.*

"Hello, thank you for reaching out to Fenwick Support. I have triggered a password reset link to your registered email address. Please check your inbox (and spam folder) for an email from `no-reply@fenwick-analytics.io`. 

Note that our security policy requires passwords to be changed every 90 days and must contain at least one uppercase letter, one number, and one special character. The reset link will expire in 24 hours."

### Macro: LGN-02 | MFA Synchronization Error
*Use this for users reporting 'Invalid Token' errors despite entering the correct code from their authenticator app.*

"It appears there is a time-drift synchronization issue between your device and our authentication server. To resolve this, please follow these steps:
1. Open the Google Authenticator or Authy app on your mobile device.
2. Go to Settings > Account Actions > Time correction for codes.
3. Select 'Sync now.'
4. Attempt to log into the Fenwick Dashboard again.

If you are still seeing the error, please provide a screenshot of the specific error code (e.g., ERR_MFA_SYNC) so we can escalate this to our DevOps team."

### Macro: LGN-03 | SSO / SAML Configuration Failure
*Use this for enterprise clients using Okta or Azure AD who are receiving 'SAML Response Invalid' errors.*

"We have detected a handshake failure between your identity provider and the Fenwick Analytics portal. This is typically caused by an expired certificate on the client side. 

Please contact your internal IT Administrator to verify that the SAML signing certificate for the `fenwick-prod-04` environment has not expired. Once they update the certificate in your SSO dashboard, you should be able to log in immediately without further intervention from our team."

### Internal Escalation Path
If these macros do not resolve the issue, escalate the ticket to the **Identity Management (IDM) Team** via Slack channel `#ops-auth-support` with the user's UUID and a timestamp of the last failed login attempt.
