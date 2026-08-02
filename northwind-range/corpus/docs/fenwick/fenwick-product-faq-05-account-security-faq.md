---
tenant: fenwick
department: Support
label: internal
title: Fenwick Account Security & Access FAQ
shares: []
contains_pii: false
contains_credential: false
---

# Fenwick Account Security & Access FAQ

**Document Owner:** Support Department  
**Last Updated:** October 12, 2023  
**Status:** Internal Use Only

This document provides guidance for Support and Customer Success teams when handling security-related inquiries from Fenwick Analytics clients.

### General Authentication
**What is the standard password policy for the Fenwick Platform?**  
All user accounts must utilize passwords of at least 12 characters, including one uppercase letter, one number, and one special character. Passwords expire every 180 days. Users are prohibited from reusing any of their previous five passwords.

**Does Fenwick support Single Sign-On (SSO)?**  
Yes. We support SAML 2.0 integration. Enterprise tier clients can integrate with Okta, Azure AD, and Ping Identity. If a client reports an SSO loop, verify that the metadata XML file was updated during their last certificate rotation.

### Multi-Factor Authentication (MFA)
**Is MFA mandatory for all users?**  
MFA is mandatory for all accounts with "Admin" or "Data Architect" permissions. For "Viewer" roles, it is optional but highly recommended. We currently support TOTP via Google Authenticator and Authy; SMS-based MFA is disabled due to security vulnerabilities.

**How do I handle a request for an MFA reset?**  
To prevent social engineering attacks, Support cannot reset MFA based on email requests alone. You must verify the user via one of two methods:
1. A confirmed video call with the account's registered Primary Administrator.
2. Submission of a signed "Identity Verification Form" uploaded through the secure client portal.

### Account Recovery & Lockouts
**What triggers an automatic account lockout?**  
An account is temporarily locked for 30 minutes after five consecutive failed login attempts within a 15-minute window. 

**Can Support manually unlock an account?**  
Yes. After verifying the user's identity, you may trigger a manual unlock via the *Admin Control Panel > User Management* tab. Please log all manual unlocks in the Jira ticket under the "Security Audit" component.

### Data Access & Permissions
**Who can grant "Super-User" access?**  
Only the designated Organization Owner for each client account can assign Super-User roles. If the Owner has left the company, the new owner must be appointed via a formal request from the client's corporate legal or IT department.

**How often are inactive accounts purged?**  
Accounts that have not logged in for 90 consecutive days are automatically disabled. Data is retained for an additional 30 days before permanent deletion occurs.
