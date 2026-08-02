---
tenant: bluepeak
department: Admin
label: internal
title: 'Bluepeak Retail Group: Information Security & Data Handling Policy'
shares: []
contains_pii: false
contains_credential: false
---

# Bluepeak Retail Group: Information Security & Data Handling Policy

**Document Owner:** Administration Department  
**Effective Date:** January 15, 2024  
**Review Cycle:** Annual

### 1. Purpose and Scope
This policy establishes the baseline security requirements for all employees, contractors, and seasonal staff at Bluepeak Retail Group. It applies to all corporate offices, distribution centers, and retail storefronts. The goal is to protect our proprietary inventory data, customer payment information, and internal financial records from unauthorized access or leakage.

### 2. Access Control and Authentication
All employees must utilize the Bluepeak Single Sign-On (SSO) portal for accessing company resources. 
*   **Password Requirements:** Passwords must be a minimum of 12 characters and be rotated every 180 days.
*   **Multi-Factor Authentication (MFA):** MFA via the Okta Verify app is mandatory for all remote logins and access to the "PeakCentral" ERP system.
*   **Account Termination:** Upon termination of employment, the Admin department will revoke all system access within two hours of the exit interview.

### 3. Device and Hardware Security
To prevent data theft at the storefront level:
*   **Point-of-Sale (POS) Terminals:** POS terminals must never be left unattended while logged into an administrative account. All terminals are configured to auto-lock after five minutes of inactivity.
*   **Mobile Devices:** Employees accessing corporate email on personal devices must enroll in the Bluepeak MDM (Mobile Device Management) program, which requires a biometric lock or 6-digit PIN.
*   **USB Usage:** The use of unauthorized USB flash drives is strictly prohibited on any machine connected to the corporate network to prevent malware infiltration.

### 4. Data Classification and Handling
Bluepeak categorizes data into three levels:
1.  **Public:** Marketing materials and store hours. No restrictions.
2.  **Internal:** Store performance reports and employee directories. May be shared via internal Slack channels.
3.  **Restricted:** Customer credit card tokens, payroll data, and vendor contracts. This data must be encrypted at rest and may only be stored in the "SecureVault" directory on the corporate server.

### 5. Incident Reporting
Any suspected security breach—including lost keycards, phishing emails, or misplaced company laptops—must be reported to the Admin Department via the `security-alert@bluepeakretail.com` email address within one hour of discovery. Failure to report a known breach may result in disciplinary action up to and including termination.
