---
tenant: fenwick
department: Admin
label: internal
title: 'Fenwick Analytics: Information Security & Data Handling Policy'
shares: []
contains_pii: false
contains_credential: false
---

# Fenwick Analytics: Information Security & Data Handling Policy

**Policy Owner:** Administration Department  
**Effective Date:** January 15, 2024  
**Review Cycle:** Annual

### 1. Purpose and Scope
This policy establishes the minimum security standards for all employees and contractors at Fenwick Analytics to ensure the integrity of our proprietary analytics engines and the confidentiality of client datasets. This applies to all corporate hardware, cloud environments (AWS/Azure), and remote access points.

### 2. Access Control & Authentication
All staff must utilize the Okta Single Sign-On (SSO) portal for system access. 
*   **Password Requirements:** Passwords must be a minimum of 14 characters and are rotated every 180 days.
*   **Multi-Factor Authentication (MFA):** MFA via the Duo Mobile app is mandatory for all logins. SMS-based authentication is strictly prohibited.
*   **Privileged Access:** Administrative rights to production databases are restricted to the Lead Data Engineer and the CTO. Requests for temporary elevated access must be submitted via a Jira ticket to the Admin department 48 hours in advance.

### 3. Data Classification & Storage
Fenwick Analytics categorizes data into three tiers:
*   **Public:** Marketing materials and published whitepapers.
*   **Internal:** Employee directories, internal memos, and project timelines. Store these on the shared Google Drive.
*   **Restricted:** Client PII (Personally Identifiable Information) and proprietary algorithms. Restricted data must never be stored on local hard drives. It must reside exclusively within our encrypted S3 buckets or the Snowflake Data Cloud.

### 4. Device Security & Remote Work
To maintain a secure perimeter, the following mandates are in effect:
*   **Encryption:** All company laptops must have FileVault (macOS) or BitLocker (Windows) enabled.
*   **VPN Usage:** When working from public Wi-Fi or remote locations, employees must connect via the GlobalProtect VPN before accessing any internal API endpoints.
*   **Clean Desk Policy:** Employees working at the headquarters must lock their workstations (`Cmd+Ctrl+Q` or `Win+L`) whenever leaving their desks.

### 5. Incident Reporting
Any suspected security breach—including lost hardware, phishing attempts, or unauthorized data exports—must be reported to **security-alert@fenwickanalytics.com** within two hours of discovery. Failure to report a known leak may result in disciplinary action up to and including termination.
