---
tenant: fenwick
department: Admin
label: internal
title: Vendor System Access and Security Policy
shares: []
contains_pii: false
contains_credential: false
---

# Vendor System Access and Security Policy

**Policy Owner:** Administration Department  
**Effective Date:** January 15, 2024  
**Last Reviewed:** November 2023

### 1. Purpose
This policy outlines the requirements for granting third-party vendors access to Fenwick Analytics’ internal networks, data warehouses, and physical office locations. The objective is to ensure that vendor presence does not compromise our proprietary analytics frameworks or client data integrity.

### 2. Access Request Procedure
All requests for vendor access must be initiated by a Fenwick Department Head via the **Admin Portal Ticket System**. Requests must include:
*   The specific vendor entity (e.g., CloudScale Infrastructure, DataGuard Security).
*   A defined expiration date for the access (maximum 12 months).
*   A detailed list of required systems (e.g., AWS Production Sandbox, Jira Project Boards).

Once submitted, the Admin Department will coordinate with IT Security to provision a unique **Vendor-ID account**. Generic or shared accounts are strictly prohibited.

### 3. Technical Access Controls
To maintain a Zero Trust environment, all vendor access is subject to the following constraints:
*   **Multi-Factor Authentication (MFA):** All vendors must use Duo Security MFA linked to a company-verified mobile device.
*   **VPN Constraints:** Vendors are granted access only via the **Fenwick-External VPN Gateway**. Access to the core internal subnet is blocked by default unless specifically authorized for a high-priority project.
*   **Session Monitoring:** All activity within the production environment is logged via our AuditTrail software. Admin will perform monthly reviews of vendor logs to ensure no unauthorized data exfiltration has occurred.

### 4. Physical Access
Vendors visiting the Fenwick Analytics headquarters must:
1.  Sign in at the front desk and present a valid government-issued ID.
2.  Wear a **Yellow "Visitor" Badge** at all times while on premises.
3.  Be escorted by their Fenwick point of contact when entering the Server Room or the Secure Data Lab.

### 5. Termination of Access
Upon completion of a contract or reaching the expiration date, the Admin Department will automatically trigger an account lockout. If a vendor employee is terminated from their own firm, the Fenwick project lead must notify the Admin Department within four business hours to ensure immediate revocation of all digital credentials.
