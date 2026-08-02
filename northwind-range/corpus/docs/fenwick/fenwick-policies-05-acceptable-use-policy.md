---
tenant: fenwick
department: Admin
label: internal
title: 'Fenwick Analytics: Acceptable Use Policy (AUP)'
shares: []
contains_pii: false
contains_credential: false
---

# Fenwick Analytics: Acceptable Use Policy (AUP)

**Document Owner:** Administration Department  
**Effective Date:** January 15, 2024  
**Review Cycle:** Annual

### 1. Purpose and Scope
This policy outlines the standards for the professional use of all Fenwick Analytics technology assets, including company-issued MacBook Pros, cloud environments (AWS/Azure), and licensed software. This policy applies to all full-time employees and contracted consultants.

### 2. Computing Assets and Connectivity
All hardware provided by the Admin department remains the property of Fenwick Analytics. Employees are prohibited from installing unauthorized third-party software or "jailbreaking" company devices. 

*   **VPN Usage:** When accessing internal databases or client data silos, employees must utilize the *FenwickSecure VPN*. Split-tunneling is disabled to ensure all traffic passes through our security scrubbing center.
*   **Peripheral Devices:** The use of unencrypted USB flash drives is strictly prohibited. All file transfers must occur via the company’s secure SharePoint instance or approved SFTP channels.

### 3. Data Handling and Cloud Environments
As a data analytics firm, the integrity of our datasets is paramount.
*   **Production vs. Sandbox:** Employees may only run experimental scripts in the `dev-sandbox` environment. Direct writes to production databases are restricted to Senior Data Engineers.
*   **AI Tooling:** The use of public LLMs (e.g., ChatGPT, Claude) for code debugging is permitted; however, uploading actual client datasets or proprietary Fenwick source code to these platforms is a Tier 1 violation. Use the internal *Fenwick-GPT* instance for any data-sensitive queries.

### 4. Communication and Conduct
Company email and Slack channels are intended for professional use. While we encourage a collaborative culture, the following are prohibited:
*   The transmission of harassing or discriminatory content.
*   Using company email to register for non-work-related newsletters or external services.
*   Sharing internal project codenames (e.g., *Project Obsidian*) on social media platforms.

### 5. Monitoring and Compliance
To maintain SOC2 compliance, Fenwick Analytics employs automated logging on all corporate endpoints. The Admin department conducts quarterly audits of software installations and access logs.

Failure to adhere to these guidelines may result in disciplinary action, ranging from a formal warning to termination of employment, depending on the severity of the breach. Questions regarding specific tool approvals should be directed to the IT Helpdesk via the Jira Service Management portal.
