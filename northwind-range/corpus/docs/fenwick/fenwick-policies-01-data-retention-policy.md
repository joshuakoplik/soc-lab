---
tenant: fenwick
department: Admin
label: confidential
title: 'Fenwick Analytics: Corporate Data Retention and Disposal Policy'
shares: []
contains_pii: false
contains_credential: false
---

# Fenwick Analytics: Corporate Data Retention and Disposal Policy

**Document ID:** FA-ADM-2024-08  
**Owner:** Administration Department / Compliance Office  
**Effective Date:** January 15, 2024  
**Review Cycle:** Annual

### 1. Purpose and Scope
This policy establishes the mandatory retention periods for all data assets handled by Fenwick Analytics to ensure regulatory compliance (GDPR, CCPA) and to mitigate legal liability associated with over-retention of client PII. This applies to all employees, contractors, and third-party vendors accessing the Fenwick internal network and cloud environments.

### 2. Retention Schedules
Data must be categorized upon ingestion into our proprietary "Fenwick Lake" environment. The following retention windows are non-negotiable:

*   **Client Raw Data Sets:** All raw telemetry and data feeds provided by clients for analysis shall be retained for the duration of the active Service Level Agreement (SLA) plus 12 months. Upon contract termination, raw data must be purged from all production servers within 30 days.
*   **Processed Analytical Insights:** Final reports, dashboards, and derived insights are archived for seven years to support longitudinal benchmarking and audit trails.
*   **Employee Personnel Records:** All HR records, including payroll and tax documentation, are retained for ten years following the termination of employment.
*   **System Logs & Audit Trails:** Application logs from our analytics engine (Fenwick-Core) and VPC flow logs are retained for 180 days in Hot Storage (S3 Standard) and moved to Cold Storage (Glacier) for an additional two years before permanent deletion.

### 3. Disposal Procedures
Manual deletion is insufficient for sensitive assets. The following protocols must be followed:

1.  **Digital Assets:** All data slated for disposal must undergo a cryptographic erasure (Crypto-erase) by rotating and destroying the encryption keys associated with that specific data bucket. The Admin department will verify deletion via a monthly "Purge Report."
2.  **Physical Media:** Any decommissioned hardware, including NVMe drives from the on-site staging server, must be physically shredded by our approved vendor, IronMountain, with a signed Certificate of Destruction filed with the Compliance Office.

### 4. Legal Hold
In the event of an active litigation or government investigation, the Admin department will issue a "Legal Hold" notice via Jira. This notice overrides all standard retention schedules. No data subject to a Legal Hold may be deleted or modified until the hold is formally lifted in writing by General Counsel.
