---
tenant: fenwick
department: Support
label: public
title: 'Fenwick Analytics: Data Privacy & Security FAQ'
shares: []
contains_pii: false
contains_credential: false
---

# Fenwick Analytics: Data Privacy & Security FAQ

**Document Owner:** Support Department  
**Last Updated:** October 14, 2023  
**Status:** Public

This document provides transparency regarding how Fenwick Analytics handles client data and the security protocols we employ to ensure the integrity of your analytics pipelines.

### How is my data stored and encrypted?
All data ingested into the Fenwick ecosystem is encrypted at rest using AES-256 encryption. For data in transit, we utilize TLS 1.3 protocols to prevent interception between your local servers and our cloud environment. Encryption keys are managed through a rotating KMS (Key Management Service) architecture, ensuring that no single administrator has permanent access to raw decryption keys.

### Does Fenwick Analytics use client data to train its global ML models?
No. We maintain a strict "Data Silo" policy. Your proprietary datasets are used exclusively to train your dedicated instance of our predictive models. These weights and parameters are stored in an isolated environment unique to your organization and are never aggregated into the general Fenwick baseline model.

### Which compliance standards do you adhere to?
Fenwick Analytics is fully SOC 2 Type II compliant as of January 2023. We strictly adhere to GDPR guidelines for our European clients and CCPA requirements for California-based entities. Our annual third-party audits are conducted by Sterling & Cross Auditors; current certification reports are available upon request via your Account Manager.

### What is the data retention policy for deleted projects?
When a project is marked for deletion in the Fenwick Dashboard, the data enters a "Soft Delete" state for 30 days, allowing for accidental recovery. After this window expires, we initiate a permanent purge from our primary databases and backup snapshots. The full erasure process is completed within 90 days across all redundant storage nodes.

### How do I request a Data Export or Deletion?
To exercise your right to data portability or erasure:
1. Navigate to **Settings > Privacy Center** in the dashboard.
2. Select "Request Archive" for a full JSON export of your processed metadata.
3. For complete account deletion, submit a ticket through the Support Portal under the category "Privacy Request." Our compliance team will verify your identity and confirm the deletion within five business days.

### Who has access to my raw data?
Access is restricted via the Principle of Least Privilege (PoLP). Only designated Fenwick Site Reliability Engineers (SREs) can access production environments, and only then through a time-bound "Just-in-Time" (JIT) access request tied to a specific support ticket. All such access is logged in an immutable audit trail.
