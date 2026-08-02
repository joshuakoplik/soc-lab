---
tenant: fenwick
department: Support
label: public
title: 'Fenwick Analytics: Integrations FAQ'
shares: []
contains_pii: false
contains_credential: false
---

# Fenwick Analytics: Integrations FAQ

**Document Owner:** Support Department  
**Last Updated:** October 14, 2023

This document provides technical guidance and common troubleshooting steps for connecting your existing data stacks to the Fenwick Analytics platform.

### General Connectivity
**Which platforms does Fenwick currently support?**
We offer native, one-click integrations for Snowflake, Google BigQuery, Amazon Redshift, and MongoDB Atlas. For users utilizing legacy SQL Server or PostgreSQL environments, we provide a dedicated Fenwick Connector agent that can be installed on your local server to facilitate secure data tunneling.

**How long does the initial synchronization take?**
For datasets under 500GB, the initial "Cold Sync" typically completes within 4 to 6 hours. Larger enterprise datasets may take up to 24 hours. Once the Cold Sync is finished, Fenwick switches to "Incremental Refresh," which updates your dashboards every 15 minutes.

### Authentication & Security
**Does Fenwick store my source credentials?**
No. We utilize OAuth 2.0 for cloud providers and AES-256 encrypted secret vaults for database strings. Your credentials are used solely to establish the handshake between the source and our analytics engine; they are never stored in plain text or accessible to Fenwick staff.

**How do I handle firewall restrictions?**
If your data is behind a corporate firewall, you must whitelist the Fenwick Static IP range (203.0.113.0/24) in your network security settings. If your organization requires a PrivateLink or VPC Peering setup, please open a ticket with our Engineering team for custom configuration.

### Troubleshooting & Limits
**Why am I seeing a "Schema Mismatch" error?**
This usually occurs when a column type is changed in the source database (e.g., changing an Integer to a String) without updating the Fenwick mapping. To resolve this, navigate to **Settings > Data Sources**, select your integration, and click "Refresh Schema."

**Are there limits on how many tables I can sync?**
Standard accounts may sync up to 50 individual tables per source. Enterprise accounts have unlimited table synchronization. If you reach your limit, you can archive unused tables in the Integration Manager to make room for new data streams.

**Who do I contact for custom API integrations?**
For sources not listed in our native library, Fenwick provides a robust REST API. You can find the full documentation at `developer.fenwickanalytics.com`. For guided implementation, please contact your Account Manager.
