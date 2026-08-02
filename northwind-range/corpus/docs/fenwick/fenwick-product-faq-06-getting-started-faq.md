---
tenant: fenwick
department: Support
label: public
title: 'Getting Started with Fenwick Analytics: FAQ'
shares: []
contains_pii: false
contains_credential: false
---

# Getting Started with Fenwick Analytics: FAQ

**Document Owner:** Support Department  
**Last Updated:** October 14, 2023

Welcome to Fenwick Analytics. This guide is designed to help new users navigate the initial setup of the Fenwick Insight Engine and begin generating data visualizations.

### Account & Access

**How do I activate my account?**  
Upon receiving your invitation email from our provisioning team, click the "Activate Account" link. You will be prompted to set a password and configure your Multi-Factor Authentication (MFA) via the Fenwick Authenticator app or SMS.

**Can I integrate my existing data sources?**  
Yes. Fenwick provides native connectors for Snowflake, Google BigQuery, and AWS Redshift. To connect, navigate to *Settings > Data Sources* and enter your warehouse credentials. For legacy CSV or JSON uploads, use the "Bulk Import" tool located in the Data Management tab.

### Platform Basics

**What is a "Data Slice," and how do I create one?**  
A Data Slice is a filtered subset of your primary dataset used for specific reporting. To create one, go to the *Explorer* view, apply your desired filters (e.g., Date Range: Last 90 Days; Region: North America), and select "Save as Slice."

**How long does it take for data to refresh?**  
Depending on your subscription tier, refresh intervals vary. Standard accounts refresh every 24 hours. Enterprise accounts can configure scheduled refreshes every 15 minutes or trigger manual refreshes via the "Sync Now" button in the dashboard header.

### Troubleshooting & Support

**Why am I seeing a "Schema Mismatch" error during upload?**  
This typically occurs when the column headers in your uploaded file do not match the mapped fields in Fenwick. Please ensure your CSV headers exactly match our required naming conventions (e.g., `customer_id` instead of `Customer ID`).

**Where can I find technical documentation?**  
Our full API documentation and User Manual are available at `docs.fenwickanalytics.com`. 

**How do I contact Support?**  
For immediate assistance, you can open a ticket via the "Help" icon in the bottom-right corner of the platform. Our support team is available Monday through Friday, 8:00 AM to 6:00 PM EST. For critical system outages, please email `urgent@fenwickanalytics.com`.
