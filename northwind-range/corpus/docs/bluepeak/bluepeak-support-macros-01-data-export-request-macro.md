---
tenant: bluepeak
department: Support
label: public
title: Data Export Request Macro & Protocol
shares: []
contains_pii: false
contains_credential: false
---

# Data Export Request Macro & Protocol

**Document Owner:** Support Department  
**Last Updated:** October 14, 2023  
**Scope:** Client-facing communication regarding bulk data extraction from the Bluepeak POS and Inventory Management Systems.

### Overview
This document provides the standardized response macros for support agents handling requests for historical data exports. To maintain system stability and security, all data export requests must follow the verification process outlined in the Security Compliance Handbook before a ticket is escalated to the Data Engineering team.

### Macro: Initial Request & Verification
*Use this macro when a client first requests a CSV or JSON export of their transactional or inventory records.*

"Thank you for reaching out to Bluepeak Support. I would be happy to assist you with your data export request. To ensure the security of your account and comply with our data privacy policies, please provide the following information:

1. The specific date range required (e.g., January 1, 2023, to September 30, 2023).
2. The specific data modules needed (Transactional History, SKU Inventory Levels, or Customer Loyalty Profiles).
3. Confirmation that the requester is a registered Administrative User on the account.

Once this information is verified, we will initiate the export process. Please note that standard exports typically take 24 to 48 business hours to compile depending on the volume of records."

### Macro: Export Completion & Delivery
*Use this macro once the Data Engineering team has uploaded the encrypted file to the client’s secure portal.*

"We have successfully completed your data export request. For security purposes, we do not send raw data files via email. 

Your files are now available for download through the Bluepeak Client Portal under the 'Secure Downloads' tab. The folder is labeled with your ticket number and today's date. Please note that this link will expire automatically in 7 days. 

If you encounter any formatting issues with the CSV files or require a different delimiter, please reply to this thread and we will adjust the parameters for you."

### Service Level Agreements (SLA)
* **Verification Phase:** 4 business hours from initial contact.
* **Extraction Phase:** 2 business days for datasets under 500k rows; 5 business days for enterprise-level historical archives.
