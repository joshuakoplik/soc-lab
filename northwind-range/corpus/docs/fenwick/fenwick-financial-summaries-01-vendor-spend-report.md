---
tenant: fenwick
department: Finance
label: confidential
title: Q3 FY24 Vendor Expenditure & Variance Analysis
shares: []
contains_pii: true
contains_credential: false
---

# Q3 FY24 Vendor Expenditure & Variance Analysis

**Owner:** Finance Department  
**Date:** October 14, 2024  
**Classification:** Confidential – Internal Use Only

### Executive Summary
Total vendor spend for Q3 reached $2.84M, representing a 12% increase over Q2. This surge is primarily attributed to the migration of our primary data lake to Snowflake and the onboarding of three new strategic partnerships for GPU compute capacity. While operational expenses (OpEx) remain within the broader annual budget, we have observed significant variance in "Cloud Infrastructure" and "Third-Party Data Licensing" categories.

### Expenditure Breakdown & Variance
**1. Cloud Infrastructure (AWS/Snowflake)**  
Actual spend: $1.42M | Budgeted: $1.15M | **Variance: +$270k**  
The variance is driven by unplanned scaling of the "Project Helios" analytics engine during August. We experienced a spike in compute costs due to inefficient query optimization on the legacy datasets being migrated. Finance is coordinating with the Engineering lead to implement stricter resource tagging and auto-scaling caps for Q4.

**2. Data Licensing (Bloomberg/Refinitiv/S&P Global)**  
Actual spend: $610k | Budgeted: $650k | **Variance: -$40k**  
Under-spend is due to the successful renegotiation of the Refinitiv contract, moving from a per-seat model to an enterprise flat fee.

**3. Professional Services & SaaS (Datadog/Okta/Consulting)**  
Actual spend: $810k | Budgeted: $750k | **Variance: +$60k**  
Costs increased due to a one-time integration fee paid to Scale AI for labeling services associated with the new predictive modeling module.

### Procurement Compliance & Audit Trail
During the Q3 audit, Finance identified two instances of "shadow IT" spending where departmental leads bypassed the central procurement process. Specifically, we flagged an unauthorized $12k annual subscription for a proprietary sentiment analysis tool purchased via corporate credit card by Sarah Jenkins (s.jenkins@fenwick-analytics.io | Ext: 4402). Moving forward, all software acquisitions exceeding $500 must be routed through the Jira Procurement Ticket system and approved by the CFO's office prior to purchase.

### Q4 Outlook
To offset the Q3 overage in cloud spend, Finance will freeze new third-party tool procurement until January 1st. We expect a $200k rebate from AWS based on our committed use discounts (CUDs) hitting in November, which should bring the year-end variance down to <4%.
