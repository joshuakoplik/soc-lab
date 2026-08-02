---
tenant: fenwick
department: Engineering
label: confidential
title: 'Engineering Runbook: Critical Incident Postmortem Protocol'
shares: []
contains_pii: false
contains_credential: false
---

# Engineering Runbook: Critical Incident Postmortem Protocol

**Document ID:** ENG-RB-042  
**Owner:** Infrastructure & Reliability Team (SRE)  
**Confidentiality Level:** Internal / Highly Restricted  
**Last Updated:** October 14, 2023

### Overview
This document mandates the procedure for analyzing High-Severity (Sev-1 and Sev-2) incidents affecting Fenwick Analytics' core data pipelines and client-facing dashboards. The goal is to move beyond "human error" to identify systemic failures in our distributed architecture. All postmortems must be completed within 72 hours of incident resolution.

### Postmortem Requirements
Every report must be filed in the `incidents-archive` Confluence space and include the following specific technical sections:

**1. The Impact Metric**  
Do not use vague terms like "some users." Quantify the failure using our telemetry data. 
*   *Example:* "The latency spike in the Kinesis stream caused a 42% drop in real-time ingestion for the Fortune 500 tier, affecting 12 enterprise accounts including GlobalLogistics Corp."

**2. The Timeline (UTC)**  
A minute-by-minute audit trail sourced from Slack `#ops-war-room` and PagerDuty logs. This must include:
*   **Detection:** When the Prometheus alert triggered vs. when a human acknowledged it.
*   **Mitigation:** The exact timestamp the rollback to version `v2.4.1` was deployed via Jenkins.

**3. Root Cause Analysis (The Five Whys)**  
Avoid attributing failure to a single developer. Analyze the guardrails. If a manual config change broke the production API, the root cause is not "the engineer forgot the flag," but rather "the CI/CD pipeline lacks a validation schema for `.yaml` configuration files."

### Remediation Tracking
Action items are categorized by priority:
*   **P0 (Immediate):** Must be resolved before the next sprint cycle. These typically involve patching critical security holes or fixing data corruption in the Snowflake warehouse.
*   **P1 (Strategic):** Long-term architectural changes (e.g., migrating from a single-region AWS deployment to Multi-AZ for the Analytics Engine).

### Approval Workflow
Once drafted, the document must be reviewed by the VP of Engineering and the Lead Architect. If an incident resulted in a breach of SLA (Service Level Agreement) resulting in financial credits to clients, the Legal and Account Management teams must be notified via the `sla-breach` email alias before the report is finalized.
