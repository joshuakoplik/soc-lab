---
tenant: fenwick
department: HR
label: internal
title: 'Fenwick Analytics: New Hire Integration Guide'
shares: []
contains_pii: true
contains_credential: false
---

# Fenwick Analytics: New Hire Integration Guide

Welcome to the team. This document outlines the mandatory operational steps for your first 14 days at Fenwick Analytics. Our goal is to move you from "orientation" to "contribution" as efficiently as possible while ensuring all compliance hurdles are cleared.

### Phase 1: Administrative Setup (Days 1-3)
Your primary point of contact for hardware and access is the IT Help Desk. Upon arrival, you will be issued a Fenwick-encrypted MacBook Pro and a YubiKey for multi-factor authentication. You must complete the following in the Workday portal by the end of your second business day:
*   **Direct Deposit:** Upload a voided check or bank authorization letter.
*   **Benefits Enrollment:** Select your health plan (BlueCross or Kaiser) and 401k contribution percentage.
*   **Tax Documentation:** Complete federal and state withholding forms.

For example, when entering your personal details in the HRIS system, ensure your record matches your legal ID exactly: *Jordan M. Sterling, Employee ID #FA-9928, j.sterling@fenwickanalytics.io*.

### Phase 2: Technical Onboarding (Days 4-7)
As a data-driven organization, access to our proprietary environments is strictly controlled. You are required to complete the "Data Privacy & Ethics" module on the Learning Management System (LMS) before requesting production access. Once certified, submit a Jira ticket to the DevOps team to request permissions for:
1.  **Snowflake Data Warehouse:** Read-only access to the `RAW_PROD` schema.
2.  **GitHub Enterprise:** Access to the `fenwick-core` and `client-dashboards` repositories.
3.  **Slack Channels:** Join `#announcements`, `#tech-stack`, and your specific departmental channel (e.g., `#team-predictive-modeling`).

### Phase 3: Integration & Mentorship (Days 8-14)
You have been paired with an "Onboarding Buddy"—a peer outside your immediate reporting line who will help you navigate the company culture. You are expected to schedule a 30-minute introductory coffee chat with your buddy and three key stakeholders identified by your manager during your first one-on-one meeting.

By the end of week two, you should have a scheduled "Initial Expectations" sync with your Director to define your KPIs for the first 90 days. Failure to complete the LMS modules or HR paperwork by Day 14 may result in a delay of system permissions.
