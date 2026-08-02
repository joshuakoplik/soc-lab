---
tenant: bluepeak
department: Engineering
label: internal
title: 'Production Deployment Runbook: Core Commerce Engine'
shares: []
contains_pii: false
contains_credential: false
---

# Production Deployment Runbook: Core Commerce Engine

**Owner:** Engineering Department  
**Last Updated:** October 14, 2023  
**Scope:** This document outlines the mandatory procedure for deploying updates to the Bluepeak Core Commerce Engine (CCE) and associated storefront APIs.

### 1. Pre-Deployment Requirements
Deployments are permitted only during the maintenance window: **Tuesdays and Thursdays from 02:00 AM to 05:00 AM EST**. Before initiating a build, the Lead Engineer must verify:
*   The release candidate has passed all automated regression tests in the `stg-bluepeak` environment.
*   A signed-off "Go/No-Go" confirmation is posted in the `#ops-deployments` Slack channel.
*   Database migrations have been vetted by the DBA team for potential table locks on the `orders_main` table.

### 2. Execution Steps
All deployments are executed via the Jenkins pipeline using the `prod-commerce-deploy` job.

1.  **Traffic Shift:** Initiate a Canary deployment by routing 5% of traffic to the new version (Green environment) via the F5 Load Balancer.
2.  **Database Migration:** Run the Liquibase update script. If the migration takes longer than 300 seconds, trigger an immediate alert to the On-Call Engineer.
3.  **Health Check Validation:** Monitor the Datadog dashboard `BP-Prod-Commerce-Health`. Ensure that:
    *   HTTP 5xx error rates remain below 0.1%.
    *   P99 latency for the `/checkout` endpoint stays under 450ms.
4.  **Full Cutover:** Once health checks are stable for 15 minutes, shift traffic to 100% on the Green environment and decommission the Blue pods.

### 3. Rollback Procedure
If any critical KPI drops or if a "Severity 1" bug is reported during the Canary phase, follow these steps:
*   **Immediate Revert:** Select the `Rollback to Previous Stable` option in Jenkins. This points the F5 Load Balancer back to the Blue environment (current stable).
*   **DB Recovery:** If a destructive migration occurred, restore the `orders_main` table from the snapshot taken at 01:45 AM EST via AWS RDS.
*   **Notification:** Notify the Stakeholder group and the VP of Engineering immediately upon initiating a rollback.

### 4. Post-Deployment
After successful cutover, the deploying engineer must perform a manual smoke test on the production storefront (specifically the "Add to Cart" and "Payment Gateway" flows) and post the "Deployment Complete" timestamp in the `#ops-deployments` channel.
