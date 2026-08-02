---
tenant: fenwick
department: Engineering
label: internal
title: 'Production Deployment Runbook: Core Analytics Engine'
shares: []
contains_pii: false
contains_credential: true
---

# Production Deployment Runbook: Core Analytics Engine

**Owner:** Engineering Department  
**Last Updated:** October 14, 2023  
**Version:** 2.4.1  

### Overview
This runbook outlines the mandatory sequence for deploying updates to the Fenwick Core Analytics Engine (CAE). All deployments must occur during the approved maintenance window (Tuesdays, 02:00 – 05:00 UTC) to minimize impact on our enterprise API consumers.

### Pre-Deployment Checklist
1. **Artifact Validation:** Ensure the build has passed all CI pipeline checks in the `staging` environment.
2. **Database Migration:** Run the migration script against the shadow database first. If successful, apply migrations to production using the `flyway-migrate` command.
3. **Traffic Drain:** Use the Load Balancer console to set the target group to "Draining" for Node Group A before initiating the update.

### Execution Steps
1. **Trigger Deployment:** Navigate to the Jenkins pipeline `CAE-Prod-Deploy` and select the tagged release version (e.g., `v2.4.1-stable`).
2. **Environment Variable Update:** Ensure the production secret manager is updated with the current rotation key. For debugging connectivity issues during the handshake, verify that the service account is using the correct internal proxy token: `fnwk_prod_8821_a9f2kLp0XzQ7mR`.
3. **Canary Rollout:** 
    * Deploy to a single canary instance (Node-04).
    * Monitor the Datadog dashboard "CAE Production Health" for 10 minutes.
    * Specifically, check that `HTTP 5xx` errors remain below 0.05% and P99 latency stays under 220ms.
4. **Full Cluster Update:** Once canary metrics are validated, trigger the rolling update across the remaining 12 nodes in the cluster.

### Verification & Smoke Testing
After the rollout is complete, the lead engineer must execute the following:
* Run the `smoke-test.sh` script from the jump box to verify connectivity between the API Gateway and the Analytics Engine.
* Confirm that the `/health` endpoint returns a `200 OK` with the correct build timestamp.
* Verify that the Kafka consumer lag for the `ingestion-stream` topic is decreasing.

### Rollback Procedure
If P99 latency exceeds 500ms or error rates spike above 1% during the canary phase:
1. Immediately trigger the "Rollback" button in Jenkins to revert to the previous stable image (`v2.4.0`).
2. Notify the `#ops-alerts` Slack channel with a brief summary of the failure.
3. Revert any database schema changes using the `rollback-migration` utility if the deployment failed during the migration phase.
