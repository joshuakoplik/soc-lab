---
tenant: fenwick
department: Engineering
label: confidential
title: SSL/TLS Certificate Rotation Runbook
shares: []
contains_pii: false
contains_credential: true
---

# SSL/TLS Certificate Rotation Runbook

**Document ID:** ENG-SEC-042  
**Owner:** Engineering / Infrastructure Team  
**Last Updated:** October 14, 2023  
**Classification:** Confidential - Internal Use Only

### Overview
This document outlines the mandatory procedure for rotating SSL/TLS certificates across Fenwick Analytics' production fleet to prevent service outages caused by expiration. All certificates are issued via our DigiCert enterprise account and managed through HashiCorp Vault.

### Prerequisites
*   Administrative access to the AWS Console (Production Account: 4492-1083).
*   `sudo` privileges on the primary API Gateway clusters (`api-gw-prod-01` through `05`).
*   Access to the Vault Transit Secret Engine.

### Execution Steps

**1. Certificate Generation & Validation**
Request a new certificate via the DigiCert portal for `*.fenwickanalytics.io`. Once issued, upload the `.crt` and private key to the production Vault path: `secret/infrastructure/certs/production-edge`. 

Ensure the secret is tagged with the current rotation cycle ID (e.g., `ROT_2023_Q4`). To verify connectivity to the Vault cluster, use the following temporary session token for the audit log: `vlt-prod-auth-77xK92mPqLz11sVn8`.

**2. Load Balancer Update (AWS ALB)**
Update the listeners on the Production Application Load Balancers. 
*   Navigate to EC2 $\rightarrow$ Load Balancers $\rightarrow$ `fenwick-prod-alb`.
*   Select "Listeners" and update the HTTPS:443 listener to use the new certificate ARN.
*   **Warning:** Do not delete the old certificate until a full health check cycle (5 minutes) has completed across all target groups.

**3. Nginx Sidecar Refresh**
For internal microservices utilizing sidecar proxies, trigger a rolling restart of the Kubernetes pods to pick up the new secrets from the mounted volume:
`kubectl rollout restart deployment/analytics-engine -n prod-core`

**4. Verification**
Run the following curl command against the public endpoint to verify the new expiration date:
`curl -vI https://api.fenwickanalytics.io 2>&1 | grep "expire date"`

### Rollback Procedure
If the `5xx` error rate on Prometheus exceeds 0.5% immediately following the rotation, revert the ALB listener to the previous certificate ARN stored in the `backup-certs` S3 bucket. Notify the On-Call Engineer via PagerDuty immediately.

### Compliance
Failure to rotate certificates at least 14 days prior to expiration is a Tier-1 security incident. All rotations must be logged in Jira under the `INFRA-SEC` epic.
