---
tenant: riverside
department: Engineering
label: internal
title: 'Load Balancer Operational Runbook: Edge-Gateway Cluster'
shares: []
contains_pii: false
contains_credential: false
---

# Load Balancer Operational Runbook: Edge-Gateway Cluster

**Document Owner:** Engineering / Infrastructure Team  
**Last Updated:** October 14, 2023  
**Status:** Active

### Overview
This document outlines the procedures for managing the F5 BIG-IP and AWS Application Load Balancers (ALB) that handle incoming traffic for Riverside Cargo’s primary logistics portal and the API gateway used by our fleet tracking mobile apps.

### Traffic Distribution Logic
Our architecture utilizes a weighted round-robin distribution across three availability zones (us-east-1a, 1b, and 1c). The primary health check is configured to ping `/health/ready` on port 8080 every 5 seconds. A node is marked "Down" after three consecutive failures.

### Common Procedures

#### 1. Adding a New Target Node
When scaling the `cargo-api-service` during peak shipping seasons (Q4), follow these steps to add new EC2 instances to the target group:
1. Ensure the instance has passed its local smoke test on port 8080.
2. Navigate to the AWS Console $\rightarrow$ EC2 $\rightarrow$ Target Groups $\rightarrow$ `tg-riverside-api-prod`.
3. Select **Register targets** and select the new instances from the list.
4. Monitor the "Health status" column; it should transition from `initial` to `healthy` within 60 seconds.

#### 2. Performing a Graceful Drain (Maintenance)
To remove a node for patching without dropping active freight bookings:
1. Set the target state to **Draining**.
2. The deregistration delay is set to 300 seconds. This allows existing TCP connections to complete their requests before the LB stops sending new traffic.
3. Once "Draining" status is confirmed, proceed with the server shutdown.

#### 3. Handling 502 Bad Gateway Spikes
If CloudWatch alerts trigger for a spike in 502 errors:
1. Check the `lb-access-logs` in S3 to determine if the error is isolated to a specific AZ.
2. Verify if the backend service pods are crashing (OOMKilled) by running `kubectl get pods -n logistics`.
3. If a specific node is flapping, manually set it to **Out of Service** to prevent "black-holing" traffic while the Engineering team investigates the root cause.

### Escalation Path
If load balancer latency exceeds 500ms for more than 5 minutes:
*   **Primary:** On-call SRE (via PagerDuty)
*   **Secondary:** Infrastructure Lead (Marcus Thorne)
*   **Tertiary:** AWS Enterprise Support Account Manager
