---
tenant: bluepeak
department: Engineering
label: internal
title: 'Bluepeak Retail Group: Load Balancer Operations Runbook'
shares: []
contains_pii: false
contains_credential: false
---

# Bluepeak Retail Group: Load Balancer Operations Runbook

**Document Owner:** Engineering / Infrastructure Team  
**Last Updated:** October 14, 2023  
**Classification:** Internal Use Only

## Overview
This runbook provides the standard operating procedures for managing the F5 BIG-IP and AWS Application Load Balancers (ALBs) that handle traffic for Bluepeak’s e-commerce storefront and internal inventory management systems. The primary goal is to ensure 99.99% availability during peak retail windows, specifically targeting high-traffic events like Black Friday and Cyber Monday.

## Traffic Distribution & Health Checks
All production traffic enters through the Edge Gateway before being routed to specific service clusters.
*   **Storefront ALB:** Routes traffic to the `bp-web-prod` auto-scaling group across three availability zones (us-east-1a, 1b, and 1c).
*   **Inventory API LB:** Handles requests for the warehouse management system using a round-robin algorithm.

**Health Check Configuration:**
The Load Balancers are configured to poll the `/health` endpoint of each target instance every 5 seconds. An instance is marked "Unhealthy" after 3 consecutive failed checks. If more than 40% of nodes in a cluster become unhealthy, an automated P1 alert is triggered via PagerDuty to the On-Call Engineer.

## Standard Procedures

### Scaling for High-Traffic Events
During scheduled sales events (e.g., "Bluepeak Summer Blowout"), the Infrastructure team must manually adjust the pre-warm settings:
1.  Open the AWS Management Console $\rightarrow$ EC2 $\rightarrow$ Load Balancers.
2.  Select the `bp-storefront-alb`.
3.  Request a "Pre-warm" via the AWS Support ticket portal 48 hours prior to the event start time to ensure the ALB can handle an expected burst of 50,000 requests per second (RPS).

### Adding/Removing Target Groups
When deploying a new version of the storefront (Canary Deployment):
1.  Create a new target group: `bp-web-vNext`.
2.  Shift traffic in increments: 5% $\rightarrow$ 25% $\rightarrow$ 50% $\rightarrow$ 100%.
3.  Monitor the 5xx error rate in Datadog; if errors exceed 0.5%, immediately roll back to the `bp-web-stable` target group.

## Troubleshooting & Escalation
If a "502 Bad Gateway" spike is detected:
*   **Step 1:** Check the Target Group health status. If all nodes are healthy, the issue is likely at the application layer (JVM heap exhaustion).
*   **Step 2:** Verify Security Group rules to ensure port 8080 remains open between the LB and the instances.
*   **Step 3:** If the ALB itself is reporting latency $> 200ms$, escalate to the Network Engineering Lead via the `#eng-network` Slack channel.
