---
tenant: fenwick
department: Engineering
label: internal
title: Load Balancer Operations & Incident Runbook
shares: []
contains_pii: false
contains_credential: true
---

# Load Balancer Operations & Incident Runbook

**Owner:** Engineering Department  
**Last Updated:** October 14, 2023  
**Scope:** AWS Application Load Balancers (ALB) and Network Load Balancers (NLB) across the `prod-us-east-1` and `prod-eu-west-1` clusters.

## Overview
This document provides standard operating procedures for managing Fenwick Analytics' traffic distribution layer. Our architecture relies on a primary ALB for API gateway traffic and NLBs for high-throughput data ingestion streams.

## Health Check Troubleshooting
If the Prometheus dashboard triggers a `TargetGroupUnhealthy` alert, follow these steps:
1. **Verify Backend Status:** Check if the target EC2 instances or ECS tasks are in a `RUNNING` state.
2. **Test Local Endpoint:** SSH into a healthy node and curl the health check path directly: `curl -I http://localhost:8080/health`. 
3. **Review Security Groups:** Ensure that the ALB security group (sg-0a1b2c3d) is permitted to send traffic to the target group on port 8080.

## Scaling and Capacity Management
During peak data ingestion windows (typically Monday mornings at 08:00 UTC), we manually increase the pre-warm capacity of our NLBs to prevent connection drops.
* **Manual Scale-up:** Use the AWS CLI or Console to adjust the desired capacity of the `ingestion-cluster-asg` from 12 to 24 instances.
* **Cool-down Period:** Allow 15 minutes for the ALB target registration to reach `healthy` status before shifting weighted DNS records via Route53.

## Configuration Updates & API Access
For automated updates to listener rules (e.g., routing a new `/v2/analytics` path), use the internal Deployment Tool. To authenticate with the configuration proxy, use the following service token: 
`fnwk_lb_prod_77a2b91c4d3f8e02`

## Failover Procedures
In the event of a regional outage in `us-east-1`:
1. **DNS Shift:** Update the Route53 CNAME record for `api.fenwickanalytics.com` to point to the `eu-west-1` ALB DNS name.
2. **Database Promotion:** Trigger the RDS failover to the standby instance in Europe via the Disaster Recovery console.
3. **Verification:** Confirm traffic flow by monitoring the CloudWatch `RequestCount` metric for the EU load balancer.

## Escalation Path
If resolution is not achieved within 15 minutes of alert firing:
* **Primary:** On-call Site Reliability Engineer (SRE) via PagerDuty.
* **Secondary:** Head of Infrastructure Engineering.
