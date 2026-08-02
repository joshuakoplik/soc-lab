---
tenant: bluepeak
department: Engineering
label: internal
title: API Gateway Outage Recovery Runbook
shares: []
contains_pii: false
contains_credential: false
---

# API Gateway Outage Recovery Runbook

**Document Owner:** Engineering / Platform Reliability Team  
**Last Updated:** October 14, 2023  
**Severity Level:** Critical (P0)

## Overview
This runbook provides the step-by-step procedure for resolving a total or partial outage of the Kong API Gateway. The API Gateway is the entry point for all Bluepeak mobile app and web storefront traffic; an outage results in complete loss of checkout capabilities and product catalog browsing.

## Initial Triage & Detection
An outage is confirmed if the **Datadog Dashboard "Edge-Traffic-Overview"** shows a drop in 2xx responses below 85% or a spike in 504 Gateway Timeouts exceeding 5,000 requests per minute across the `us-east-1` region.

## Recovery Procedures

### Step 1: Traffic Diversion (Failover)
If the primary gateway cluster is unresponsive, immediately divert traffic to the standby disaster recovery (DR) site in `us-west-2`.
1. Log into the **Route53 Management Console**.
2. Navigate to the hosted zone `api.bluepeakretail.com`.
3. Update the CNAME record for the production alias from `prod-gateway-east.bluepeak.internal` to `dr-gateway-west.bluepeak.internal`.
4. Verify traffic shift via the CloudWatch "RequestCount" metric for the West cluster.

### Step 2: Service Health Check & Restart
If failover is not required but latency is high, check for memory leaks in the Kong pods within the Kubernetes cluster:
1. Run `kubectl get pods -n gateway-prod` to identify pods in `CrashLoopBackOff` or `OOMKilled` states.
2. If resource exhaustion is detected, scale the deployment manually to handle current load spikes:
   `kubectl scale deployment kong-gateway --replicas=25 -n gateway-prod`.
3. Flush the Redis cache layer if stale configuration data is causing routing loops:
   `redis-cli -h redis-gateway.bluepeak.internal FLUSHALL`.

### Step 3: Circuit Breaker Reset
If a downstream microservice (e.g., the Order Management System) caused the gateway to trip its circuit breakers:
1. Access the **Kong Manager Admin UI**.
2. Navigate to **Routes** $\rightarrow$ `/v1/orders`.
3. Manually toggle the "Circuit Breaker" status to `Disabled` to allow a trickle of traffic back into the system.

## Escalation Path
If service is not restored within 15 minutes of following these steps, notify the following:
* **On-Call Lead:** Sarah Jenkins (Slack: @sjenkins_eng)
* **Infrastructure Manager:** Marcus Thorne (PagerDuty: Infrastructure-Tier1)
* **Stakeholder Notification:** Post a status update to the `#incidents-war-room` channel.
