---
tenant: fenwick
department: Engineering
label: internal
title: API Gateway Outage & Recovery Runbook
shares: []
contains_pii: false
contains_credential: false
---

# API Gateway Outage & Recovery Runbook

**Document Owner:** Engineering / Platform Team  
**Last Updated:** October 14, 2023  
**Severity Level:** Critical (P0/P1)

## Overview
This runbook provides the operational steps required to diagnose and remediate a failure of the Kong API Gateway cluster. A total outage prevents all external clients from accessing Fenwick Analytics’ data endpoints, resulting in a complete service blackout for our customers.

## Initial Triage & Detection
An outage is typically signaled by a "High Error Rate" alert via PagerDuty (Monitor: `api-gateway-5xx-spike`). 
1. **Verify Scope:** Check the Grafana Dashboard `Infrastructure -> API Gateway` to determine if the issue is global or isolated to a specific AWS region (us-east-1 vs us-west-2).
2. **Health Check:** Execute `curl -I https://api.fenwickanalytics.com/health`. A `503 Service Unavailable` or timeout indicates a gateway failure; a `404 Not Found` suggests a routing configuration error.

## Remediation Steps

### Scenario A: Gateway Pod CrashLoopBackOff
If the Kubernetes pods are failing to start in the `prod-gateway` namespace:
1. Check logs for OOM (Out of Memory) kills:  
   `kubectl logs -n prod-gateway deployment/kong-gateway-proxy --previous`
2. If memory exhaustion is detected, scale the replicas immediately to distribute load:  
   `kubectl scale deployment kong-gateway-proxy -n prod-gateway --replicas=15`
3. Verify if a recent ConfigMap update caused the crash. Roll back the last deployment:  
   `kubectl rollout undo deployment/kong-gateway-proxy -n prod-gateway`

### Scenario B: Database Connectivity Failure (PostgreSQL)
If logs indicate `cannot connect to pg-gateway-db`:
1. Verify the status of the RDS instance in the AWS Console.
2. Check for locked tables or connection exhaustion. If connections exceed 500, restart the gateway pods to clear stale sessions.

### Scenario C: Upstream Service Timeout
If the gateway is healthy but returning `504 Gateway Timeout`:
1. Identify the failing service using the `kong-prometheus` metric `gateway_upstream_latency`.
2. If a specific microservice (e.g., `query-engine-v2`) is lagging, trigger a circuit breaker trip via the Admin API to prevent cascading failure:  
   `curl -X PATCH http://localhost:8001/services/query-engine-v2 -d "timeout=2000"`

## Escalation Path
If service is not restored within 30 minutes of triage:
* **Primary:** Lead Site Reliability Engineer (SRE)
* **Secondary:** VP of Engineering
* **Communication:** Post updates to the `#incident-mgmt` Slack channel every 15 minutes.
