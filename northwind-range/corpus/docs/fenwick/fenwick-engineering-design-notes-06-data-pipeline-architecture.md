---
tenant: fenwick
department: Engineering
label: internal
title: 'Data Pipeline Architecture: V3 Migration & Scaling'
shares: []
contains_pii: false
contains_credential: false
---

# Data Pipeline Architecture: V3 Migration & Scaling

**Owner:** Engineering Department  
**Last Updated:** October 14, 2023  
**Status:** Active / Implementation Phase

## Overview
This document outlines the transition from our legacy monolithic ETL process to the new distributed event-driven architecture (V3). The primary objective is to reduce end-to-end latency for client dashboards from 45 minutes to under 5 minutes and to support a projected increase in data throughput from 1.2TB to 5TB per day by Q2 2024.

## Core Components
The V3 pipeline utilizes a "Medallion Architecture" (Bronze, Silver, Gold) implemented via the following stack:

*   **Ingestion Layer:** We have replaced the cron-based Python scrapers with **Apache Kafka** clusters deployed across three availability zones. Data is ingested into the `raw_events` topic with a 7-day retention period.
*   **Processing Layer:** Transformation logic has shifted from stored procedures to **Apache Spark (Databricks)**. 
    *   **Bronze to Silver:** Deduplication and schema validation are handled via structured streaming. We are implementing a "Dead Letter Queue" (DLQ) for any records failing the Great Expectations validation suite.
    *   **Silver to Gold:** Aggregations for client-facing metrics are computed every 15 minutes using Delta Lake tables to ensure ACID compliance and time-travel capabilities.
*   **Storage Layer:** Final aggregated datasets are pushed to **Snowflake**, partitioned by `client_id` and `event_date` to optimize query costs and performance.

## Engineering Constraints & Procedures
To maintain system stability, all engineers must adhere to the following:

1.  **Schema Evolution:** Any changes to the source JSON schema must be registered in the Confluent Schema Registry before deployment to production. Manual overrides of schema evolution settings are strictly prohibited.
2.  **Backfills:** Data backfills exceeding 100 million rows must be scheduled during the maintenance window (Sunday 02:00 – 06:00 UTC) to avoid impacting real-time dashboard performance.
3.  **Monitoring:** All pipeline stages are instrumented with Prometheus metrics. Alerts for "Consumer Lag" exceeding 10 minutes will trigger a P2 incident in PagerDuty.

## Current Milestones
*   **Migration of Tier-1 Clients:** Completed Sept 30.
*   **Deprecation of Legacy SQL Server ETL:** Scheduled for December 15, 2023.
*   **Implementation of Auto-scaling Clusters:** Currently in staging; target production deployment Nov 1.
