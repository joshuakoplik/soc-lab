---
tenant: bluepeak
department: Engineering
label: confidential
title: 'Architecture Design Note: Unified Omnichannel Data Pipeline (v2.4)'
shares: []
contains_pii: false
contains_credential: false
---

# Architecture Design Note: Unified Omnichannel Data Pipeline (v2.4)

**Owner:** Engineering / Data Platform Team  
**Status:** Draft for Review  
**Date:** October 14, 2023  
**Confidentiality Level:** Internal - Highly Restricted

### Overview
The current fragmented state of our data ingestion—where Point-of-Sale (POS) systems from the Northeast region are siloed from the e-commerce Shopify backend—is creating a 14-hour latency in inventory visibility. This document outlines the transition to a unified event-driven architecture designed to reduce this lag to < 5 minutes, enabling real-time "Buy Online, Pick Up In Store" (BOPIS) accuracy across all 142 locations.

### Technical Specifications
The pipeline will move away from legacy nightly batch jobs toward a streaming architecture utilizing **Apache Kafka** as the central message bus.

1.  **Ingestion Layer:** We are deploying three specialized connectors:
    *   **POS-Streamer:** A custom Java wrapper around our NCR Silver APIs to push transactional data via Protobuf to the `tx_raw` topic.
    *   **Web-Hook Listener:** A Node.js microservice hosted on AWS Lambda to capture Shopify webhook events for order updates and returns.
    *   **ERP-Sync:** A Change Data Capture (CDC) implementation using Debezium on our Oracle NetSuite instance to track warehouse stock movements in real-time.

2.  **Processing Layer:** We will utilize **Apache Flink** for stateful stream processing. The primary goal is the "Inventory Reconciliation Job," which must join the `tx_raw` and `warehouse_stock` streams using a sliding 60-second window to prevent race conditions during high-volume events (e.g., Black Friday).

3.  **Storage & Serving:**
    *   **Cold Storage:** Raw events will be archived in S3 (Parquet format) partitioned by `year/month/day/store_id` for audit compliance and historical training of the demand forecasting model.
    *   **Hot Layer:** Aggregated KPIs (e.g., hourly sales per category) will be pushed to **ClickHouse**, providing the executive dashboard with sub-second query response times.

### Critical Constraints & Risks
*   **Schema Evolution:** To prevent pipeline breakage, all producers must adhere to the Confluent Schema Registry. Any breaking change to the `Order` object requires a version bump and 48-hour notice to the Analytics team.
*   **Backpressure Handling:** During peak traffic (projected 15k events/sec), Flink checkpoints will be stored on EFS to ensure recovery without re-processing the entire day's stream.

### Implementation Timeline
Migration of the Northeast region stores is scheduled for November 2nd, followed by a full rollout across all territories by January 15th.
