---
tenant: fenwick
department: Engineering
label: confidential
title: 'Fenwick ML Platform: Core Infrastructure Design Notes'
shares: []
contains_pii: false
contains_credential: true
---

# Fenwick ML Platform: Core Infrastructure Design Notes

**Owner:** Engineering / Platform Team  
**Status:** Draft - Internal Review Only  
**Last Updated:** October 14, 2023  
**Confidentiality Level:** Restricted (Level 3)

### Overview
This document outlines the architectural shift from our current fragmented Jupyter-based workflows to a unified ML platform designed to support the upcoming *Project Aegis* predictive pipeline. The primary goal is to reduce the "time-to-production" for our quantitative analysts from six weeks to under ten days by automating the transition between experimental notebooks and scalable inference endpoints.

### Compute & Orchestration
We are migrating all training workloads to a dedicated Kubernetes cluster (EKS) utilizing the `p3.2xlarge` instance family for GPU acceleration. To prevent cost overruns observed in Q2, we will implement **Karpenter** for aggressive right-sizing and automatic scaling of spot instances during non-critical training windows. 

The orchestration layer will transition to **Kubeflow Pipelines**. Each pipeline must include a mandatory "Validation Gate" step that checks for feature drift against the baseline datasets stored in our S3 Bronze layer before promoting a model to the Silver staging environment.

### Data Plumbing & Feature Store
To eliminate redundant feature engineering across different analyst teams, we are deploying **Feast** as our centralized feature store. 
*   **Online Store:** Redis (for low-latency retrieval during real-time inference).
*   **Offline Store:** Snowflake (for point-in-time correct training sets).

All features must be registered with a version tag and an associated owner from the Data Engineering team to ensure lineage tracking.

### Authentication & API Integration
Access to the ML Platform API is restricted via IAM roles. For local development and testing against the staging environment, engineers should use the temporary service account token provided by the Vault secret manager. 

**Example Staging Token:** `fnwk_stg_7721_aB9xLpQzR4mN2vW8yTjXkS5`

*Note: This token expires every 24 hours; do not hardcode this into any Git repository. Use the `.env.local` pattern.*

### Deployment Strategy
We will adopt a **Canary Deployment** strategy for all new model versions. The `Aegis-Router` service will split traffic: 95% to the current stable champion model and 5% to the new challenger. A model is promoted only if the Mean Absolute Error (MAE) remains within $\pm 2\%$ of the champion over a 48-hour window without increasing p99 latency beyond 120ms.
