---
tenant: riverside
department: Engineering
label: confidential
title: 'Internal ML Platform Design: Project "Waypoint"'
shares: []
contains_pii: false
contains_credential: false
---

# Internal ML Platform Design: Project "Waypoint"

**Owner:** Engineering / Data Infrastructure Team  
**Status:** Draft for Review (Q3 2024)  
**Confidentiality Level:** Restricted - Internal Only

### Overview
The current reliance on fragmented Jupyter notebooks and manual CSV uploads to the legacy Oracle warehouse is creating unacceptable latency in our route optimization engine. Project Waypoint aims to centralize model development, deployment, and monitoring into a unified internal platform to reduce the time-to-production for our "Dynamic Load Balancer" (DLB) models from six weeks to under five business days.

### Architecture Specifications
The platform will be built on a Kubernetes cluster (EKS) utilizing a hub-and-spoke model to isolate training workloads from production inference. 

1.  **Feature Store:** We are implementing Feast atop our existing Redis cache to manage real-time features, specifically the `truck_telemetry` and `port_congestion_index` streams. This eliminates the current discrepancy where training data uses batch historicals while production uses live API calls.
2.  **Model Registry:** MLflow will serve as the primary registry. All models must be tagged with a specific version of the `Riverside-Logistics-Core` library to ensure dependency parity across environments.
3.  **Inference Pipeline:** To handle the high throughput of our East Coast hub telemetry, we will deploy a Triton Inference Server. This allows us to run concurrent ensembles—specifically combining the XGBoost demand forecaster with the PyTorch route optimizer—without increasing latency beyond 200ms per request.

### Deployment & Guardrails
To prevent "model drift" in our fuel consumption predictions, Waypoint will integrate Prometheus alerting. If the KL-divergence between the serving data and training baseline exceeds 0.15 for a 4-hour window, the system must trigger an automated rollback to the previous stable champion model.

### Resource Allocation
*   **Compute:** Initial allocation of 4x NVIDIA A10g instances for the training pool.
*   **Storage:** S3 buckets partitioned by `region/client_id/timestamp` to comply with our updated data residency agreements for European freight partners.

### Next Milestones
*   **Aug 15:** Completion of the CI/CD pipeline integration (Jenkins $\rightarrow$ EKS).
*   **Sept 1:** Beta migration of the "Last-Mile Efficiency" model.
*   **Sept 15:** Full deprecation of the legacy manual deployment scripts.
