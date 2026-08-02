---
tenant: bluepeak
department: Engineering
label: confidential
title: 'API Versioning Strategy: Transition to Semantic Header Routing'
shares: []
contains_pii: false
contains_credential: false
---

# API Versioning Strategy: Transition to Semantic Header Routing

**Owner:** Engineering / Platform Team  
**Status:** Approved/Active  
**Last Updated:** October 14, 2023  
**Confidentiality Level:** Internal Only

### Overview
As Bluepeak Retail Group scales its omnichannel integration—specifically the synchronization between our legacy POS systems and the new *Apex* E-commerce engine—the current practice of URI versioning (e.g., `/v1/orders`) has become unsustainable. This document outlines the shift to Header-based Semantic Versioning to prevent breaking changes for our third-party logistics (3PL) partners while maintaining rapid deployment cycles for internal microservices.

### Routing Logic & Implementation
Effective November 1, 2023, all new endpoints in the `Retail-Core` and `Inventory-Mgmt` clusters must implement versioning via the `X-Bluepeak-Api-Version` request header.

*   **Default Behavior:** Requests lacking a version header will default to the "Stable" track (currently v2.4).
*   **Semantic Mapping:** We are adopting a `Major.Minor` format. 
    *   **Major changes** (breaking) trigger a routing shift at the API Gateway (Kong), directing traffic to separate service pods.
    *   **Minor changes** (additive/non-breaking) are handled via backward-compatible schema evolution within the same pod.

### Deprecation Lifecycle
To avoid "version sprawl," Bluepeak will enforce a strict N-2 support policy. Only the current and two previous major versions will be maintained in production.

1.  **Sunset Notification:** When v3.0 is released, v1.0 enters "Deprecated" status. 
2.  **Warning Phase:** All responses for deprecated versions must include a `Warning` HTTP header: `Warning: 299 - "API version 1.0 is deprecated and will be removed on 2024-05-01"`.
3.  **Hard Cutoff:** On the sunset date, requests to the deprecated version will return a `410 Gone` error with a payload pointing to the migration guide in the internal Confluence space.

### Specific Constraints for POS Integration
Because our legacy NCR store terminals cannot easily modify request headers, the Platform Team has implemented a "Legacy Proxy" shim. This proxy intercepts traffic from Store IDs 400-850 and injects the `X-Bluepeak-Api-Version: 1.2` header automatically before forwarding to the backend. No further changes should be made to these legacy endpoints without approval from the Retail Operations lead.

### Validation
All new PRs must include a versioning impact analysis in the Jira ticket. Automated tests in the Jenkins pipeline will now fail if a breaking change is detected in the OpenAPI spec without a corresponding major version bump.
