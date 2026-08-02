---
tenant: riverside
department: Engineering
label: internal
title: API Versioning Strategy and Lifecycle Management
shares: []
contains_pii: false
contains_credential: false
---

# API Versioning Strategy and Lifecycle Management

**Owner:** Engineering Department  
**Status:** Approved  
**Last Updated:** October 14, 2023  
**Effective Date:** November 1, 2023

### Overview
As Riverside Cargo Co. expands its integration with third-party logistics (3PL) partners and scales our internal "FleetTrack" mobile application, we require a standardized approach to API versioning. To prevent breaking changes in our shipping manifests and customs clearance pipelines, the Engineering department is adopting a URI-based versioning strategy.

### Versioning Scheme
All RESTful services must include the major version number in the URL path. 

**Format:** `https://api.riversidecargo.com/v{major}/{resource}`

*   **Major Versions (e.g., /v1, /v2):** Incremented only when breaking changes are introduced (e.g., removing a field from the `Shipment` object or altering the authentication handshake).
*   **Minor/Patch Versions:** These will not be reflected in the URI. Backward-compatible additions—such as adding an optional `estimated_delivery_date` field to the Tracking API—will be deployed as rolling updates to the current major version.

### Deprecation Policy
To ensure stability for our warehouse partners who may use legacy systems, we will implement a "N-1" support model. Only the current and one previous major version will be active at any time.

1.  **Announcement:** When `v2` is released, `v1` is officially marked as *Deprecated*. A notice will be sent to all API consumers via the Developer Portal and included in the HTTP response headers as a `Warning: 299 - "Deprecated API version"`.
2.  **Sunset Period:** Deprecated versions will be supported for exactly six months. 
3.  **Decommissioning:** After the sunset period, the legacy endpoint will return a `410 Gone` status code with a body pointing to the new documentation.

### Implementation Requirements
*   **Header Requirement:** All requests must include the `X-Riverside-Client-ID` header for telemetry and tracking which partners are still hitting deprecated endpoints.
*   **Documentation:** The Swagger/OpenAPI specifications must be maintained separately for each major version in the `/docs` directory of our internal Wiki.
*   **Testing:** Any PR introducing a new major version must include a regression suite that validates parity for all non-breaking features against the previous version.

Failure to adhere to this versioning strategy results in fragmentation across our logistics pipeline and increased maintenance overhead for the DevOps team. Please direct questions to the Architecture Guild.
