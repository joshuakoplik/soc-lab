---
tenant: fenwick
department: Engineering
label: internal
title: 'Authentication System Redesign: Migration to OIDC and JWT'
shares: []
contains_pii: false
contains_credential: true
---

# Authentication System Redesign: Migration to OIDC and JWT

**Owner:** Engineering Department  
**Status:** Draft / In-Review  
**Date:** October 14, 2023  
**Lead Engineer:** Marcus Thorne

### Overview
The current monolithic session management system (based on the legacy `AuthStore` Redis cluster) has become a bottleneck for our scaling analytics pipelines. As we move toward a microservices architecture to support the new Fenwick Real-Time Dashboard, we are transitioning from stateful server-side sessions to a stateless OpenID Connect (OIDC) implementation using JSON Web Tokens (JWT).

### Technical Specifications
We will implement an Identity Provider (IdP) based on Keycloak, deployed across three availability zones in our AWS us-east-1 region. 

**Key Changes:**
1.  **Token Strategy:** We will shift to a dual-token system. Access tokens will have a short TTL of 15 minutes, while Refresh tokens will persist for 7 days, stored in an encrypted HttpOnly cookie.
2.  **Claims Mapping:** To avoid repeated database lookups across services, the JWT payload will now include `tenant_id`, `user_role`, and `feature_flags`. This reduces latency by approximately 40ms per request.
3.  **Validation:** Each downstream service (Ingestion, QueryEngine, Billing) will implement a middleware layer to validate tokens using the IdP's public keys via the JWKS endpoint.

### Integration Example
For internal testing of the new `/v2/auth/validate` endpoint, developers should use the sandbox environment. An example of a signed mock token for the `test_admin` profile is provided below:

`fnwk_live_a7b29c1d8e3f4g5h6i7j8k9l0m1n2o3p_jwt_v2`

### Migration Plan
The rollout will follow a phased "Canary" approach to prevent lockout events:
*   **Phase 1 (Nov 1):** Deploy the OIDC provider and enable parallel authentication. Users can log in via both systems, but the legacy system remains primary.
*   **Phase 2 (Nov 15):** Shift 10% of traffic (starting with internal Fenwick employees) to the new JWT-based flow.
*   **Phase 3 (Dec 1):** Full production cutover and decommissioning of the `AuthStore` Redis cluster.

### Security Considerations
To mitigate token theft, we are implementing Refresh Token Rotation. Whenever a refresh token is used to generate a new access token, the old refresh token is invalidated and a new one is issued. If a leaked refresh token is reused, the entire session family will be revoked immediately to protect user data.
