---
tenant: riverside
department: Engineering
label: confidential
title: 'Engineering Design Notes: AuthN/AuthZ Infrastructure Migration'
shares: []
contains_pii: false
contains_credential: false
---

# Engineering Design Notes: AuthN/AuthZ Infrastructure Migration

**Document Status:** Draft / Internal Review  
**Owner:** Engineering (Identity Team)  
**Date:** October 14, 2023  
**Confidentiality Level:** Restricted – Internal Only

### Overview
The current monolithic authentication system, based on the legacy `UserAuth` module in the Riverside Core API, is failing to scale with our expansion into the EMEA market. Specifically, we are seeing latency spikes during peak morning login windows (07:00–09:00 EST) and a lack of granular permissioning for third-party logistics (3PL) partners who require scoped access to shipment tracking without visibility into billing records.

### Proposed Architecture
We will migrate from the existing session-based state stored in Redis to a stateless JWT (JSON Web Token) architecture utilizing an OIDC (OpenID Connect) provider. 

**Key Technical Specifications:**
*   **Identity Provider:** Migration to Okta for internal staff and a custom Keycloak instance for external vendors/drivers to maintain data sovereignty over client PII.
*   **Token Strategy:** Implementation of short-lived Access Tokens (15 minutes) and sliding-window Refresh Tokens (7 days). 
*   **Secret Management:** All signing keys will be rotated every 30 days via AWS Secrets Manager, moving away from the current static `.env` configuration used in the legacy cluster.

### Scope of Work & Integration Points
1.  **Legacy Bridge:** We must implement a "Shadow Auth" period starting November 1st. During this window, the `auth-gateway-v2` will validate tokens against both the new Keycloak instance and the legacy SQL database to prevent lockout for the 4,200 active driver accounts.
2.  **RBAC Overhaul:** We are replacing the binary `isAdmin` flag with a granular Role-Based Access Control (RBAC) system. New scopes include:
    *   `shipment:read` / `shipment:write`
    *   `billing:view`
    *   `fleet:dispatch`
3.  **MFA Mandate:** Multi-factor authentication will be mandatory for all users with `billing:view` or `fleet:dispatch` permissions, enforced via TOTP (Time-based One-Time Password).

### Risks and Mitigations
The primary risk is the potential for "Token Bloat." Given the number of warehouse locations a single dispatcher may manage, including all location IDs in the JWT payload could exceed header size limits on our Nginx ingress. To mitigate this, we will store location mappings in a distributed cache (Redis) and reference a single `org_id` within the token.

**Next Milestone:** Load testing the Keycloak cluster in the staging environment by October 28th.
