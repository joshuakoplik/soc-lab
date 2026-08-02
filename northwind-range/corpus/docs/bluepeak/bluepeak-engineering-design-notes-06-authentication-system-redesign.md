---
tenant: bluepeak
department: Engineering
label: confidential
title: 'Engineering Design Notes: Unified Auth Service Redesign (Project Keystone)'
shares: []
contains_pii: false
contains_credential: false
---

# Engineering Design Notes: Unified Auth Service Redesign (Project Keystone)

**Owner:** Engineering / Identity Platform Team  
**Status:** Draft / Pending Architecture Review  
**Date:** October 24, 2023  
**Confidentiality Level:** Internal Restricted

### Context & Problem Statement
Our current authentication landscape is fragmented across three legacy silos: the Bluepeak E-commerce portal (Node.js/Passport), the Store Manager Dashboard (PHP/Custom Auth), and the Loyalty App (Firebase). This fragmentation has led to "account drift," where a customer updating their password on the web portal remains locked out of the mobile app for up to 24 hours due to asynchronous sync jobs between our MongoDB clusters and the legacy Oracle DB.

Furthermore, the current session management relies on stateful server-side sessions stored in Redis, which is causing significant latency spikes during peak traffic events (e.g., Black Friday) as we hit memory limits on the `auth-redis-01` and `02` nodes.

### Proposed Architecture
We will migrate to a centralized Identity Provider (IdP) based on an OIDC (OpenID Connect) framework. We are moving away from stateful sessions toward stateless JWTs (JSON Web Tokens) signed via RS256.

**Key Technical Specifications:**
1.  **Token Strategy:** 
    *   **Access Tokens:** Short-lived (15 minutes), stored in memory.
    *   **Refresh Tokens:** Long-lived (7 days), stored in `HttpOnly`, `Secure` cookies with a rotating refresh strategy to mitigate replay attacks.
2.  **Migration Path:** We will implement a "Lazy Migration" pattern. When a user logs in, the new Auth Service will validate credentials against the legacy Oracle DB; upon success, it will migrate the hashed password (Bcrypt) to the new PostgreSQL identity store and flag the account as `migrated=true`.
3.  **Rate Limiting:** To prevent brute-force attacks on the `/v1/login` endpoint, we are implementing a sliding window rate limit via Kong Gateway: 5 failed attempts per IP per 10-minute window.

### Critical Risks & Dependencies
*   **Legacy API Compatibility:** The Store Manager Dashboard uses an older SOAP interface that does not support Bearer tokens. We will need to implement a temporary "Token Exchange" proxy to convert JWTs into the legacy session IDs until the PHP migration is complete in Q1 2024.
*   **Database Latency:** Initial benchmarks show that the cross-region sync between US-East and EU-West for user profiles adds ~200ms of latency. We are evaluating Global Aurora clusters to reduce this.

### Success Metrics
*   Reduction in "Account Sync" support tickets by 80%.
*   Authentication p99 latency reduced from 450ms to <120ms.
