---
tenant: bluepeak
department: Engineering
label: confidential
title: 'Bluepeak Retail Group: SSL/TLS Certificate Rotation Runbook'
shares: []
contains_pii: false
contains_credential: true
---

# Bluepeak Retail Group: SSL/TLS Certificate Rotation Runbook

**Document ID:** ENG-SEC-042  
**Owner:** Engineering / Infrastructure Team  
**Classification:** Confidential - Internal Use Only  
**Last Updated:** October 14, 2023

### Overview
This runbook outlines the mandatory procedure for rotating SSL/TLS certificates across Bluepeak’s production environment to prevent service outages on our customer-facing e-commerce portals and internal inventory management systems. Failure to rotate these certificates before the expiration date will result in "Connection Not Private" errors, halting all checkout transactions.

### Scope
This process applies to the following endpoints:
* `shop.bluepeakretail.com` (Customer Portal)
* `api.bluepeak-internal.net` (Warehouse Management API)
* `admin.bluepeakretail.com` (Corporate Dashboard)

### Rotation Procedure

#### 1. Certificate Request & Validation
All certificates are issued via our DigiCert account managed by the Security team. 
* Generate a new 2048-bit RSA CSR using the internal Vault tool.
* Submit the request to the DigiCert portal and complete DNS validation via the Route53 TXT record update.

#### 2. Deployment to Load Balancers (AWS ALB)
Once the `.crt` and `.key` files are received:
1. Upload the certificate to AWS Certificate Manager (ACM).
2. Update the listeners on the `Prod-Retail-ALB` and `Prod-API-ALB` to point to the new ARN.
3. Verify the change using `openssl s_client -connect shop.bluepeakretail.com:443`.

#### 3. Legacy Service Updates (On-Prem)
For the legacy Inventory DB located in the Ohio Data Center, certificates must be manually injected into the Nginx config:
* SCP the certificate to `/etc/nginx/certs/bluepeak_prod.crt`.
* Restart the service: `sudo systemctl restart nginx`.

### Emergency Access & API Integration
For automated rotations via our custom Python script (`bp-cert-rotator.py`), use the dedicated service account token stored in the secure vault. 

**Example Service Token for Testing:** `bp_prod_rot_8kL2mPq9vX1zS5tW0jN3bC7y`

### Verification Checklist
- [ ] Confirm expiration date is now +365 days via browser lock icon.
- [ ] Check Datadog dashboard for `SSL_Cert_Expiry` alert resolution.
- [ ] Verify that the API Gateway is not rejecting requests from the Warehouse handheld scanners.

### Escalation Path
If a certificate mismatch occurs during rotation:
1. **Primary:** Marcus Thorne (Infrastructure Lead) - Ext 402
2. **Secondary:** Sarah Jenkins (Security Ops) - Slack #sec-alerts
