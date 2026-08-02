---
tenant: riverside
department: Engineering
label: internal
title: Certificate Rotation Runbook
shares: []
contains_pii: false
contains_credential: false
---

# Certificate Rotation Runbook

**Department:** Engineering — Platform Team
**Owner:** Priya Natarajan, Platform Lead
**Last reviewed:** February 14, 2025
**Classification:** Internal

## Scope

This runbook covers rotation of the TLS certificates Engineering manages directly:

- **freightlink.riversidecargo.com** — customer tracking and booking portal; cert imported into AWS ACM and attached to the production ALB.
- **edi-gw.riversidecargo.com** — EDI gateway exchanging 204/214/210 transactions with carrier and shipper partners; cert terminates on nginx at edi-gw-01 (RHEL 8).
- **Service mesh mTLS** on prod-eks-1, issued by cert-manager v1.14 with our Vault PKI issuer (90-day lifetime, auto-renews at day 60).

Warehouse WMS and corporate VPN certs are owned by IT Ops — see their separate runbook.

## Schedule and Lead Times

Portal and EDI certs are DigiCert OV, 397-day validity, ordered through CertCentral (account admin: Marcus Webb). Renew at T-30 days. Two EDI partners — Schneider and J.B. Hunt — pin our certificate and require 10 business days' notice, so the EDI rotation notice must go out by T-15 at the latest. Rotations occur during Tuesday/Thursday maintenance windows, 02:00–04:00 CT.

## Rotation Procedure

1. Confirm current expiry: `openssl s_client -connect freightlink.riversidecargo.com:443 </dev/null 2>/dev/null | openssl x509 -noout -dates`. Verify no open Sev-1/Sev-2 incidents.
2. Generate the CSR, order the renewal in CertCentral, and approve the DCV email (sent to tls-admin@riversidecargo.com).
3. Install on staging first (staging ALB and edi-gw-stg) and run the smoke suite in `platform/cert-smoke`. For EDI, send a test 214 to the partner test mailbox.
4. Production: import the new cert into ACM and swap it on the ALB listener. On edi-gw-01, place the cert/key in `/etc/pki/tls/riverside/` and run `systemctl reload nginx`. Keep the previous cert files — they are the rollback path.
5. Verify: correct served dates and full chain via the openssl command, no 5xx spike on the freightlink Grafana dashboard for 30 minutes, and a successful inbound 204 from each pinned partner before closing the window.
6. Rollback if needed: reattach the prior ACM cert, or restore the backed-up files on edi-gw-01 and reload nginx.

## Mesh Auto-Renewal Failures

cert-manager alerts page Platform on-call (`CertificateRenewalFailed`). Check `kubectl get certificates,certificaterequests,challenges -A`. The usual culprit is the Vault PKI role max-TTL, which must exceed 90 days.

## Escalation and Wrap-Up

Primary: Platform on-call via PagerDuty. Secondary: Priya Natarajan. DigiCert support: 1-801-877-2100, account RC-44713. After each rotation, update the Certificate Inventory page in Confluence (Infra space) and close the auto-created INFRA Jira ticket.
