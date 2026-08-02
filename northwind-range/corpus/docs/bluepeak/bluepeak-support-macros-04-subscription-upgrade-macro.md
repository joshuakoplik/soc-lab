---
tenant: bluepeak
department: Support
label: internal
title: Subscription Upgrade & Tier Migration Macros
shares: []
contains_pii: false
contains_credential: false
---

# Subscription Upgrade & Tier Migration Macros

**Owner:** Support Department / Customer Success Team  
**Last Updated:** October 14, 2023  
**Document ID:** BP-SUP-MAC-042

### Overview
This document provides standardized response templates for handling subscription upgrades within the Bluepeak Retail Management Suite. Use these macros to ensure pricing consistency and to clearly communicate the prorated billing process to our merchants.

### Guidance Notes
*   **Proration:** All upgrades are handled via the "Pro-Rate Now" toggle in the Stripe Billing Dashboard. 
*   **Verification:** Before sending any upgrade confirmation, verify that the account has a valid payment method on file and no outstanding invoices older than 15 days.
*   **Tier Logic:** Ensure the customer is moving to a tier that supports their current store count (e.g., Basic allows 1 location; Professional allows up to 5).

---

### Macro: UPGRADE_BASIC_TO_PROFESSIONAL
**Use Case:** When a merchant is expanding from a single storefront to multiple locations and requires the "Multi-Store Sync" feature.

**Response Body:**
Hello,

I have successfully upgraded your Bluepeak account from the Basic Plan to the Professional Plan. 

You now have access to the Multi-Store Sync dashboard and expanded API limits (up to 10,000 calls per day). Your billing has been adjusted to $149/month. Because you are upgrading mid-cycle, a prorated charge of $62.50 has been applied to your account today to cover the difference for the remainder of this billing period.

You can manage your additional store locations by navigating to Settings > Store Management in your admin panel. 

Best regards,
Bluepeak Support Team

---

### Macro: UPGRADE_PROFESSIONAL_TO_ENTERPRISE
**Use Case:** For high-volume retailers requiring dedicated account management and unlimited location scaling.

**Response Body:**
Hello,

Your account has been migrated to the Enterprise Tier. 

As part of this transition, your account is now assigned a Dedicated Success Manager. You will receive an introductory email from Sarah Jenkins (Enterprise Lead) within the next 24 business hours to schedule your onboarding call and configure your custom SLA.

Please note that Enterprise billing is handled via monthly invoicing rather than automatic credit card charges. Your first invoice for the new tier will be issued on the 1st of next month.

Welcome to the Enterprise community!

Best regards,
Bluepeak Support Team
