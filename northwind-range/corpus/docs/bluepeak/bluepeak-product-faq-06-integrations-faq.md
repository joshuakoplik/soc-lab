---
tenant: bluepeak
department: Support
label: public
title: Bluepeak Integrations & Connectivity FAQ
shares: []
contains_pii: false
contains_credential: false
---

# Bluepeak Integrations & Connectivity FAQ

**Document Owner:** Support Department  
**Last Updated:** October 14, 2023  
**Status:** Public

This guide provides technical clarity on how the Bluepeak Retail Suite connects with third-party logistics, payment gateways, and e-commerce platforms.

### General Integration Questions

**Which e-commerce platforms are natively supported?**  
Bluepeak offers "one-click" native integrations for Shopify Plus, Magento 2, and BigCommerce. For stores using WooCommerce or custom headless builds, we provide a robust REST API to synchronize inventory and order data in real-time.

**How often does the inventory sync occur across channels?**  
For native integrations, Bluepeak utilizes Webhooks to push updates instantly. When an item is sold via your POS in-store, the stock level is updated across all digital storefronts within 30 seconds. For legacy systems using our scheduled polling service, updates occur every 15 minutes.

### Shipping & Logistics

**Which carriers are integrated for automated label generation?**  
Our shipping module integrates directly with FedEx, UPS, and DHL Express. To activate these, navigate to *Settings > Logistics* and enter your carrier account credentials. Once linked, Bluepeak automatically pulls live shipping rates based on the package dimensions stored in your product catalog.

**Can I connect my own 3PL (Third Party Logistics) provider?**  
Yes. We support direct EDI (Electronic Data Interchange) connections for most major 3PLs. If your provider is not listed in our dropdown menu, our Support team can configure a custom mapping file. This process typically takes 5–7 business days to verify.

### Payments & Accounting

**Which payment gateways are compatible with Bluepeak POS?**  
We are fully integrated with Stripe, Adyen, and Square. To ensure PCI compliance, Bluepeak never stores raw credit card data; we use secure tokenization provided by the gateway. 

**Does Bluepeak sync with accounting software?**  
Yes. We offer a direct integration with QuickBooks Online and Xero. This sync maps your daily sales totals, tax collections, and refund summaries into your general ledger automatically every night at 12:00 AM UTC.

### Troubleshooting & Support

**What should I do if an API connection returns a 401 Unauthorized error?**  
This usually indicates that your API key has expired or was rotated. Please generate a new Secret Key in the *Developer Portal* and update it in your integration settings.

**Where can I find the full API documentation?**  
Detailed endpoint references and authentication guides are available at `developer.bluepeakretail.com`.
