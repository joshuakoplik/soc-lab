---
tenant: riverside
department: Support
label: public
title: Riverside Cargo API Rate Limits & Quotas FAQ
shares: []
contains_pii: false
contains_credential: false
---

# Riverside Cargo API Rate Limits & Quotas FAQ

**Document Owner:** Support Department  
**Last Updated:** October 12, 2023  
**Status:** Public

This document provides technical guidance on the rate limiting policies applied to the Riverside Cargo Logistics API. To ensure system stability and equitable resource distribution for all freight partners, we employ a sliding-window throttling mechanism.

### What are the current rate limits?
Limits are applied based on your API Key and vary by account tier:

*   **Standard Tier:** 100 requests per minute (RPM) / 5,000 requests per day.
*   **Enterprise Tier:** 500 requests per minute (RPM) / 50,000 requests per day.
*   **Partner Integration Tier:** Custom limits negotiated via account management.

These limits apply globally across all endpoints, including Shipment Tracking, Rate Calculation, and Bill of Lading (BOL) generation.

### How do I know if I have hit a rate limit?
When a request exceeds the allowed threshold, the API will return an **HTTP 429 Too Many Requests** response. The response body will contain a JSON object specifying the reason for the block:

`{ "error": "Rate limit exceeded", "retry_after": 30 }`

### How can I track my current usage?
You can monitor your real-time consumption by inspecting the HTTP headers of every API response. Riverside Cargo includes the following headers in all calls:
*   `X-RateLimit-Limit`: Your total quota for the current window.
*   `X-RateLimit-Remaining`: The number of requests remaining in your current window.
*   `X-RateLimit-Reset`: The UTC timestamp indicating when the limit resets.

### What is the best way to handle 429 errors?
We strongly recommend implementing an **Exponential Backoff** strategy. Rather than retrying immediately, your application should wait for the duration specified in the `retry_after` header, increasing the delay progressively if subsequent requests also fail.

### How do I request a limit increase?
If your shipping volume has grown and you are consistently hitting your quota, please follow these steps:
1. Log into the Riverside Developer Portal.
2. Navigate to **Account Settings > Usage Quotas**.
3. Submit a "Limit Increase Request" form detailing your expected peak RPM and the specific use case (e.g., migrating historical freight data).

Requests are typically reviewed by our Support Engineering team within two business days.
