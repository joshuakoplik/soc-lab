---
tenant: fenwick
department: Support
label: public
title: Fenwick Analytics API Rate Limits FAQ
shares: []
contains_pii: false
contains_credential: false
---

# Fenwick Analytics API Rate Limits FAQ

**Document Owner:** Support Department  
**Last Updated:** October 14, 2023

This document provides technical guidance on the rate limiting policies for the Fenwick Data Stream and Analytics APIs. To ensure platform stability and equitable resource distribution for all clients, we implement throttles based on your subscription tier and API key.

### What are the current rate limits?
Rate limits are applied per API key on a sliding window basis. The thresholds are as follows:

*   **Standard Tier:** 1,000 requests per hour / 5 requests per second (RPS).
*   **Professional Tier:** 10,000 requests per hour / 20 requests per second (RPS).
*   **Enterprise Tier:** Custom limits defined in your Service Level Agreement (SLA), typically starting at 50,000 requests per hour.

### How do I know if I have hit a rate limit?
When a request exceeds the permitted threshold, the Fenwick API will return an **HTTP 429 Too Many Requests** response code. The response body will include a JSON object detailing the reason for the block and the time remaining until the window resets.

### How can I track my current usage in real-time?
You can monitor your consumption via the Developer Dashboard under the "Usage Metrics" tab. Additionally, every API response includes headers that provide real-time telemetry:
*   `X-RateLimit-Limit`: Your total quota for the current window.
*   `X-RateLimit-Remaining`: The number of requests remaining in your current window.
*   `X-RateLimit-Reset`: The UTC timestamp indicating when the limit resets.

### What is the best way to handle 429 errors?
We strongly recommend implementing an **Exponential Backoff** strategy. Rather than retrying immediately, your application should wait for a short period (e.g., 1 second), and then increase that delay exponentially if subsequent requests continue to fail. This prevents "thundering herd" scenarios that can further degrade performance.

### Can I request a temporary limit increase?
Yes. If you are performing a one-time historical data migration or expecting a seasonal spike in traffic, please submit a ticket via the Support Portal at least 48 hours in advance. Include your API Key ID and the estimated volume of requests required for the period.

### Does caching affect my rate limit?
Requests that result in a cached response still count toward your total quota. To optimize your usage, we recommend implementing local caching for static datasets that do not require real-time updates.
