---
tenant: bluepeak
department: Support
label: public
title: Bluepeak API Rate Limits & Quotas FAQ
shares: []
contains_pii: false
contains_credential: false
---

# Bluepeak API Rate Limits & Quotas FAQ

**Document Owner:** Support Department  
**Last Updated:** October 14, 2023

This guide provides technical specifications regarding the rate limits applied to the Bluepeak Retail Group Open API. These limits are in place to ensure system stability and fair resource allocation across all integrated partner platforms.

### What are the current rate limits?
Bluepeak employs a sliding window algorithm to track requests. Limits are applied per API Key based on your account tier:

*   **Standard Tier:** 1,000 requests per hour.
*   **Enterprise Tier:** 5,000 requests per hour.
*   **Partner Sandbox:** 100 requests per hour (for testing purposes only).

### How do I know if I have hit a rate limit?
When a request exceeds the allocated quota, the API will return an **HTTP 429 Too Many Requests** response code. The response body will include a JSON payload specifying the reason for the rejection and the time remaining until the window resets.

### How can I track my current usage in real-time?
You can monitor your consumption by inspecting the HTTP headers returned with every API response:
*   `X-RateLimit-Limit`: Your total quota per hour.
*   `X-RateLimit-Remaining`: The number of requests remaining in your current window.
*   `X-RateLimit-Reset`: The UTC timestamp indicating when the counter resets to zero.

### What is the best way to handle 429 errors?
We strongly recommend implementing an **exponential backoff** strategy. Rather than retrying immediately—which may further exhaust your limit—your application should wait for a short period, then increase the delay between subsequent retries. 

For high-volume data synchronization (such as full inventory updates), we suggest utilizing our Bulk Export endpoints rather than making individual GET requests for every SKU.

### Can I request a limit increase?
Yes. If your business requirements exceed the Enterprise Tier limits, please submit a "Quota Increase Request" via the Bluepeak Developer Portal. 

Our engineering team reviews these requests weekly. Please include your current average hourly volume and your projected peak volume during high-traffic events (e.g., Black Friday/Cyber Monday). Requests are typically processed within 3 to 5 business days.
