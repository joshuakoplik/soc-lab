---
tenant: fenwick
department: Support
label: public
title: Fenwick Analytics Mobile App FAQ
shares: []
contains_pii: false
contains_credential: false
---

# Fenwick Analytics Mobile App FAQ

**Document Owner:** Support Department  
**Last Updated:** October 14, 2023

Welcome to the official support guide for the Fenwick Analytics mobile application. This document provides quick answers to common questions regarding installation, data synchronization, and account management.

### Getting Started
**Which devices are supported?**  
The Fenwick app is compatible with iOS 15.0 or later and Android 11.0 or later. We recommend using a device with at least 4GB of RAM to ensure smooth rendering of complex data visualizations.

**How do I activate my account on mobile?**  
Once you have downloaded the app from the App Store or Google Play, log in using your corporate SSO credentials. If your organization uses Duo or Okta for multi-factor authentication, you will be prompted to verify your identity before accessing your first dashboard.

### Data & Performance
**How often does the mobile app sync with the main server?**  
By default, the app performs a "Delta Sync" every 15 minutes. You can trigger a manual refresh at any time by pulling down on the home screen. For users on the Enterprise Tier, real-time streaming is available for specific "Critical Alert" widgets.

**Can I use the app offline?**  
Yes. The app caches the last three viewed dashboards for offline access. Please note that while you can view cached data, any filters applied or reports generated while offline will be queued and processed once a connection is re-established.

**Why are some of my complex SQL queries not running on mobile?**  
To maintain performance and battery life, the mobile app restricts "Heavy Compute" queries that exceed 30 seconds of processing time. For these deep-dive analytics, we recommend using the Fenwick Desktop Portal.

### Troubleshooting & Security
**I forgot my password. How do I reset it?**  
Click the "Forgot Password" link on the login screen. An automated reset link will be sent to your registered company email. For security reasons, these links expire after 24 hours.

**How is my data secured on the device?**  
Fenwick employs AES-256 encryption for all data at rest. Additionally, you can enable Biometric Lock (FaceID or Fingerprint) in the *Settings > Security* menu to add an extra layer of protection when opening the app.

**Who do I contact for technical bugs?**  
Please submit a ticket via the "Help" tab within the app or email support@fenwickanalytics.com with your device model and OS version included.
