# Security Policy

## Reporting a Vulnerability

If you discover a security vulnerability in this extension, please report it responsibly rather than opening a public issue.

**Contact:** Open a [GitHub Security Advisory](https://github.com/MohammedSabith/cookie-lie-detector/security/advisories/new) on this repository.

I will acknowledge the report within 48 hours and aim to release a fix within 7 days depending on severity.

## Scope

This is a client-side browser extension with no backend or server component. The main areas of interest are:

- **False positives** that incorrectly accuse a site of violating consent
- **False negatives** that miss real violations, potentially misleading users
- **Content script injection issues** that could be exploited by a malicious page
- **Data leakage** of browsing data beyond what is necessary for the audit

## Out of Scope

- Issues in third-party tracker databases (Disconnect, EasyPrivacy) that this extension references
- Sites intentionally blocking or detecting the extension
