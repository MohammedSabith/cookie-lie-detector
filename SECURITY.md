# Security Policy

## Reporting a Vulnerability

If you discover a security vulnerability in this extension, please report it responsibly rather than opening a public issue.

**Contact:** Open a [GitHub Security Advisory](https://github.com/MohammedSabith/cookie-lie-detector/security/advisories/new) on this repository.

I will acknowledge the report within 48 hours and aim to release a fix within 7 days depending on severity.

## Scope

This is a client-side browser extension with no backend or server component. The main areas of interest are:

- **False positives** that incorrectly accuse a site of violating consent (e.g., a non-tracker domain in the tracker database, or a cookie name pattern matching a legitimate cookie)
- **False negatives** that miss real violations, potentially misleading users
- **Content script injection issues** that could be exploited by a malicious page
- **Data leakage** of browsing data beyond what is necessary for the audit

## Out of Scope

- Gaps in the built-in tracker domain list (missing trackers are a known limitation, not a vulnerability)
- Sites intentionally blocking or detecting the extension
- Third-party cookies blocked by browser settings (the extension warns about incognito mode)
