# Cookie Consent Lie Detector

A Chrome extension that audits whether websites actually respect your "Reject All" cookie choice. It captures a baseline before you interact with the consent banner, monitors what happens after you click reject, and generates a Lie Score with detailed evidence.

Research by ETH Zurich found that the vast majority of websites using consent management platforms have at least one cookie consent violation ([CookieBlock, 2022](https://github.com/dibollinger/CookieBlock)). This tool makes those violations visible.

## How It Works

1. **Visit any website** with a cookie consent banner
2. The extension **auto-detects the banner** and captures a baseline snapshot of cookies and tracking pixels
3. **Click "Reject All"** on the site's cookie banner
4. The extension detects your rejection (auto or manual), waits for the site to process it, then **audits what actually changed**
5. A **Lie Score (0-100)** tells you how much the site violated your consent choice

### What It Detects

| Signal | What It Means | Contributes to Score |
|---|---|---|
| **Persisted Tracking Cookies** | Known tracking cookies (Google Analytics, Facebook, etc.) still present after rejection | Yes (0-35 pts) |
| **New Tracking Cookies** | Tracking cookies the site actively set AFTER you clicked reject | Yes (0-25 pts) |
| **Unexpected New Cookies** | Non-consent cookies that appeared after rejection | Yes (0-15 pts) |
| **New Tracking Pixels** | Invisible 1x1 images/iframes from tracker domains loaded after rejection | Yes (0-20 pts) |
| **Browser Fingerprinting** | Canvas, WebGL, Audio, Font, and MediaDevice fingerprinting detected | Shown separately (not in consent score) |

Fingerprinting is reported as a separate alert because it operates independently of cookie consent. Rejecting cookies doesn't stop fingerprinting, and a site that removes all cookies but fingerprints you isn't technically lying about cookies.

## Cookie Classification

Unlike tools that rely on static blocklists, the Lie Detector uses a **heuristic classifier** that analyzes 5 properties of each cookie to determine if it's tracking, consent, or functional:

| Signal | Tracking Indicators | Functional Indicators |
|---|---|---|
| **Name** | Matches known patterns (_ga, _fbp, _hjid, etc.) | — |
| **Domain** | Third-party, known tracker domain | First-party |
| **Value** | UUID, high-entropy random string | Short/simple, consent preference data |
| **Expiry** | Long-lived (>1 year) | Session, short-lived |
| **Attributes** | SameSite=None, JS-accessible cross-site | HttpOnly + Secure + first-party |

This catches unknown tracking cookies that aren't in any blocklist. For example, a third-party cookie with a UUID value, long expiry, and SameSite=None scores high on tracking signals regardless of its name.

Every classification includes transparent reasoning with point values, visible on the Details page.

## Installation

1. Clone this repository
2. Open Chrome and go to `chrome://extensions/`
3. Enable **Developer mode** (top right toggle)
4. Click **Load unpacked** and select the `cookie-lie-detector` folder
5. The extension icon appears in your toolbar

## Usage

### Automatic Mode
Visit a website with a cookie banner. The extension auto-detects the banner, captures a baseline, and watches for your rejection click. After you click "Reject All," the extension audits at 2, 5, and 10 seconds and shows the final score on the badge.

If the site reloads the page after rejection (common with OneTrust and other CMPs), the extension detects the same-domain reload, preserves the audit state, and resumes automatically on the new page.

### Manual Mode
If auto-detection doesn't catch the banner:
1. Click the extension icon
2. Click **Start Audit** (captures baseline)
3. Click "Reject All" on the website's cookie banner
4. Click **Capture After Rejection**

### Viewing Results
- **Popup**: Shows the Lie Score, fingerprinting alert, consent violations, and a stats breakdown with tooltips explaining each metric
- **Copy Results**: Copies a CSV row to clipboard matching the audit spreadsheet format — useful for batch-testing multiple sites
- **View Details**: Opens a full-page report showing every cookie with its classification, confidence score, and reasoning. Also shows baseline vs. after cookie comparison, tracking pixel analysis, and fingerprinting methods detected
- **Reset Audit**: Clears the audit state without reloading the page, so you can re-run

## Banner Detection

The extension uses three detection layers:

1. **Known CMP Selectors** — ~40 CSS selectors for popular consent management platforms (OneTrust, Cookiebot, Quantcast, Didomi, SourcePoint, TrustArc, Iubenda, Klaro, etc.)
2. **Heuristic Detection** — Finds fixed/sticky overlay elements containing cookie-related text. Requires at least 2 distinct keywords (e.g., "cookie" + "consent") or a strong phrase (e.g., "we use cookies"), minimum 50 characters of text, and the presence of interactive buttons. Excludes navigation bars, headers, and footers.
3. **MutationObserver** — Watches for dynamically injected banners that load after the initial page render

### Rejection Detection

Three strategies are used, with fallback priority:
- **Button text matching** — Identifies reject buttons by text patterns (supports English, German, French, Spanish, Italian) and attaches click listeners
- **Banner click delegation** — Listens for any click inside the banner and classifies the button text as reject/accept
- **Banner disappearance** — If the above don't fire, polls for the banner being removed or hidden. Checks the last button clicked inside the banner, then falls back to CMP APIs (TCF, OneTrust, Cookiebot) and consent cookies to determine the consent action

## Project Structure

```
cookie-lie-detector/
  manifest.json              — Chrome Extension Manifest V3
  background.js              — Service worker: cookie monitoring, scoring engine, audit coordination
  content.js                 — Content script (ISOLATED world): banner detection, pixel detection, consent monitoring
  fingerprint-detector.js    — Content script (MAIN world): detects fingerprinting via API monkey-patching
  trackers.js                — Tracker database, cookie classifier, pixel domain sets
  popup.html / popup.js / popup.css    — Extension popup UI
  details.html / details.js / details.css  — Full-page detailed audit report
  icons/                     — Extension icons
```

## Technical Details

### Why a Separate Fingerprint Detector File?

Fingerprinting detection requires overriding browser APIs (`HTMLCanvasElement.toDataURL`, `WebGLRenderingContext.getParameter`, etc.) in the **page's JavaScript context**. Chrome's Manifest V3 supports this via `"world": "MAIN"` in the content script registration, which injects the script directly into the page context and bypasses Content Security Policy restrictions that would block inline script injection.

### Scoring Integrity

The scoring engine has several safeguards:
- **`finalizeAudit` runs exactly once** — guarded by a `finalizing` flag and phase check
- **Chrome API cookies are awaited** before scoring — ensures HttpOnly cookies are included
- **Baseline chrome cookies are guaranteed** — fallback capture in `finalizeAudit` if the initial capture was missed
- **Late AUDIT_RESULT messages are rejected** — prevents overwriting finalized data
- **Report counts match scoring counts** — both use the same classified results object
- **No double-counting** — persisted cookies and new cookies are mutually exclusive filters

### Pixel Detection

Only domains whose primary purpose is beacon/pixel tracking are flagged (Facebook Pixel, Google Ads conversion, Bing UET, LinkedIn Insight, etc.). Ad platforms that serve visible content (Taboola, Outbrain, Criteo, PubMatic) are excluded to prevent false positives. Only pixels that appeared AFTER rejection are scored — pre-existing pixels are filtered by baseline comparison.

## Limitations

- **Stale baseline in auto-detection**: The baseline is captured when the banner appears, not at the exact moment of rejection. If tracking scripts load lazily between banner appearance and rejection, they may be flagged as new.
- **Iframe-based CMPs**: Some consent management platforms render inside cross-origin iframes, which content scripts cannot access. The manual flow still works in these cases.
- **Cookie walls**: Some sites (The Guardian, Daily Mail, Le Monde, etc.) require a paid subscription to access the "Reject All" option. If rejection redirects to an entirely different domain (e.g., a third-party subscription platform), the extension cannot resume the audit across that domain boundary.
- **First-party cookies only**: The Chrome cookies API scoped by domain doesn't return third-party cookies. Third-party tracking is caught by the pixel detection signal instead.
- **Service worker lifecycle**: Chrome may terminate Manifest V3 service workers after ~5 minutes of inactivity, wiping in-memory audit state. Audits complete within ~15 seconds, so this doesn't affect normal usage.

## Sites to Test

Sites with cookie banners that work well for testing:
- **bbc.com** — OneTrust CMP, has "Reject All"
- **stackoverflow.com** — Cookie consent banner (scored 21 in testing)
- **reuters.com** — OneTrust, shows Reject All (scored 21 in testing)
- **spiegel.de** — German site, strict GDPR banner

Note: Some major news sites (The Guardian, Daily Mail, Le Monde, CNN) use "cookie walls" that require a subscription to access the reject option, making them difficult to audit with this tool.

## License

MIT
