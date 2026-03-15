/**
 * Known tracker database — domains and patterns used for tracking.
 * Sourced from public tracker lists (Disconnect, EasyPrivacy, DuckDuckGo Tracker Radar).
 */

const TRACKER_DB = {
  // --- Advertising / Marketing ---
  // Only domains whose PRIMARY purpose is ad serving / ad tracking.
  advertising: [
    "doubleclick.net",
    "googlesyndication.com",
    "googleadservices.com",
    "google-analytics.com",
    "googletagmanager.com",
    "adnxs.com",               // AppNexus / Xandr
    "adsrvr.org",              // The Trade Desk
    "amazon-adsystem.com",
    "criteo.com",
    "criteo.net",
    "demdex.net",              // Adobe Audience Manager
    "facebook.net",            // Facebook tracking SDK (NOT facebook.com or fbcdn.net)
    "moatads.com",             // Oracle Moat ad verification
    "outbrain.com",            // Content recommendation + tracking
    "taboola.com",             // Content recommendation + tracking
    "tapad.com",               // Cross-device tracking
    "rubiconproject.com",      // Magnite ad exchange
    "pubmatic.com",
    "openx.net",
    "casalemedia.com",         // Index Exchange
    "indexww.com",             // Index Exchange
    "bidswitch.net",
    "sharethrough.com",
    "smartadserver.com",
    "media.net",               // Yahoo/Bing contextual ads
    "adform.net",
    "bat.bing.com",            // Bing UET tag (specific subdomain, NOT bing.com)
    "ads-twitter.com",
    "t.co",                    // Twitter click tracker (only sub-resource loads are caught)
    // REMOVED: fbcdn.net — Facebook CDN, serves static assets (images/CSS/JS), not tracking
    // REMOVED: bing.com/bat.js — was extracting to bing.com (all of Bing). Fixed → bat.bing.com
  ],

  // --- Analytics ---
  // Only services that track user behavior. Excludes APM, privacy-focused analytics,
  // A/B testing, and debugging tools.
  analytics: [
    "google-analytics.com",
    "analytics.google.com",
    "googletagmanager.com",
    "hotjar.com",
    "hotjar.io",
    "fullstory.com",
    "mixpanel.com",
    "segment.com",
    "segment.io",
    "amplitude.com",
    "heap.io",
    "heapanalytics.com",
    "mouseflow.com",
    "luckyorange.com",
    "crazyegg.com",
    "clarity.ms",              // Microsoft Clarity session recording
    "smartlook.com",
    // REMOVED: plausible.io — privacy-focused, no cookies, GDPR-compliant without consent
    // REMOVED: posthog.com — open-source, self-hostable, privacy-focused
    // REMOVED: matomo.cloud — privacy-respecting analytics alternative
    // REMOVED: newrelic.com / nr-data.net — APM (server monitoring), not user tracking
    // REMOVED: optimizely.com — A/B testing, not cross-site tracking
    // REMOVED: logrocket.com / logrocket.io — debugging/error replay tool
    // REMOVED: clarium.io — unclear/defunct
  ],

  // --- Social Media Tracking ---
  // Only SPECIFIC tracking subdomains. Main domains (facebook.com, tiktok.com, etc.)
  // excluded because they serve legitimate embeds, widgets, and content.
  social: [
    "connect.facebook.net",    // Facebook SDK / tracking pixel loader
    "ads.linkedin.com",        // LinkedIn ad tracking
    "snap.licdn.com",          // LinkedIn tracking pixel
    "px.ads.linkedin.com",     // LinkedIn Insight Tag
    "analytics.tiktok.com",    // TikTok analytics pixel
    "ct.pinterest.com",        // Pinterest conversion tag
    "pins.reddit.com",         // Reddit conversion pixel
    "ads-twitter.com",         // Twitter/X ad tracking
    "analytics.twitter.com",   // Twitter/X analytics
    "sc-static.net",           // Snapchat ad tracking SDK
    // REMOVED: facebook.com/tr — was extracting to facebook.com (all of Facebook)
    // REMOVED: reddit.com/rpixel — was extracting to reddit.com (all of Reddit)
    // REMOVED: platform.twitter.com — serves tweet embeds, not just tracking
    // REMOVED: platform.linkedin.com — serves Sign-in buttons, profile widgets
    // REMOVED: tiktok.com — main domain, serves embedded videos
    // REMOVED: pinterest.com — main domain, serves embeds/buttons
    // REMOVED: snapchat.com — main domain
  ],

  // --- Tracking Pixels / Beacons ---
  // Used ONLY by PIXEL_DOMAINS for detecting 1x1 images and hidden iframes.
  // NOT added to ALL_TRACKER_DOMAINS — pixel detection context (tiny hidden images)
  // is different from network request monitoring (where facebook.com could be a
  // legitimate embed). Broader domains are safe here because we only check them
  // against actual hidden/1x1 elements.
  pixels: [
    "facebook.com",              // Facebook Pixel (/tr endpoint)
    "connect.facebook.net",      // Facebook SDK pixel
    "bat.bing.com",              // Bing UET tag
    "ct.pinterest.com",          // Pinterest conversion tag
    "analytics.twitter.com",     // Twitter/X analytics pixel
    "ads-twitter.com",           // Twitter/X ad pixel
    "t.co",                      // Twitter/X redirect tracker
    "px.ads.linkedin.com",       // LinkedIn Insight Tag
    "snap.licdn.com",            // LinkedIn tracking pixel
    "analytics.tiktok.com",      // TikTok pixel

    "googleadservices.com",      // Google Ads conversion tracking
    "doubleclick.net",           // Google DoubleClick pixel
    "googlesyndication.com",     // Google ad beacon

    "pixel.quantserve.com",      // Quantcast measurement pixel
    "pixel.adsafeprotected.com", // IAS ad verification pixel
    "sp.analytics.yahoo.com",    // Yahoo analytics pixel
    "demdex.net",                // Adobe Audience Manager sync pixel
  ],

  // --- Fingerprinting Services ---
  // Only actual fingerprinting-as-a-service providers used for tracking.
  // Bot detection / fraud prevention services REMOVED — they fingerprint
  // for security (stopping bots, preventing fraud), not cross-site tracking.
  // Their cookies serve legitimate security functions.
  fingerprinting: [
    "fingerprintjs.com",
    "fpjs.io",
    // REMOVED: arkoselabs.com — CAPTCHA / bot detection (security)
    // REMOVED: perimeterx.net — bot protection / HUMAN Security (security)
    // REMOVED: datadome.co — bot detection (security)
    // REMOVED: distil.it — bot detection / Imperva (security)
    // REMOVED: iovation.com — fraud prevention / TransUnion (security)
    // REMOVED: threatmetrix.com — fraud prevention / LexisNexis (security)
  ],
};

// Flatten tracker domains into lookup structures.
// ALL_TRACKER_DOMAINS — used by webRequest monitoring, cookie capture, heuristic classifier.
// Must be precise: only domains that are ALWAYS trackers regardless of context.
// Excludes pixel-only domains (facebook.com, etc.) to prevent false positives from
// legitimate embeds/widgets triggering tracker detection.
const ALL_TRACKER_DOMAINS = new Set();
const TRACKER_CATEGORIES = {};

// PIXEL_DOMAINS — used ONLY by content.js pixel detection (1x1 images, hidden iframes).
// Can include broader domains because pixel detection context (tiny hidden elements)
// has inherently low false-positive risk.
const PIXEL_DOMAINS = new Set();
for (const domain of TRACKER_DB.pixels) {
  PIXEL_DOMAINS.add(domain);
}

for (const [category, domains] of Object.entries(TRACKER_DB)) {
  for (const domain of domains) {
    // Populate category lookup for all domains (used by checkPixelTracker reporting)
    if (!TRACKER_CATEGORIES[domain]) {
      TRACKER_CATEGORIES[domain] = [];
    }
    TRACKER_CATEGORIES[domain].push(category);

    // Only add non-pixel domains to ALL_TRACKER_DOMAINS.
    // Pixel domains are checked separately via PIXEL_DOMAINS in content.js.
    if (category !== "pixels") {
      ALL_TRACKER_DOMAINS.add(domain);
    }
  }
}

/**
 * Check if a URL belongs to a known tracker.
 * Returns { isTracker, domain, categories } or null.
 */
function checkTracker(url) {
  try {
    const hostname = new URL(url).hostname;
    for (const trackerDomain of ALL_TRACKER_DOMAINS) {
      if (
        hostname === trackerDomain ||
        hostname.endsWith("." + trackerDomain)
      ) {
        return {
          isTracker: true,
          matchedDomain: trackerDomain,
          categories: TRACKER_CATEGORIES[trackerDomain] || ["unknown"],
          hostname: hostname,
        };
      }
    }
    return { isTracker: false, hostname: hostname };
  } catch {
    return { isTracker: false, hostname: "unknown" };
  }
}

// =========================================================
// Known name patterns (still useful as a strong signal)
// =========================================================
const TRACKING_COOKIE_PATTERNS = [
  /^_ga$/,         // Google Analytics (exact: _ga)
  /^_ga_/,         // Google Analytics (prefixed: _ga_XXXXXXX)
  /^_gid$/,        // Google Analytics
  /^_gat(_|$)/,    // Google Analytics (_gat or _gat_UA-XXXXX, not _gateway)
  /^_gcl_/,        // Google Ads (_gcl_au, _gcl_aw, etc.)
  /^_fbp$/,        // Facebook Pixel
  /^_fbc$/,        // Facebook Click
  /^fr$/,          // Facebook
  /^_pin_unauth/,  // Pinterest
  /^_uetsid$/,     // Bing UET
  /^_uetvid$/,     // Bing UET
  /^_tt_/,         // TikTok
  /^__hssc$/,      // HubSpot
  /^__hssrc$/,     // HubSpot
  /^__hstc$/,      // HubSpot
  /^hubspotutk$/,  // HubSpot
  /^li_sugr$/,     // LinkedIn
  /^bcookie$/,     // LinkedIn (exact match only)
  /^lidc$/,        // LinkedIn (exact match only)
  /^_hjid$/,       // Hotjar
  /^_hjSession/,   // Hotjar (_hjSessionUser_*, _hjSession_*)
  /^mp_[0-9a-f]+_mixpanel$/, // Mixpanel (specific format: mp_{token}_mixpanel)
  /^amplitude_id/, // Amplitude
  /^optimizelyEndUserId$/, // Optimizely
  /^_clck$/,       // Microsoft Clarity
  /^_clsk$/,       // Microsoft Clarity
  /^IDE$/,         // DoubleClick
  /^NID$/,         // Google
  /^test_cookie$/, // DoubleClick
  /^YSC$/,         // YouTube
  /^VISITOR_INFO/,  // YouTube (VISITOR_INFO1_LIVE, etc.)
];

const CONSENT_COOKIE_PATTERNS = [
  /^OptanonConsent/,         // OneTrust
  /^OptanonAlertBoxClosed/,  // OneTrust
  /^OneTrust/,               // OneTrust (various: OneTrustWPCCPAGoogleOptOut, etc.)
  /^usprivacy$/,             // US Privacy / CCPA signal string
  /^CookieConsent/,          // Cookiebot
  /^CookieControl/,          // Civic
  /^euconsent/,              // IAB TCF
  /^__cmpcc/,                // Generic CMP
  /^cookielawinfo/,          // CookieLaw
  /^gdpr/i,                  // Generic GDPR
  /^cc_cookie/,              // Cookie Consent (Osano)
  /^klaro/,                  // Klaro
  /^didomi/,                 // Didomi
  /^sp_consent/,             // SourcePoint (specific consent cookie, not broad sp_)
  /^truste/i,                // TrustArc
  /^iubenda/,                // Iubenda
  /^_iub_cs/,                // Iubenda
  /^consent/i,               // Generic consent
  // NOTE: __cf_bm and cf_clearance are Cloudflare security cookies (bot mgmt).
  // They are NOT consent cookies. They are handled as "functional" by the
  // heuristic classifier (HttpOnly + Secure + first-party → +10 functional).
];

/**
 * Check if a URL belongs to a known pixel/beacon tracker.
 * More restrictive than checkTracker() — only matches domains known
 * for pixel tracking and advertising, not general analytics.
 */
function checkPixelTracker(url) {
  try {
    const hostname = new URL(url).hostname;
    for (const pixelDomain of PIXEL_DOMAINS) {
      if (
        hostname === pixelDomain ||
        hostname.endsWith("." + pixelDomain)
      ) {
        return {
          isPixelTracker: true,
          matchedDomain: pixelDomain,
          categories: TRACKER_CATEGORIES[pixelDomain] || ["pixels"],
          hostname: hostname,
        };
      }
    }
    return { isPixelTracker: false, hostname: hostname };
  } catch {
    return { isPixelTracker: false, hostname: "unknown" };
  }
}

// Simple name-only checks (used by content.js which can't see cookie attributes)
function isTrackingCookie(cookieName) {
  return TRACKING_COOKIE_PATTERNS.some((pattern) => pattern.test(cookieName));
}

function isConsentCookie(cookieName) {
  return CONSENT_COOKIE_PATTERNS.some((pattern) => pattern.test(cookieName));
}

// =========================================================
// Heuristic Cookie Classifier
// =========================================================
// Uses multiple signals to classify cookies, not just name patterns.
// This catches unknown tracking cookies that aren't in our blocklist.

/**
 * Classify a cookie using heuristic analysis of all its properties.
 *
 * @param {object} cookie - Full cookie object from Chrome cookies API:
 *   { name, value, domain, expirationDate, httpOnly, secure, sameSite, path }
 * @param {string} pageDomain - The domain of the page the user is visiting
 * @returns {{ classification: string, confidence: number, reasons: string[] }}
 *   classification: "tracking" | "consent" | "functional" | "unknown"
 *   confidence: 0.0 - 1.0
 */
function classifyCookie(cookie, pageDomain) {
  let trackingScore = 0;
  let consentScore = 0;
  let functionalScore = 0;
  const reasons = [];

  const name = cookie.name || "";
  const value = cookie.value || "";
  const domain = (cookie.domain || "").replace(/^\./, "");

  // ---------------------------------------------------------
  // Signal 1: Name patterns (strong signal when matched)
  // ---------------------------------------------------------
  if (TRACKING_COOKIE_PATTERNS.some((p) => p.test(name))) {
    trackingScore += 40;
    reasons.push("name matches known tracking pattern [+40 tracking]");
  }
  if (CONSENT_COOKIE_PATTERNS.some((p) => p.test(name))) {
    consentScore += 40;
    reasons.push("name matches known consent pattern [+40 consent]");
  }

  // ---------------------------------------------------------
  // Signal 2: Domain — third-party vs first-party
  // ---------------------------------------------------------
  const isThirdParty = pageDomain && domain &&
    !pageDomain.endsWith(domain) && !domain.endsWith(pageDomain);

  if (isThirdParty) {
    trackingScore += 15;
    reasons.push(`third-party domain (${domain}) [+15 tracking]`);

    // Check if the domain is a known tracker
    for (const trackerDomain of ALL_TRACKER_DOMAINS) {
      if (domain === trackerDomain || domain.endsWith("." + trackerDomain)) {
        trackingScore += 25;
        reasons.push(`domain is known tracker (${trackerDomain}) [+25 tracking]`);
        break;
      }
    }
  } else {
    functionalScore += 5;
    reasons.push("first-party domain [+5 functional]");
  }

  // ---------------------------------------------------------
  // Signal 3: Value analysis
  // ---------------------------------------------------------
  if (value.length > 0) {
    // UUID pattern: tracking signal
    if (/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i.test(value)) {
      trackingScore += 15;
      reasons.push("value is a UUID [+15 tracking]");
    }
    // Long random-looking string (high entropy): tracking signal
    else if (/^[A-Za-z0-9_-]{30,}$/.test(value) && hasHighEntropy(value)) {
      trackingScore += 12;
      reasons.push("value looks like a unique identifier (high entropy) [+12 tracking]");
    }

    // Consent preference patterns
    const lowerVal = value.toLowerCase();
    if (
      lowerVal.includes("marketing:") ||
      lowerVal.includes("statistics:") ||
      lowerVal.includes("preferences:") ||
      /C000[1-9]:[01]/.test(value) ||        // OneTrust groups
      lowerVal.includes("consent") ||
      lowerVal.includes("necessary")
    ) {
      consentScore += 25;
      reasons.push("value contains consent preference data [+25 consent]");
    }

    // Short simple values are more likely functional
    if (value.length <= 5 && /^[a-zA-Z0-9]+$/.test(value)) {
      functionalScore += 5;
      reasons.push("short simple value [+5 functional]");
    }
  }

  // ---------------------------------------------------------
  // Signal 4: Expiry
  // ---------------------------------------------------------
  if (cookie.expirationDate) {
    const now = Date.now() / 1000;
    const daysUntilExpiry = (cookie.expirationDate - now) / 86400;

    if (daysUntilExpiry > 365) {
      trackingScore += 10;
      reasons.push(`long expiry (${Math.round(daysUntilExpiry)} days) [+10 tracking]`);
    } else if (daysUntilExpiry > 180) {
      trackingScore += 5;
      reasons.push(`moderate expiry (${Math.round(daysUntilExpiry)} days) [+5 tracking]`);
    } else if (daysUntilExpiry <= 1) {
      functionalScore += 5;
      reasons.push("short-lived cookie [+5 functional]");
    }
  } else {
    // Session cookie (no expiry) — likely functional
    functionalScore += 8;
    reasons.push("session cookie (no expiry) [+8 functional]");
  }

  // ---------------------------------------------------------
  // Signal 5: Cookie attributes
  // ---------------------------------------------------------
  if (cookie.sameSite === "none") {
    trackingScore += 10;
    reasons.push("SameSite=None (allows cross-site use) [+10 tracking]");
  }

  if (!cookie.httpOnly && isThirdParty) {
    trackingScore += 5;
    reasons.push("not HttpOnly + third-party (JS-accessible cross-site) [+5 tracking]");
  }

  if (cookie.httpOnly && cookie.secure && !isThirdParty) {
    functionalScore += 10;
    reasons.push("HttpOnly + Secure + first-party (likely session/auth) [+10 functional]");
  }

  // ---------------------------------------------------------
  // Determine classification
  // ---------------------------------------------------------
  const maxScore = Math.max(trackingScore, consentScore, functionalScore);
  let classification = "unknown";
  let confidence = 0;

  if (trackingScore >= 20 && trackingScore >= consentScore && trackingScore >= functionalScore) {
    classification = "tracking";
    confidence = Math.min(1, trackingScore / 80);
  } else if (consentScore >= 20 && consentScore >= trackingScore && consentScore >= functionalScore) {
    classification = "consent";
    confidence = Math.min(1, consentScore / 65);
  } else if (functionalScore >= 15 && functionalScore >= trackingScore) {
    classification = "functional";
    confidence = Math.min(1, functionalScore / 30);
  } else {
    confidence = 0.2;
  }

  return {
    classification,
    confidence: Math.round(confidence * 100) / 100,
    reasons,
    scores: { tracking: trackingScore, consent: consentScore, functional: functionalScore },
  };
}

/**
 * Shannon entropy estimate — high entropy means the string looks random
 * (like a tracking ID), low entropy means it's structured/readable.
 */
function hasHighEntropy(str) {
  if (str.length < 10) return false;
  const freq = {};
  for (const ch of str) {
    freq[ch] = (freq[ch] || 0) + 1;
  }
  let entropy = 0;
  const len = str.length;
  for (const count of Object.values(freq)) {
    const p = count / len;
    entropy -= p * Math.log2(p);
  }
  // English text ~4.5 bits, random base64 ~5.5-6 bits
  return entropy > 4.8;
}

// =========================================================
// Exports
// =========================================================
if (typeof globalThis !== "undefined") {
  globalThis.TRACKER_DB = TRACKER_DB;
  globalThis.ALL_TRACKER_DOMAINS = ALL_TRACKER_DOMAINS;
  globalThis.TRACKER_CATEGORIES = TRACKER_CATEGORIES;
  globalThis.checkTracker = checkTracker;
  globalThis.checkPixelTracker = checkPixelTracker;
  globalThis.PIXEL_DOMAINS = PIXEL_DOMAINS;
  globalThis.isTrackingCookie = isTrackingCookie;
  globalThis.isConsentCookie = isConsentCookie;
  globalThis.classifyCookie = classifyCookie;
  globalThis.TRACKING_COOKIE_PATTERNS = TRACKING_COOKIE_PATTERNS;
  globalThis.CONSENT_COOKIE_PATTERNS = CONSENT_COOKIE_PATTERNS;
}
