/**
 * Known tracker database — domains and patterns used for tracking.
 * Sourced from public tracker lists (Disconnect, EasyPrivacy, DuckDuckGo Tracker Radar).
 */

const TRACKER_DB = {
  // --- Advertising / Marketing ---
  advertising: [
    "doubleclick.net",
    "googlesyndication.com",
    "googleadservices.com",
    "google-analytics.com",
    "googletagmanager.com",
    "adnxs.com",
    "adsrvr.org",
    "amazon-adsystem.com",
    "criteo.com",
    "criteo.net",
    "demdex.net",
    "facebook.net",
    "fbcdn.net",
    "moatads.com",
    "outbrain.com",
    "taboola.com",
    "tapad.com",
    "rubiconproject.com",
    "pubmatic.com",
    "openx.net",
    "casalemedia.com",
    "indexww.com",
    "bidswitch.net",
    "sharethrough.com",
    "smartadserver.com",
    "media.net",
    "adform.net",
    "bing.com/bat.js",
    "ads-twitter.com",
    "t.co",
  ],

  // --- Analytics ---
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
    "optimizely.com",
    "newrelic.com",
    "nr-data.net",
    "matomo.cloud",
    "plausible.io",
    "clarity.ms",
    "clarium.io",
    "logrocket.com",
    "logrocket.io",
    "smartlook.com",
    "posthog.com",
  ],

  // --- Social Media Tracking ---
  social: [
    "connect.facebook.net",
    "facebook.com/tr",
    "platform.twitter.com",
    "ads.linkedin.com",
    "snap.licdn.com",
    "platform.linkedin.com",
    "px.ads.linkedin.com",
    "sc-static.net",
    "snapchat.com",
    "tiktok.com",
    "analytics.tiktok.com",
    "pinterest.com",
    "pins.reddit.com",
    "reddit.com/rpixel",
  ],

  // --- Tracking Pixels / Beacons ---
  // These domains are specifically known for pixel/beacon-based tracking
  // (tiny invisible images or iframes that fire HTTP requests to log visits).
  // Kept separate from analytics — loading a Hotjar JS SDK is different
  // from Facebook embedding a 1x1 tracking pixel.
  pixels: [
    // Social media pixels — fire invisible beacons to log page visits
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

    // Ad conversion pixels — track conversions, not content delivery
    "googleadservices.com",      // Google Ads conversion tracking
    "doubleclick.net",           // Google DoubleClick pixel
    "googlesyndication.com",     // Google ad beacon

    // Measurement/verification pixels
    "pixel.quantserve.com",      // Quantcast measurement pixel
    "pixel.adsafeprotected.com", // IAS ad verification pixel
    "sp.analytics.yahoo.com",    // Yahoo analytics pixel
    "demdex.net",                // Adobe Audience Manager sync pixel

    // NOT included: ad exchanges/SSPs that serve visible content
    // (Criteo, Taboola, Outbrain, PubMatic, RubiconProject, etc.)
    // These are caught by cookie classification instead.
  ],

  // --- Fingerprinting Services ---
  fingerprinting: [
    "fingerprintjs.com",
    "fpjs.io",
    "arkoselabs.com",
    "perimeterx.net",
    "datadome.co",
    "distil.it",
    "iovation.com",
    "threatmetrix.com",
  ],
};

// Flatten all tracker domains into a single Set for fast lookup
const ALL_TRACKER_DOMAINS = new Set();
const TRACKER_CATEGORIES = {};

// Separate set for pixel-specific domains (used by pixel detection only).
// ONLY includes domains whose primary purpose is beacon/pixel tracking.
// Ad platforms (Taboola, Criteo, PubMatic, etc.) excluded — they serve
// visible content and would cause false positives. They're still caught
// by cookie classification if they set tracking cookies after rejection.
const PIXEL_DOMAINS = new Set();
for (const domain of TRACKER_DB.pixels) {
  PIXEL_DOMAINS.add(domain.split("/")[0]);
}

for (const [category, domains] of Object.entries(TRACKER_DB)) {
  for (const domain of domains) {
    const cleanDomain = domain.split("/")[0]; // Remove path portions
    ALL_TRACKER_DOMAINS.add(cleanDomain);
    if (!TRACKER_CATEGORIES[cleanDomain]) {
      TRACKER_CATEGORIES[cleanDomain] = [];
    }
    TRACKER_CATEGORIES[cleanDomain].push(category);
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
  /^_ga/,          // Google Analytics
  /^_gid/,         // Google Analytics
  /^_gat/,         // Google Analytics
  /^_gcl/,         // Google Ads
  /^_fbp/,         // Facebook Pixel
  /^_fbc/,         // Facebook Click
  /^fr$/,          // Facebook
  /^_pin_unauth/,  // Pinterest
  /^_uetsid/,      // Bing UET
  /^_uetvid/,      // Bing UET
  /^_tt_/,         // TikTok
  /^__hssc/,       // HubSpot
  /^__hssrc/,      // HubSpot
  /^__hstc/,       // HubSpot
  /^hubspotutk/,   // HubSpot
  /^li_sugr/,      // LinkedIn
  /^bcookie/,      // LinkedIn
  /^lidc/,         // LinkedIn
  /^_hjid/,        // Hotjar
  /^_hjSession/,   // Hotjar
  /^mp_/,          // Mixpanel
  /^amplitude_id/, // Amplitude
  /^optimizelyEndUserId/, // Optimizely
  /^_clck/,        // Microsoft Clarity
  /^_clsk/,        // Microsoft Clarity
  /^IDE$/,         // DoubleClick
  /^NID$/,         // Google
  /^test_cookie/,  // DoubleClick
  /^YSC$/,         // YouTube
  /^VISITOR_INFO/,  // YouTube
];

const CONSENT_COOKIE_PATTERNS = [
  /^OptanonConsent/,         // OneTrust
  /^OptanonAlertBoxClosed/,  // OneTrust
  /^CookieConsent/,          // Cookiebot
  /^CookieControl/,          // Civic
  /^euconsent/,              // IAB TCF
  /^__cmpcc/,                // Generic CMP
  /^cookielawinfo/,          // CookieLaw
  /^gdpr/i,                  // Generic GDPR
  /^cc_cookie/,              // Cookie Consent (Osano)
  /^klaro/,                  // Klaro
  /^didomi/,                 // Didomi
  /^sp_/,                    // SourcePoint
  /^truste/i,                // TrustArc
  /^iubenda/,                // Iubenda
  /^_iub_cs/,                // Iubenda
  /^__cf_bm/,                // Cloudflare bot mgmt (functional)
  /^cf_clearance/,           // Cloudflare (functional)
  /^consent/i,               // Generic consent
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
