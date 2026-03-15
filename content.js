/**
 * Content script — runs on every page.
 * Detects cookie consent banners, auto-captures baseline,
 * watches for reject button clicks, and monitors for violations.
 */

(() => {
  "use strict";

  // =========================================================
  // State
  // =========================================================
  const state = {
    phase: "watching", // watching | baseline_captured | rejected | auditing | done
    fingerprinting: {
      canvas: 0,
      webgl: 0,
      audioContext: 0,
      fonts: 0,
      mediaDevices: 0,
    },
    domCookiesBefore: [],
    domCookiesAfter: [],
    bannerDetected: false,
    bannerInfo: null,
    bannerElement: null,
    rejectButton: null,
    trackingPixels: [],
    baselineCapturedAt: null,
    rejectedAt: null,
  };

  // =========================================================
  // 1. Fingerprinting Detection
  // =========================================================
  // The actual API monkey-patching is in fingerprint-detector.js,
  // registered with "world": "MAIN" in manifest.json. Chrome injects
  // it directly into the page context, bypassing CSP restrictions.
  // It reports detections via window.postMessage → we listen here.

  // Listen for fingerprint reports from the MAIN world script
  window.addEventListener("message", (event) => {
    if (event.data && event.data.type === "CCLD_FINGERPRINT") {
      state.fingerprinting[event.data.method] =
        (state.fingerprinting[event.data.method] || 0) + 1;
      reportToBackground();
    }
  });

  // =========================================================
  // 2. Cookie Consent Banner Detection
  // =========================================================
  const BANNER_SELECTORS = [
    "#onetrust-banner-sdk",
    "#onetrust-consent-sdk",
    ".onetrust-pc-dark-filter",
    "#CybotCookiebotDialog",
    "#CybotCookiebotDialogBody",
    "#cookie-law-info-bar",
    "#gdpr-cookie-notice",
    ".cc-banner",
    ".cc-window",
    "#cookie-notice",
    "#cookie-consent",
    "#cookieconsent",
    ".cookie-consent",
    ".cookie-banner",
    ".cookie-notice",
    ".consent-banner",
    ".privacy-banner",
    "#privacy-banner",
    '[class*="cookie-banner"]',
    '[class*="cookie-consent"]',
    '[class*="cookieConsent"]',
    '[class*="consent-banner"]',
    '[id*="cookie-banner"]',
    '[id*="cookie-consent"]',
    '[id*="cookieconsent"]',
    '[aria-label*="cookie"]',
    '[aria-label*="consent"]',
    '[role="dialog"][class*="cookie"]',
    '[role="dialog"][class*="consent"]',
    ".fc-consent-root",
    "#sp_message_container",
    ".qc-cmp2-container",
    "#didomi-host",
    ".evidon-banner",
    "#truste-consent-track",
    ".iubenda-cs-container",
    "#klaro",
  ];

  const REJECT_BUTTON_PATTERNS = [
    /reject\s*all/i,
    /decline\s*all/i,
    /deny\s*all/i,
    /refuse\s*all/i,
    /reject\s*cookies/i,
    /reject/i,
    /decline/i,
    /deny/i,
    /only\s*necessary/i,
    /only\s*essential/i,
    /necessary\s*only/i,
    /essential\s*only/i,
    /do\s*not\s*accept/i,
    /do\s*not\s*agree/i,
    /do\s*not\s*consent/i,
    /not\s*agree/i,         // "I do not agree"
    /not\s*consent/i,       // "I do not consent"
    /no,?\s*thanks/i,
    /disagree/i,
    /opt[\s-]*out/i,
    /ablehnen/i,         // German: reject
    /tout\s*refuser/i,   // French: reject all
    /rechazar/i,         // Spanish: reject
    /rifiuta/i,          // Italian: reject
  ];

  const ACCEPT_BUTTON_PATTERNS = [
    /accept\s*all/i,
    /accept\s*cookies/i,
    /accept\s*(&|and)\s*/i,  // "Accept and close", "Accept & continue"
    /allow\s*all/i,
    /allow\s*cookies/i,
    /^accept$/i,             // Bare "Accept" as full button text
    /^i\s*accept$/i,         // "I accept" as full text
    /^i\s*agree$/i,          // "I agree" as full text (not "I do not agree")
    /\bagree\s*(&|and)\s*continue\b/i,
    /\bagree\b$/i,           // "Agree" at end: "I Agree" ✓, "Disagree" ✗
    /got\s*it/i,
    /^ok$/i,                 // Only "OK" as the entire button text
    /^i\s*consent$/i,        // "I consent" as full text, not "manage consent"
  ];

  function detectBanner() {
    // Strategy 1: Known CMP selectors
    for (const selector of BANNER_SELECTORS) {
      try {
        const el = document.querySelector(selector);
        if (el && isVisible(el)) {
          return onBannerFound(el, selector, "selector");
        }
      } catch {
        // Invalid selector, skip
      }
    }

    // Strategy 2: Heuristic — find fixed/sticky overlays containing cookie-related text
    const heuristicBanner = detectBannerHeuristic();
    if (heuristicBanner) {
      return onBannerFound(heuristicBanner, "heuristic", "heuristic");
    }

    return null;
  }

  /**
   * Heuristic banner detection — finds elements that look like cookie banners
   * based on position, z-index, size, and text content.
   */
  function detectBannerHeuristic() {
    // Individual keywords for matching
    const COOKIE_WORDS = ["cookie", "consent", "gdpr", "privacy", "datenschutz", "données", "privacidad"];
    const COOKIE_KEYWORDS_RE = /cookie|consent|gdpr|privacy|datenschutz|données|privacidad/i;

    // Strong phrases that almost certainly indicate a cookie banner
    const STRONG_PHRASES = /we\s*use\s*cookies|this\s*(site|website)\s*uses\s*cookies|cookie\s*policy|cookie\s*preferences|manage\s*cookies|cookie\s*settings|cookie\s*consent/i;

    const candidates = [];

    function scoreElement(el) {
      if (!isVisible(el)) return null;

      const text = el.textContent.substring(0, 1500);
      if (!COOKIE_KEYWORDS_RE.test(text)) return null;

      // Require buttons
      const buttons = el.querySelectorAll("button, a[role='button'], input[type='button']");
      if (buttons.length === 0) return null;

      // Exclude navigation elements — nav bars aren't cookie banners
      const tag = el.tagName.toLowerCase();
      if (tag === "nav" || tag === "header" || tag === "footer") return null;
      if (el.querySelector("nav") && !el.querySelector('[class*="cookie"], [class*="consent"]')) return null;

      // Require minimum text length — a real cookie banner has more than a few words
      const textLength = text.trim().length;
      if (textLength < 50) return null;

      // Count distinct keyword matches
      const lowerText = text.toLowerCase();
      let distinctKeywords = 0;
      for (const word of COOKIE_WORDS) {
        if (lowerText.includes(word)) distinctKeywords++;
      }

      // Require at least 2 distinct keywords (e.g., "cookie" + "consent")
      // OR a strong phrase (e.g., "we use cookies")
      const hasStrongPhrase = STRONG_PHRASES.test(text);
      if (distinctKeywords < 2 && !hasStrongPhrase) return null;

      const hasAcceptRejectButtons =
        findRejectButton(el) !== null || findAcceptButton(el) !== null;

      const score =
        distinctKeywords * 3 +
        (hasStrongPhrase ? 15 : 0) +
        (hasAcceptRejectButtons ? 10 : 0) +
        Math.min(buttons.length, 5);

      return { el, score };
    }

    // Check fixed/sticky positioned elements
    const overlayElements = document.querySelectorAll(
      '[style*="position: fixed"], [style*="position:fixed"], ' +
      '[style*="position: sticky"], [style*="position:sticky"], ' +
      '[role="dialog"], [role="alertdialog"], [aria-modal="true"]'
    );

    for (const el of overlayElements) {
      const style = window.getComputedStyle(el);
      const isOverlay =
        style.position === "fixed" ||
        style.position === "sticky" ||
        parseInt(style.zIndex) > 999;
      if (!isOverlay) continue;

      const result = scoreElement(el);
      if (result) candidates.push(result);
    }

    // Check dialog/modal/overlay elements (some don't use inline styles)
    const dialogElements = document.querySelectorAll(
      'div[role="dialog"], div[role="alertdialog"], div[aria-modal="true"], ' +
      'div[class*="modal"], div[class*="overlay"], div[class*="popup"], ' +
      'div[class*="bottom-bar"], div[class*="bottombar"], div[class*="notification-bar"]'
    );

    for (const el of dialogElements) {
      const result = scoreElement(el);
      if (result) candidates.push(result);
    }

    if (candidates.length === 0) return null;

    // Return the highest-scoring candidate
    candidates.sort((a, b) => b.score - a.score);
    return candidates[0].el;
  }

  function findAcceptButton(container) {
    const buttons = container.querySelectorAll(
      'button, a[role="button"], input[type="button"]'
    );
    for (const btn of buttons) {
      const text = btn.textContent.trim();
      if (!text) continue;
      for (const pattern of ACCEPT_BUTTON_PATTERNS) {
        if (pattern.test(text)) return btn;
      }
    }
    return null;
  }

  function onBannerFound(el, selector, method) {
    const rejectBtn = findRejectButton(el);
    state.bannerDetected = true;
    state.bannerElement = el;
    state.rejectButton = rejectBtn;
    state.bannerInfo = {
      selector: selector,
      detectionMethod: method,
      cmp: identifyCMP(el),
      hasRejectButton: rejectBtn !== null,
      rejectButtonText: rejectBtn ? rejectBtn.textContent.trim().substring(0, 50) : null,
    };

    // Auto-capture baseline when banner is detected
    if (state.phase === "watching") {
      captureBaseline();
    }

    // Watch for reject button click
    if (rejectBtn) {
      watchRejectButton(rejectBtn, el);
    }

    // Watch ALL buttons in the banner
    watchBannerButtons(el);

    // Watch for banner disappearance (most reliable signal)
    watchBannerDisappearance(el);

    reportToBackground();
    return el;
  }

  function isVisible(el) {
    if (!el) return false;
    const style = window.getComputedStyle(el);
    return (
      style.display !== "none" &&
      style.visibility !== "hidden" &&
      style.opacity !== "0" &&
      el.offsetWidth > 0 &&
      el.offsetHeight > 0
    );
  }

  function identifyCMP(bannerEl) {
    const html = bannerEl.outerHTML.substring(0, 2000).toLowerCase();
    if (html.includes("onetrust")) return "OneTrust";
    if (html.includes("cookiebot")) return "Cookiebot";
    if (html.includes("quantcast") || html.includes("qc-cmp")) return "Quantcast";
    if (html.includes("didomi")) return "Didomi";
    if (html.includes("sourcepoint") || html.includes("sp_message")) return "SourcePoint";
    if (html.includes("iubenda")) return "Iubenda";
    if (html.includes("klaro")) return "Klaro";
    if (html.includes("truste") || html.includes("trustarc")) return "TrustArc";
    if (html.includes("funding") || html.includes("fc-consent")) return "FundingChoices";
    if (html.includes("osano")) return "Osano";
    return "Unknown CMP";
  }

  function findRejectButton(container) {
    const buttons = container.querySelectorAll(
      'button, a[role="button"], input[type="button"], [class*="reject"], [class*="decline"], [class*="deny"], [id*="reject"], [id*="decline"]'
    );
    for (const btn of buttons) {
      const text = btn.textContent.trim();
      if (!text) continue;
      for (const pattern of REJECT_BUTTON_PATTERNS) {
        if (pattern.test(text)) {
          return btn;
        }
      }
    }
    return null;
  }

  function classifyButtonClick(button) {
    const text = button.textContent.trim();
    for (const pattern of REJECT_BUTTON_PATTERNS) {
      if (pattern.test(text)) return "reject";
    }
    for (const pattern of ACCEPT_BUTTON_PATTERNS) {
      if (pattern.test(text)) return "accept";
    }
    return "other";
  }

  // =========================================================
  // 3. Auto-Watch for Reject Button Clicks
  // =========================================================
  let rejectWatched = false;

  function watchRejectButton(btn, bannerEl) {
    if (rejectWatched) return;
    rejectWatched = true;

    btn.addEventListener("click", () => {
      onConsentRejected(bannerEl);
    }, { once: true, capture: true });
  }

  function watchBannerButtons(bannerEl) {
    // Watch all clickable elements inside the banner
    bannerEl.addEventListener("click", (e) => {
      const button = e.target.closest("button, a[role='button'], [class*='btn'], input[type='button']");
      if (!button) return;

      const action = classifyButtonClick(button);
      if (action === "reject") {
        onConsentRejected(bannerEl);
      } else if (action === "accept") {
        onConsentAccepted(bannerEl);
      }
    }, { capture: true });
  }

  /**
   * Watch for the banner element disappearing from the page.
   * This is the most reliable signal that the user interacted with consent,
   * regardless of which button they clicked or how the CMP works.
   */
  function watchBannerDisappearance(bannerEl) {
    let checkCount = 0;
    const maxChecks = 120; // Check for 60 seconds (every 500ms)
    let lastBannerClickedButton = null;  // Click inside banner
    let lastPageClickedButton = null;    // Click anywhere (fallback)

    // Track clicks inside the banner specifically
    const bannerClickTracker = (e) => {
      const btn = e.target.closest("button, a[role='button'], [class*='btn'], input[type='button'], a");
      if (btn) lastBannerClickedButton = btn;
    };
    bannerEl.addEventListener("click", bannerClickTracker, { capture: true });

    // Fallback: track page-level clicks, but only use if no banner click detected
    const pageClickTracker = (e) => {
      const btn = e.target.closest("button, a[role='button'], [class*='btn'], input[type='button']");
      if (btn) lastPageClickedButton = btn;
    };
    document.addEventListener("click", pageClickTracker, { capture: true });

    const interval = setInterval(() => {
      checkCount++;

      // Banner gone from DOM or hidden
      const gone = !document.contains(bannerEl) || !isVisible(bannerEl);

      if (gone && state.phase === "baseline_captured") {
        clearInterval(interval);
        document.removeEventListener("click", pageClickTracker, { capture: true });

        // Priority 1: Check button clicked INSIDE the banner
        let action = "unknown";
        if (lastBannerClickedButton) {
          action = classifyButtonClick(lastBannerClickedButton);
        }

        // Priority 2: Check CMP APIs and consent cookies (most reliable)
        if (action === "unknown" || action === "other") {
          action = detectConsentStatus();
        }

        // Priority 3: Page-level click (only if it matches known consent patterns)
        // DON'T use page clicks for classification — too risky for false positives.
        // A "Decline" on a form is not a cookie rejection.

        if (action === "reject") {
          onConsentRejected(bannerEl);
        } else if (action === "accept") {
          onConsentAccepted(bannerEl);
        } else {
          // Can't determine what the user clicked.
          // Don't assume — let the user use the manual flow instead.
          // Auto-triggering on unknown would cause false audits.
        }
      }

      if (checkCount >= maxChecks) {
        clearInterval(interval);
        document.removeEventListener("click", pageClickTracker, { capture: true });
      }
    }, 500);
  }

  /**
   * Try to detect consent status from CMP APIs / cookies.
   * Many CMPs set specific cookies or expose JS APIs after consent is given.
   */
  function detectConsentStatus() {
    // Check TCF API (IAB standard)
    if (typeof window.__tcfapi === "function") {
      try {
        let status = "unknown";
        window.__tcfapi("getTCData", 2, (data, success) => {
          if (success && data) {
            // If purpose consents are mostly false, user rejected
            const consents = data.purpose?.consents || {};
            const consentCount = Object.values(consents).filter(Boolean).length;
            status = consentCount <= 1 ? "reject" : "accept";
          }
        });
        if (status !== "unknown") return status;
      } catch {}
    }

    // Check OneTrust-specific
    if (typeof window.OnetrustActiveGroups === "string") {
      // C0001=Necessary, C0002=Performance, C0003=Functional, C0004=Targeting
      // If tracking categories (C0002, C0004) are absent → user rejected tracking
      const groups = window.OnetrustActiveGroups;
      if (groups.includes("C0002") || groups.includes("C0004")) return "accept";
      if (groups.includes("C0001")) return "reject"; // Has necessary but no tracking = rejected
    }

    // Check Cookiebot-specific
    if (window.Cookiebot) {
      try {
        const cb = window.Cookiebot;
        if (cb.consent && !cb.consent.marketing && !cb.consent.statistics) return "reject";
        if (cb.consent && cb.consent.marketing) return "accept";
      } catch {}
    }

    // Check for common consent cookies
    const cookies = document.cookie;
    // OneTrust stores groups in OptanonConsent cookie
    const optanon = cookies.match(/OptanonConsent=([^;]*)/);
    if (optanon) {
      const decoded = decodeURIComponent(optanon[1]);
      // groups=C0001:1,C0002:0 means only necessary accepted
      if (decoded.includes("C0002:0") && decoded.includes("C0004:0")) return "reject";
      if (decoded.includes("C0002:1")) return "accept";
    }

    // Cookiebot consent cookie
    const cbCookie = cookies.match(/CookieConsent=([^;]*)/);
    if (cbCookie) {
      const val = decodeURIComponent(cbCookie[1]);
      if (val.includes("marketing:false") && val.includes("statistics:false")) return "reject";
      if (val.includes("marketing:true")) return "accept";
    }

    return "unknown";
  }

  function onConsentRejected(bannerEl) {
    if (state.phase === "rejected" || state.phase === "auditing" || state.phase === "done") {
      return; // Already processing
    }

    // Re-capture baseline right before rejection.
    // The original baseline was captured at banner detection time, which may be
    // seconds earlier. Scripts that loaded in between may have set cookies or
    // loaded tracking pixels that should be in the baseline.
    state.domCookiesBefore = parseCookies();
    detectTrackingPixels();

    state.phase = "rejected";
    state.rejectedAt = Date.now();

    chrome.runtime.sendMessage({
      type: "CONSENT_REJECTED",
      data: {
        url: window.location.href,
        bannerInfo: state.bannerInfo,
        cookies: state.domCookiesBefore,
        trackingPixels: [...state.trackingPixels],
        timestamp: state.rejectedAt,
      },
    });

    // Wait for the site to process the rejection, then audit
    // Check at 2s, 5s, and 10s to catch delayed tracking
    setTimeout(() => runAudit("early"), 2000);
    setTimeout(() => runAudit("mid"), 5000);
    setTimeout(() => runAudit("final"), 10000);
  }

  function onConsentAccepted(bannerEl) {
    // User accepted — not interesting for our purposes, but log it
    chrome.runtime.sendMessage({
      type: "CONSENT_ACCEPTED",
      data: {
        url: window.location.href,
        bannerInfo: state.bannerInfo,
        timestamp: Date.now(),
      },
    });
  }

  // =========================================================
  // 4. Audit — Compare Before vs After
  // =========================================================
  function captureBaseline() {
    state.phase = "baseline_captured";
    state.baselineCapturedAt = Date.now();
    state.domCookiesBefore = parseCookies();
    detectTrackingPixels();

    chrome.runtime.sendMessage({
      type: "BASELINE_CAPTURED",
      data: {
        cookies: state.domCookiesBefore,
        trackingPixels: [...state.trackingPixels],
        fingerprinting: { ...state.fingerprinting },
        url: window.location.href,
        timestamp: state.baselineCapturedAt,
      },
    });
  }

  function runAudit(stage) {
    state.phase = "auditing";
    state.domCookiesAfter = parseCookies();
    detectTrackingPixels();

    // Compare before/after cookies
    const beforeNames = new Set(state.domCookiesBefore.map((c) => c.name));
    const newCookies = state.domCookiesAfter.filter(
      (c) => !beforeNames.has(c.name)
    );
    const newTrackingCookies = newCookies.filter((c) => c.isTracking);
    const persistedTrackingCookies = state.domCookiesAfter.filter(
      (c) => c.isTracking
    );

    chrome.runtime.sendMessage({
      type: "AUDIT_RESULT",
      data: {
        stage: stage,
        cookiesBefore: state.domCookiesBefore.length,
        cookiesAfter: state.domCookiesAfter.length,
        newCookies: newCookies,
        newTrackingCookies: newTrackingCookies,
        persistedTrackingCookies: persistedTrackingCookies,
        trackingPixels: state.trackingPixels,
        fingerprinting: { ...state.fingerprinting },
        bannerInfo: state.bannerInfo,
        url: window.location.href,
        timestamp: Date.now(),
      },
    });

    if (stage === "final") {
      state.phase = "done";
    }
  }

  // =========================================================
  // 5. Tracking Pixel Detection
  // =========================================================
  function detectTrackingPixels() {
    const pixels = [];

    // 1x1 images and hidden images
    const images = document.querySelectorAll("img");
    for (const img of images) {
      const isPixel =
        (img.width <= 3 && img.height <= 3) ||
        (img.naturalWidth <= 3 && img.naturalHeight <= 3) ||
        img.style.display === "none" ||
        img.style.visibility === "hidden" ||
        (img.style.width === "0px" && img.style.height === "0px") ||
        (img.style.width === "1px" && img.style.height === "1px");

      if (isPixel && img.src) {
        const trackerInfo = checkPixelTracker(img.src);
        if (trackerInfo && trackerInfo.isPixelTracker) {
          pixels.push({
            src: img.src,
            tracker: trackerInfo.matchedDomain,
            categories: trackerInfo.categories,
          });
        }
      }
    }

    // Beacon-style iframes
    const iframes = document.querySelectorAll("iframe");
    for (const iframe of iframes) {
      if (
        iframe.src &&
        (iframe.width <= 3 || iframe.height <= 3 ||
         iframe.style.display === "none" ||
         iframe.style.visibility === "hidden")
      ) {
        const trackerInfo = checkPixelTracker(iframe.src);
        if (trackerInfo && trackerInfo.isPixelTracker) {
          pixels.push({
            src: iframe.src,
            tracker: trackerInfo.matchedDomain,
            categories: trackerInfo.categories,
            type: "iframe",
          });
        }
      }
    }

    state.trackingPixels = pixels;
    return pixels;
  }

  // =========================================================
  // 6. DOM Cookie Monitoring
  // =========================================================
  function parseCookies() {
    return document.cookie.split(";").map((c) => {
      const [name, ...rest] = c.trim().split("=");
      return {
        name: name.trim(),
        value: rest.join("="),
        isTracking: isTrackingCookie(name.trim()),
      };
    }).filter((c) => c.name);
  }

  // =========================================================
  // 7. Communication with Background Script
  // =========================================================
  function reportToBackground() {
    chrome.runtime.sendMessage({
      type: "CONTENT_REPORT",
      data: {
        phase: state.phase,
        fingerprinting: { ...state.fingerprinting },
        bannerDetected: state.bannerDetected,
        bannerInfo: state.bannerInfo,
        trackingPixels: state.trackingPixels,
        domCookies: parseCookies(),
        url: window.location.href,
        timestamp: Date.now(),
      },
    });
  }

  // Listen for messages from popup/background
  chrome.runtime.onMessage.addListener((msg, sender, sendResponse) => {
    if (msg.type === "START_AUDIT") {
      // Manual audit start from popup
      captureBaseline();
      sendResponse({ ok: true, phase: state.phase });
    }

    if (msg.type === "CAPTURE_AFTER") {
      // Manual "after" capture from popup
      runAudit("final");
      sendResponse({ ok: true, phase: state.phase });
    }

    if (msg.type === "GET_STATE") {
      sendResponse({
        phase: state.phase,
        fingerprinting: { ...state.fingerprinting },
        bannerDetected: state.bannerDetected,
        bannerInfo: state.bannerInfo,
        trackingPixels: state.trackingPixels,
        domCookies: parseCookies(),
        baselineCapturedAt: state.baselineCapturedAt,
        rejectedAt: state.rejectedAt,
      });
    }

    if (msg.type === "RESUME_AUDIT") {
      // Background detected a same-domain page reload during an active audit
      // (consent-triggered reload). Scan the new page for pixels and fingerprinting
      // and return the data so background can finalize the audit.
      detectTrackingPixels();
      sendResponse({
        ok: true,
        trackingPixels: state.trackingPixels,
        fingerprinting: { ...state.fingerprinting },
      });
    }

    if (msg.type === "RESET_AUDIT") {
      // Reset all state back to initial without reloading the page.
      // NOTE: fingerprinting is NOT reset — it's a page-level event that
      // happened during page load. The scripts won't re-execute without
      // a reload, so clearing the counts would lose the evidence.
      state.phase = "watching";
      state.domCookiesBefore = [];
      state.domCookiesAfter = [];
      state.bannerDetected = false;
      state.bannerInfo = null;
      state.bannerElement = null;
      state.rejectButton = null;
      state.trackingPixels = [];
      state.baselineCapturedAt = null;
      state.rejectedAt = null;
      rejectWatched = false;

      // Re-start banner detection — banner may still be gone (user already
      // interacted), so this is mainly for the manual flow on next attempt
      setTimeout(() => {
        const banner = detectBanner();
        if (!banner) watchForBanner();
      }, 500);

      sendResponse({ ok: true });
    }

    return true;
  });

  // =========================================================
  // 8. Watch for banner appearing via MutationObserver
  // =========================================================
  function watchForBanner() {
    const observer = new MutationObserver((mutations) => {
      if (state.bannerDetected) return;

      for (const mutation of mutations) {
        for (const node of mutation.addedNodes) {
          if (node.nodeType !== Node.ELEMENT_NODE) continue;
          // Check if the added node IS a banner or CONTAINS a banner
          const banner = detectBanner();
          if (banner) {
            observer.disconnect();
            return;
          }
        }
      }
    });

    observer.observe(document.documentElement, {
      childList: true,
      subtree: true,
    });

    // Stop watching after 30 seconds to save resources
    setTimeout(() => observer.disconnect(), 30000);
  }

  // =========================================================
  // 9. Initialize
  // =========================================================
  function startup() {
    // Try to detect banner immediately
    const banner = detectBanner();

    if (!banner) {
      // Banner might load later (dynamically injected by CMP scripts)
      watchForBanner();
    }

    // Also detect tracking pixels
    setTimeout(detectTrackingPixels, 2000);
    setTimeout(reportToBackground, 3000);
  }

  if (document.readyState === "loading") {
    document.addEventListener("DOMContentLoaded", () => {
      setTimeout(startup, 500);
    });
  } else {
    setTimeout(startup, 500);
  }
})();
