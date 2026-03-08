/**
 * Background service worker — monitors cookies, coordinates audits,
 * and calculates lie scores. Handles both automatic and manual audit flows.
 */

importScripts("trackers.js");

// =========================================================
// Per-tab audit state
// =========================================================
const tabState = {};

function getTabState(tabId) {
  if (!tabState[tabId]) {
    tabState[tabId] = {
      phase: "watching",
      baseline: {
        cookies: [],        // from content.js (name + value only)
        chromeCookies: null, // from Chrome API (full attributes) — null means not yet captured
        trackingPixels: [],
        fingerprinting: {},
        timestamp: null,
      },
      after: {
        cookies: [],
        chromeCookies: null,
        newTrackingCookies: [],
        persistedTrackingCookies: [],
        trackingPixels: [],
        fingerprinting: {},
        timestamp: null,
      },
      // Final classified results (set by calculateLieScore, used by buildReport)
      classifiedResults: null,
      contentReport: null,
      lieScore: null,
      violations: [],
      bannerDetected: false,
      bannerInfo: null,
      consentAction: null,
      auditStage: null,
      fingerprintingInfo: null, // { detected, methods, count } — separate from consent score
      url: "",
      finalizing: false, // Guard against concurrent finalizeAudit calls
      pendingReload: false, // Set when consent-triggered page reload detected
    };
  }
  return tabState[tabId];
}

// Clean up when tab closes
chrome.tabs.onRemoved.addListener((tabId) => {
  delete tabState[tabId];
});

// Reset on navigation — but preserve state on same-domain reload during active audit
chrome.webNavigation.onBeforeNavigate.addListener((details) => {
  if (details.frameId !== 0) return;

  const ts = tabState[details.tabId];
  if (!ts) return;

  // Check if this is a same-domain navigation during an active audit
  let oldDomain = "";
  let newDomain = "";
  try { oldDomain = new URL(ts.url).hostname; } catch {}
  try { newDomain = new URL(details.url).hostname; } catch {}

  const auditActive = ts.consentAction === "rejected" || ts.phase === "auditing";
  const sameDomain = oldDomain && newDomain &&
    (oldDomain === newDomain || oldDomain.endsWith("." + newDomain) || newDomain.endsWith("." + oldDomain));

  if (sameDomain && auditActive && ts.phase !== "done") {
    // Consent-triggered reload — keep state, mark for resumption
    // Cancel any pending resume timer from a previous reload (redirect chains)
    if (ts._resumeTimer) {
      clearTimeout(ts._resumeTimer);
      ts._resumeTimer = null;
    }
    ts.pendingReload = true;
  } else {
    delete tabState[details.tabId];
  }
});

// After a consent-triggered reload completes, resume the audit
chrome.webNavigation.onCompleted.addListener((details) => {
  if (details.frameId !== 0) return;

  const ts = tabState[details.tabId];
  if (!ts || !ts.pendingReload) return;

  ts.pendingReload = false;

  // Wait for the new page's content.js to be ready, then ask it to scan
  // Store timer ID so it can be canceled if another reload happens
  ts._resumeTimer = setTimeout(() => {
    ts._resumeTimer = null;
    chrome.tabs.sendMessage(
      details.tabId,
      { type: "RESUME_AUDIT" },
      (response) => {
        // Consume lastError to prevent console noise if content.js isn't ready
        if (chrome.runtime.lastError) {
          // Content script not ready — proceed with existing data
        }
        // If content.js responded with data, merge it
        if (response && response.ok) {
          ts.after.trackingPixels = response.trackingPixels || ts.after.trackingPixels;
          ts.after.fingerprinting = response.fingerprinting || ts.after.fingerprinting;
        }
        // Finalize regardless — chrome cookies are the priority
        finalizeAudit(details.tabId);
      }
    );
  }, 2000); // 2s for page to settle and content.js to be ready
});

// =========================================================
// Cookie monitoring via Chrome cookies API
// =========================================================
chrome.cookies.onChanged.addListener((changeInfo) => {
  const { cookie, removed } = changeInfo;
  if (removed) return;

  const cookieDomain = (cookie.domain || "").replace(/^\./, "");

  for (const [tabIdStr, ts] of Object.entries(tabState)) {
    if (ts.phase !== "auditing" && ts.consentAction !== "rejected") continue;

    // Only attribute this cookie to tabs whose URL domain matches
    let tabDomain = "";
    try { tabDomain = new URL(ts.url).hostname; } catch {}
    if (!tabDomain) continue;

    const domainMatches =
      tabDomain === cookieDomain ||
      tabDomain.endsWith("." + cookieDomain) ||
      cookieDomain.endsWith("." + tabDomain);

    // Only attribute cookies that domain-match this tab.
    // We can't reliably attribute third-party cookies to specific tabs
    // because cookies.onChanged doesn't include tab information.
    // Third-party tracking cookies (e.g. on .doubleclick.net) will be
    // caught by captureChromeCookies if the browser returns them.
    if (!domainMatches) continue;

    const cookieEntry = {
      name: cookie.name,
      domain: cookie.domain,
      isTracking: isTrackingCookie(cookie.name),
      secure: cookie.secure,
      httpOnly: cookie.httpOnly,
      sameSite: cookie.sameSite,
      expirationDate: cookie.expirationDate,
      timestamp: Date.now(),
    };

    // Deduplicate by name
    if (!ts.after.newTrackingCookies.find((c) => c.name === cookieEntry.name)) {
      if (cookieEntry.isTracking) {
        ts.after.newTrackingCookies.push(cookieEntry);
      }
    }
  }
});

// =========================================================
// Message handling
// =========================================================
chrome.runtime.onMessage.addListener((msg, sender, sendResponse) => {
  // Use msg.tabId if explicitly provided (popup/details page messages).
  // Fall back to sender.tab.id for content script messages.
  const tabId = msg.tabId || (sender.tab ? sender.tab.id : null);
  if (!tabId) return true;

  const ts = getTabState(tabId);

  // --- Content script: general report ---
  if (msg.type === "CONTENT_REPORT") {
    ts.contentReport = msg.data;
    ts.bannerDetected = msg.data.bannerDetected;
    ts.bannerInfo = msg.data.bannerInfo;
    ts.url = msg.data.url;
    sendResponse({ ok: true });
    return true;
  }

  // --- Content script: baseline auto-captured ---
  if (msg.type === "BASELINE_CAPTURED") {
    ts.phase = "baseline_captured";
    ts.baseline.cookies = msg.data.cookies;
    ts.baseline.trackingPixels = msg.data.trackingPixels;
    ts.baseline.fingerprinting = msg.data.fingerprinting;
    ts.baseline.timestamp = msg.data.timestamp;
    ts.url = msg.data.url;

    // Capture chrome cookies for baseline (async, best-effort)
    // For auto-detection flow, this is the only place baseline chrome cookies get captured.
    captureChromeCookies(tabId, "baseline");
    sendResponse({ ok: true });
    return true;
  }

  // --- Content script: user rejected consent ---
  if (msg.type === "CONSENT_REJECTED") {
    ts.consentAction = "rejected";
    ts.bannerInfo = msg.data.bannerInfo;
    updateBadge(tabId, null, "...");
    sendResponse({ ok: true });
    return true;
  }

  // --- Content script: user accepted consent ---
  if (msg.type === "CONSENT_ACCEPTED") {
    ts.consentAction = "accepted";
    sendResponse({ ok: true });
    return true;
  }

  // --- Content script: audit result (called at 2s, 5s, 10s after rejection) ---
  if (msg.type === "AUDIT_RESULT") {
    // If audit is already finalized, ignore late-arriving results
    // (can happen when both manual and auto-detection flows are active)
    if (ts.phase === "done") {
      sendResponse({ ok: true });
      return true;
    }

    ts.phase = "auditing";
    ts.auditStage = msg.data.stage;

    // Merge into ts.after (preserves chromeCookies and accumulated data)
    ts.after.cookies = msg.data.persistedTrackingCookies || [];
    ts.after.persistedTrackingCookies = msg.data.persistedTrackingCookies || [];
    ts.after.trackingPixels = msg.data.trackingPixels || [];
    ts.after.fingerprinting = msg.data.fingerprinting || {};
    ts.after.timestamp = msg.data.timestamp;

    // Accumulate new tracking cookies from content.js (deduplicated)
    const incoming = msg.data.newTrackingCookies || [];
    for (const c of incoming) {
      if (!ts.after.newTrackingCookies.find((x) => x.name === c.name)) {
        ts.after.newTrackingCookies.push(c);
      }
    }

    if (msg.data.stage === "final") {
      // Final stage — finalize with chrome cookies, calculate definitive score
      finalizeAudit(tabId);
    }

    sendResponse({ ok: true });
    return true;
  }

  // --- Popup: manual start audit ---
  if (msg.type === "POPUP_START_AUDIT") {
    startAuditForTab(tabId).then((result) => sendResponse(result));
    return true;
  }

  // --- Popup: manual capture after ---
  if (msg.type === "POPUP_CAPTURE_AFTER") {
    captureAfterForTab(tabId).then((result) => sendResponse(result));
    return true;
  }

  // --- Popup: reset audit ---
  if (msg.type === "POPUP_RESET_AUDIT") {
    delete tabState[tabId];
    updateBadge(tabId, null);
    sendResponse({ ok: true });
    return true;
  }

  // --- Popup: get report ---
  if (msg.type === "POPUP_GET_REPORT") {
    const report = buildReport(tabId);
    sendResponse(report);
    return true;
  }

  // --- Details page: get full debug report ---
  if (msg.type === "POPUP_GET_DEBUG_REPORT") {
    const report = buildDebugReport(tabId);
    sendResponse(report);
    return true;
  }

  return true;
});

// =========================================================
// Async audit flow helpers
// =========================================================

async function startAuditForTab(tabId) {
  try {
    await chrome.tabs.sendMessage(parseInt(tabId), { type: "START_AUDIT" });
  } catch {}
  await captureChromeCookies(tabId, "baseline");
  return { ok: true, phase: "baseline_captured" };
}

async function captureAfterForTab(tabId) {
  const ts = getTabState(tabId);
  try {
    await chrome.tabs.sendMessage(parseInt(tabId), { type: "CAPTURE_AFTER" });
  } catch {}

  // content.js will send AUDIT_RESULT "final" which triggers finalizeAudit.
  // Wait for it to complete instead of calling finalizeAudit ourselves.
  await waitForPhase(tabId, "done", 10000);

  return {
    ok: true,
    lieScore: ts.lieScore,
    violations: ts.violations,
  };
}

/**
 * Wait for a tab's phase to reach the target value, with timeout.
 */
function waitForPhase(tabId, targetPhase, timeoutMs) {
  return new Promise((resolve) => {
    const start = Date.now();
    const interval = setInterval(() => {
      const ts = tabState[tabId];
      if (!ts || ts.phase === targetPhase || Date.now() - start > timeoutMs) {
        clearInterval(interval);
        resolve();
      }
    }, 200);
  });
}

/**
 * Finalize the audit — capture chrome cookies, calculate definitive score.
 * Guarded against concurrent calls.
 */
async function finalizeAudit(tabId) {
  const ts = getTabState(tabId);

  // Guard: only finalize once
  if (ts.finalizing || ts.phase === "done") return;
  ts.finalizing = true;

  try {
    // Ensure baseline chrome cookies are captured (may have been missed
    // if user clicked reject very quickly after banner appeared)
    if (!ts.baseline.chromeCookies) {
      await captureChromeCookies(tabId, "baseline");
    }

    // Capture after-state chrome cookies (includes HttpOnly cookies)
    await captureChromeCookies(tabId, "after");

    // Calculate the definitive score with ALL data
    calculateLieScore(tabId);

    ts.phase = "done";
    updateBadge(tabId, ts.lieScore);
  } finally {
    ts.finalizing = false;
  }
}

// =========================================================
// Capture cookies via Chrome API (gets HttpOnly cookies too)
// =========================================================
async function captureChromeCookies(tabId, phase) {
  const ts = getTabState(tabId);
  try {
    const tab = await chrome.tabs.get(parseInt(tabId));
    if (!tab.url) return;
    const url = new URL(tab.url);
    const cookies = await chrome.cookies.getAll({ domain: url.hostname });

    const mapped = cookies.map((c) => ({
      name: c.name,
      value: c.value,
      domain: c.domain,
      isTracking: isTrackingCookie(c.name),
      secure: c.secure,
      httpOnly: c.httpOnly,
      sameSite: c.sameSite,
      expirationDate: c.expirationDate,
    }));

    if (phase === "baseline") {
      ts.baseline.chromeCookies = mapped;
    } else {
      ts.after.chromeCookies = mapped;
    }
  } catch (e) {
    // Tab may have been closed
  }
}

// =========================================================
// Lie Score Calculation
// =========================================================
function calculateLieScore(tabId) {
  const ts = getTabState(tabId);
  const violations = [];
  let score = 0;

  // Get page domain for heuristic classification
  let pageDomain = "";
  try {
    pageDomain = new URL(ts.url).hostname;
  } catch {}

  // Use Chrome API cookies if available (full attributes for heuristic classifier).
  // Only fall back to content.js cookies if Chrome API capture failed.
  const afterCookies = ts.after.chromeCookies || [];
  const baselineCookies = ts.baseline.chromeCookies || [];
  const useHeuristic = ts.after.chromeCookies !== null;

  const baselineNames = new Set(baselineCookies.map((c) => c.name));

  // If we also have content.js baseline cookies, include their names too
  // (covers cookies that Chrome API might miss due to domain scoping)
  for (const c of (ts.baseline.cookies || [])) {
    baselineNames.add(c.name);
  }

  // Classify cookies
  let classified;
  if (useHeuristic) {
    // Full attribute data available — use heuristic classifier
    classified = afterCookies.map((c) => ({
      ...c,
      classification: classifyCookie(c, pageDomain),
      isNew: !baselineNames.has(c.name),
    }));
  } else {
    // Only content.js data available — use simple name-pattern matching
    // (don't run heuristic on incomplete data, it would give wrong results)
    classified = (ts.after.cookies || []).map((c) => ({
      ...c,
      classification: {
        classification: isTrackingCookie(c.name) ? "tracking"
          : isConsentCookie(c.name) ? "consent"
          : "unknown",
        confidence: isTrackingCookie(c.name) ? 0.8 : 0.3,
        reasons: isTrackingCookie(c.name) ? ["known tracking pattern"] : ["name-only classification"],
        scores: { tracking: isTrackingCookie(c.name) ? 40 : 0, consent: 0, functional: 0 },
      },
      isNew: !baselineNames.has(c.name),
    }));
  }

  // Store classified results for the report (must match scoring logic)
  const allTracking = classified.filter((c) => c.classification.classification === "tracking");
  ts.classifiedResults = {
    total: classified.length,
    tracking: allTracking.length,
    persistedTracking: allTracking.filter((c) => !c.isNew).length,
    newTracking: allTracking.filter((c) => c.isNew).length,
    consent: classified.filter((c) => c.classification.classification === "consent").length,
    functional: classified.filter((c) => c.classification.classification === "functional").length,
    unknown: classified.filter((c) => c.classification.classification === "unknown").length,
    // New non-consent cookies (what the user cares about — excludes expected consent cookies)
    newNonConsent: classified.filter(
      (c) => c.isNew && c.classification.classification !== "consent"
    ).length,
    // New tracking pixels (not in baseline) — set after scoring runs below
    newPixels: 0,
  };

  // --- 1. PERSISTED tracking cookies — were in baseline, still here (0-35 pts) ---
  const persistedTracking = classified.filter(
    (c) => !c.isNew && c.classification.classification === "tracking"
  );

  if (persistedTracking.length > 0) {
    const pts = Math.min(35, persistedTracking.length * 7);
    score += pts;
    violations.push({
      type: "tracking_cookies",
      severity: persistedTracking.length >= 3 ? "high" : "medium",
      count: persistedTracking.length,
      details: persistedTracking.map(
        (c) => `${c.name} (${Math.round(c.classification.confidence * 100)}% — ${c.classification.reasons[0]})`
      ),
      message: `${persistedTracking.length} tracking ${persistedTracking.length === 1 ? "cookie" : "cookies"} persisted after rejection (should have been removed)`,
    });
  }

  // --- 2. NEW tracking cookies set after rejection (0-25 pts) ---
  //    These weren't in the baseline — the site actively set them after you said no.
  const newTracking = classified.filter(
    (c) => c.isNew && c.classification.classification === "tracking"
  );

  if (newTracking.length > 0) {
    const pts = Math.min(25, newTracking.length * 10);
    score += pts;
    violations.push({
      type: "new_tracking_cookies",
      severity: "high",
      count: newTracking.length,
      details: newTracking.map(
        (c) => `${c.name} (${c.classification.reasons.join(", ")})`
      ),
      message: `${newTracking.length} NEW tracking ${newTracking.length === 1 ? "cookie" : "cookies"} set AFTER you clicked reject`,
    });
  }

  // --- 3. Suspicious unknown new cookies (0-15 pts) ---
  const suspiciousNew = classified.filter(
    (c) => c.isNew &&
      c.classification.classification !== "tracking" &&
      c.classification.classification !== "consent" &&
      c.classification.classification !== "functional"
  );
  const borderline = classified.filter(
    (c) => c.isNew &&
      c.classification.classification === "functional" &&
      c.classification.scores.tracking >= 15
  );
  const allSuspicious = [...suspiciousNew, ...borderline];

  if (allSuspicious.length > 0) {
    const pts = Math.min(15, allSuspicious.length * 5);
    score += pts;
    violations.push({
      type: "unexpected_cookies",
      severity: allSuspicious.length >= 3 ? "medium" : "low",
      count: allSuspicious.length,
      details: allSuspicious.map(
        (c) => `${c.name} (${c.classification.classification}, tracking score: ${c.classification.scores.tracking})`
      ),
      message: `${allSuspicious.length} unexpected new ${allSuspicious.length === 1 ? "cookie" : "cookies"} set after rejection`,
    });
  }

  // --- 4. Fingerprinting detected (separate from consent score) ---
  const fp = ts.after.fingerprinting || {};
  const fpMethods = Object.entries(fp).filter(([, v]) => v > 0).map(([k]) => k);
  if (fpMethods.length > 0) {
    // Fingerprinting is NOT added to the consent lie score — it's a separate signal.
    // Tracked as ts.fingerprintingInfo for the popup to display independently.
    violations.push({
      type: "fingerprinting",
      severity: fpMethods.length >= 2 ? "high" : "medium",
      count: fpMethods.length,
      details: fpMethods,
      message: `${fpMethods.length} fingerprinting ${fpMethods.length === 1 ? "method" : "methods"} detected: ${fpMethods.join(", ")}`,
    });
  }
  ts.fingerprintingInfo = {
    detected: fpMethods.length > 0,
    methods: fpMethods,
    count: fpMethods.length,
  };

  // --- 5. NEW tracking pixels loaded after rejection (0-20 pts) ---
  //    Only flag pixels that weren't in the baseline — pre-existing pixels
  //    (e.g. ad containers loaded before consent interaction) aren't violations.
  const baselinePixelSrcs = new Set(
    (ts.baseline.trackingPixels || []).map((p) => p.src)
  );
  const baselinePixelTrackers = new Set(
    (ts.baseline.trackingPixels || []).map((p) => p.tracker)
  );
  const afterPixels = ts.after.trackingPixels || [];
  const newPixels = afterPixels.filter(
    (p) => !baselinePixelSrcs.has(p.src) && !baselinePixelTrackers.has(p.tracker)
  );

  if (newPixels.length > 0) {
    const pts = Math.min(20, newPixels.length * 5);
    score += pts;
    violations.push({
      type: "tracking_pixels",
      severity: newPixels.length >= 3 ? "high" : "medium",
      count: newPixels.length,
      details: newPixels.map((p) => p.tracker || p.src),
      message: `${newPixels.length} tracking ${newPixels.length === 1 ? "pixel" : "pixels"} loaded AFTER rejection`,
    });
  }

  ts.lieScore = Math.min(100, score); // Consent violations only (no fingerprinting)
  ts.violations = violations;

  // Update pixel count in classified results for the report
  if (ts.classifiedResults) {
    ts.classifiedResults.newPixels = newPixels.length;
  }
}

// =========================================================
// Badge
// =========================================================
function updateBadge(tabId, score, text) {
  const id = parseInt(tabId);
  if (text) {
    chrome.action.setBadgeBackgroundColor({ tabId: id, color: "#6366f1" });
    chrome.action.setBadgeText({ tabId: id, text });
    return;
  }

  if (score === null || score === undefined) {
    chrome.action.setBadgeText({ tabId: id, text: "" });
    return;
  }

  let color;
  if (score === 0) {
    color = "#22c55e";
    text = "OK";
  } else if (score <= 30) {
    color = "#f59e0b";
    text = String(score);
  } else if (score <= 60) {
    color = "#f97316";
    text = String(score);
  } else {
    color = "#ef4444";
    text = String(score);
  }

  chrome.action.setBadgeBackgroundColor({ tabId: id, color });
  chrome.action.setBadgeText({ tabId: id, text });
}

// =========================================================
// Build report for popup
// =========================================================
function buildReport(tabId) {
  const ts = getTabState(tabId);
  const content = ts.contentReport || {};
  const cr = ts.classifiedResults;

  // Use classified results for counts (consistent with score calculation)
  const baselineCookies = ts.baseline.chromeCookies || ts.baseline.cookies || [];
  const afterCookies = ts.after.chromeCookies || ts.after.cookies || [];

  return {
    phase: ts.phase,
    lieScore: ts.lieScore,
    violations: ts.violations,
    consentAction: ts.consentAction,
    auditStage: ts.auditStage,
    baseline: {
      cookieCount: baselineCookies.length,
      trackingCookies: cr ? null : baselineCookies.filter((c) => c.isTracking).length,
      timestamp: ts.baseline.timestamp,
    },
    current: {
      cookieCount: afterCookies.length,
      // Use classifier results if available (consistent with scoring)
      trackingCookies: cr ? cr.tracking : afterCookies.filter((c) => c.isTracking).length,
      newTrackingCookies: cr ? cr.newNonConsent : (ts.after.newTrackingCookies || []).length,
      persistedTracking: cr ? cr.persistedTracking : 0,
      trackingPixels: cr ? cr.newPixels : (ts.after.trackingPixels || []).length,
      timestamp: ts.after.timestamp,
    },
    fingerprintingInfo: ts.fingerprintingInfo || null,
    bannerDetected: ts.bannerDetected || content.bannerDetected || false,
    bannerInfo: ts.bannerInfo || content.bannerInfo || null,
    url: ts.url || content.url || "",
  };
}

/**
 * Build a full debug report with every cookie classified and all raw data.
 * Used by the details page for verification.
 */
function buildDebugReport(tabId) {
  const ts = getTabState(tabId);
  const content = ts.contentReport || {};

  let pageDomain = "";
  try { pageDomain = new URL(ts.url).hostname; } catch {}

  // Re-classify all after cookies (same logic as calculateLieScore)
  const afterCookies = ts.after.chromeCookies || [];
  const baselineCookies = ts.baseline.chromeCookies || ts.baseline.cookies || [];
  const useHeuristic = ts.after.chromeCookies !== null;

  const baselineNames = new Set(baselineCookies.map((c) => c.name));
  for (const c of (ts.baseline.cookies || [])) {
    baselineNames.add(c.name);
  }

  let classifiedCookies;
  if (useHeuristic) {
    classifiedCookies = afterCookies.map((c) => {
      const result = classifyCookie(c, pageDomain);
      return {
        name: c.name,
        domain: c.domain,
        value: (c.value || "").substring(0, 100) + ((c.value || "").length > 100 ? "..." : ""),
        classification: result.classification,
        confidence: result.confidence,
        reasons: result.reasons,
        scores: result.scores,
        isNew: !baselineNames.has(c.name),
        httpOnly: c.httpOnly,
        secure: c.secure,
        sameSite: c.sameSite,
        expirationDate: c.expirationDate,
      };
    });
  } else {
    classifiedCookies = (ts.after.cookies || []).map((c) => ({
      name: c.name,
      domain: "N/A (content.js)",
      value: (c.value || "").substring(0, 100),
      classification: isTrackingCookie(c.name) ? "tracking"
        : isConsentCookie(c.name) ? "consent" : "unknown",
      confidence: isTrackingCookie(c.name) ? 0.8 : 0.3,
      reasons: isTrackingCookie(c.name) ? ["known tracking name pattern"] : ["name-only, no attributes available"],
      scores: { tracking: isTrackingCookie(c.name) ? 40 : 0, consent: 0, functional: 0 },
      isNew: !baselineNames.has(c.name),
      httpOnly: null,
      secure: null,
      sameSite: null,
      expirationDate: null,
    }));
  }

  // Sort: tracking first, then new, then by name
  classifiedCookies.sort((a, b) => {
    const order = { tracking: 0, unknown: 1, functional: 2, consent: 3 };
    const aOrder = order[a.classification] ?? 1;
    const bOrder = order[b.classification] ?? 1;
    if (aOrder !== bOrder) return aOrder - bOrder;
    if (a.isNew !== b.isNew) return a.isNew ? -1 : 1;
    return a.name.localeCompare(b.name);
  });

  return {
    url: ts.url || content.url || "",
    phase: ts.phase,
    lieScore: ts.lieScore,
    violations: ts.violations,
    consentAction: ts.consentAction,
    bannerInfo: ts.bannerInfo || content.bannerInfo || null,
    classifiedCookies,
    baselineCookies: baselineCookies.map((c) => ({
      name: c.name,
      domain: c.domain || "N/A",
      isTracking: c.isTracking || isTrackingCookie(c.name),
      httpOnly: c.httpOnly,
      secure: c.secure,
      sameSite: c.sameSite,
    })),
    allPixels: {
      baseline: ts.baseline.trackingPixels || [],
      after: ts.after.trackingPixels || [],
    },
    fingerprinting: ts.after.fingerprinting || content.fingerprinting || {},
    after: {
      timestamp: ts.after.timestamp,
    },
    baseline: {
      timestamp: ts.baseline.timestamp,
    },
  };
}
