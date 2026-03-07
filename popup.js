/**
 * Popup script — displays audit status and results.
 * Supports both automatic detection (extension detects reject click)
 * and manual audit flow (user triggers from popup).
 */

const $ = (sel) => document.querySelector(sel);
const scoreSection = $("#score-section");
const scoreNumber = $("#score-number");
const scoreRingFill = $("#score-ring-fill");
const scoreVerdict = $("#score-verdict");
const bannerSection = $("#banner-section");
const bannerStatus = $("#banner-status");
const bannerDetail = $("#banner-detail");
const violationsSection = $("#violations-section");
const violationsList = $("#violations-list");
const statsSection = $("#stats-section");
const btnBaseline = $("#btn-baseline");
const btnCapture = $("#btn-capture");
const btnReset = $("#btn-reset");
const btnDetails = $("#btn-details");
const step1 = $("#step-1");
const step2 = $("#step-2");
const step3 = $("#step-3");

let currentTabId = null;
let pollInterval = null;
let resultsShown = false; // Prevent re-animating the score

// =========================================================
// Init — Check if we already have results
// =========================================================
async function init() {
  const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
  if (!tab) return;
  currentTabId = tab.id;

  fetchAndDisplay();

  // Poll for updates (auto-audit may be in progress)
  pollInterval = setInterval(fetchAndDisplay, 2000);

  // Stop polling after 30s
  setTimeout(() => clearInterval(pollInterval), 30000);
}

function fetchAndDisplay() {
  chrome.runtime.sendMessage(
    { type: "POPUP_GET_REPORT", tabId: currentTabId },
    (report) => {
      if (!report) return;

      // Show banner info if detected
      if (report.bannerDetected) {
        showBannerInfo(report.bannerInfo);
      }

      // Handle different phases
      if (report.phase === "done" && report.lieScore !== null && report.lieScore !== undefined) {
        clearInterval(pollInterval);
        if (!resultsShown) showResults(report);
      } else if (report.phase === "auditing") {
        showAuditInProgress(report);
      } else if (report.phase === "baseline_captured" && report.consentAction === "rejected") {
        showAuditInProgress(report);
      } else if (report.phase === "baseline_captured") {
        showBaselineCaptured();
      }
    }
  );
}

// =========================================================
// Audit Flow — Manual buttons (fallback if auto-detect fails)
// =========================================================
btnBaseline.addEventListener("click", () => {
  btnBaseline.disabled = true;
  btnBaseline.textContent = "Capturing...";
  btnBaseline.classList.add("loading");

  chrome.runtime.sendMessage(
    { type: "POPUP_START_AUDIT", tabId: currentTabId },
    (result) => {
      if (result && result.ok) {
        showBaselineCaptured();
      }
    }
  );
});

btnCapture.addEventListener("click", () => {
  btnCapture.disabled = true;
  btnCapture.textContent = "Analyzing...";
  btnCapture.classList.add("loading");

  // Update step UI immediately
  step2.classList.remove("active");
  step2.classList.add("done");
  step3.classList.add("active");

  chrome.runtime.sendMessage(
    { type: "POPUP_CAPTURE_AFTER", tabId: currentTabId },
    (result) => {
      btnCapture.classList.remove("loading");
      btnCapture.textContent = "Analysis Complete";
      // Don't show results from this callback — wait for the final
      // poll to get the complete report with all Chrome API data.
      // The polling (fetchAndDisplay) will pick it up.
    }
  );
});

btnDetails.addEventListener("click", () => {
  chrome.tabs.create({
    url: chrome.runtime.getURL(`details.html#${currentTabId}`),
  });
});

btnReset.addEventListener("click", () => {
  chrome.runtime.sendMessage(
    { type: "POPUP_RESET_AUDIT", tabId: currentTabId },
    () => {
      chrome.tabs.sendMessage(currentTabId, { type: "RESET_AUDIT" }, () => {
        // Reset the popup UI to initial state
        resultsShown = false;
        clearInterval(pollInterval);

        scoreSection.classList.add("hidden");
        $("#fingerprint-alert").classList.add("hidden");
        bannerSection.classList.add("hidden");
        violationsSection.classList.add("hidden");
        statsSection.classList.add("hidden");
        btnReset.classList.add("hidden");
        btnDetails.classList.add("hidden");

        violationsList.innerHTML = "";
        scoreNumber.textContent = "0";
        scoreRingFill.style.strokeDashoffset = 326.73;
        $("#score-site").textContent = "";

        step1.classList.add("active");
        step1.classList.remove("done");
        step2.classList.remove("active", "done");
        step3.classList.remove("active", "done");

        btnBaseline.disabled = false;
        btnBaseline.textContent = "Start Audit";
        btnBaseline.classList.remove("loading");
        btnCapture.disabled = true;
        btnCapture.textContent = "Capture After Rejection";
        btnCapture.classList.remove("loading");

        // Restart polling for auto-detection
        pollInterval = setInterval(fetchAndDisplay, 2000);
        setTimeout(() => clearInterval(pollInterval), 30000);
      });
    }
  );
});

// =========================================================
// Display States
// =========================================================
function showBaselineCaptured() {
  step1.classList.remove("active");
  step1.classList.add("done");
  step2.classList.add("active");
  btnBaseline.disabled = true;
  btnBaseline.textContent = "Baseline Captured";
  btnBaseline.classList.remove("loading");
  btnCapture.disabled = false;
}

function showAuditInProgress(report) {
  step1.classList.remove("active");
  step1.classList.add("done");
  step2.classList.remove("active");
  step2.classList.add("done");
  step3.classList.add("active");

  btnBaseline.disabled = true;
  btnBaseline.textContent = "Baseline Captured";
  btnCapture.disabled = true;
  btnCapture.textContent = "Auto-detected rejection";

  // Show a "processing" state in the score area
  scoreSection.classList.remove("hidden");
  scoreNumber.textContent = "...";
  scoreNumber.style.color = "var(--accent)";
  scoreVerdict.textContent = `Analyzing (${report.auditStage || "checking"})...`;
  scoreVerdict.style.color = "var(--text-muted)";
}

function showResults(report) {
  if (resultsShown) return; // Only show results once — prevents score re-animation
  resultsShown = true;
  clearInterval(pollInterval);

  // Mark all steps done
  step1.classList.remove("active");
  step1.classList.add("done");
  step2.classList.remove("active");
  step2.classList.add("done");
  step3.classList.add("active", "done");
  btnBaseline.disabled = true;
  btnBaseline.textContent = "Baseline Captured";
  btnCapture.disabled = true;

  if (report.consentAction === "rejected") {
    btnCapture.textContent = "Auto-detected rejection";
  } else {
    btnCapture.textContent = "Analysis Complete";
  }

  // Show site name
  if (report.url) {
    try {
      const hostname = new URL(report.url).hostname;
      $("#score-site").textContent = hostname;
    } catch {}
  }

  // Show score
  const score = report.lieScore ?? 0;
  showLieScore(score);

  // Show fingerprinting alert (separate from consent score)
  if (report.fingerprintingInfo && report.fingerprintingInfo.detected) {
    showFingerprintAlert(report.fingerprintingInfo);
  }

  // Show banner info
  if (report.bannerDetected) {
    showBannerInfo(report.bannerInfo);
  }

  // Show violations (exclude fingerprinting — it has its own section)
  const consentViolations = (report.violations || []).filter(
    (v) => v.type !== "fingerprinting"
  );
  if (consentViolations.length > 0) {
    showViolations(consentViolations);
  }

  // Show stats
  if (report.baseline || report.current) {
    showStats(report);
  }

  btnReset.classList.remove("hidden");
  btnDetails.classList.remove("hidden");
}

function showLieScore(score) {
  scoreSection.classList.remove("hidden");
  scoreSection.classList.add("fade-in");

  let current = 0;
  const duration = 1000;
  const start = performance.now();

  function animate(now) {
    const elapsed = now - start;
    const progress = Math.min(elapsed / duration, 1);
    current = Math.round(score * easeOut(progress));
    scoreNumber.textContent = current;

    const circumference = 326.73;
    const offset = circumference - (current / 100) * circumference;
    scoreRingFill.style.strokeDashoffset = offset;

    const color = getScoreColor(current);
    scoreRingFill.style.stroke = color;
    scoreNumber.style.color = color;

    if (progress < 1) requestAnimationFrame(animate);
  }

  requestAnimationFrame(animate);

  if (score === 0) {
    scoreVerdict.textContent = "Honest! This site respects your choice.";
    scoreVerdict.style.color = "var(--green)";
  } else if (score <= 20) {
    scoreVerdict.textContent = "Minor issues. Mostly respectful.";
    scoreVerdict.style.color = "var(--yellow)";
  } else if (score <= 50) {
    scoreVerdict.textContent = "Suspicious. Partial consent violations.";
    scoreVerdict.style.color = "var(--orange)";
  } else if (score <= 75) {
    scoreVerdict.textContent = "Liar. Significant consent violations.";
    scoreVerdict.style.color = "var(--red)";
  } else {
    scoreVerdict.textContent = "Shameless liar. Your rejection was completely ignored.";
    scoreVerdict.style.color = "var(--red)";
  }
}

function showBannerInfo(info) {
  bannerSection.classList.remove("hidden");
  if (info) {
    bannerStatus.textContent = "Detected";
    bannerStatus.className = "status-badge detected";
    let detail = `CMP: ${info.cmp || "Unknown"}`;
    if (info.hasRejectButton) {
      detail += ` | Reject: "${info.rejectButtonText || "found"}"`;
    } else {
      detail += " | No clear reject button found";
    }
    bannerDetail.textContent = detail;
  } else {
    bannerStatus.textContent = "Not detected";
    bannerStatus.className = "status-badge not-detected";
    bannerDetail.textContent = "No cookie consent banner detected on this page.";
  }
}

function showViolations(violations) {
  violationsSection.classList.remove("hidden");
  violationsSection.classList.add("fade-in");
  violationsList.innerHTML = "";

  const typeLabels = {
    tracking_cookies: "Tracking Cookies Persisted",
    new_tracking_cookies: "New Tracking After Rejection",
    unexpected_cookies: "Unexpected New Cookies",
    fingerprinting: "Browser Fingerprinting",
    tracking_pixels: "Tracking Pixels After Rejection",
  };

  for (const v of violations) {
    const card = document.createElement("div");
    card.className = `violation-card ${v.severity}`;
    card.innerHTML = `
      <div class="violation-header">
        <span class="violation-type">${typeLabels[v.type] || v.type}</span>
        <span class="violation-severity severity-${v.severity}">${v.severity}</span>
      </div>
      <p class="violation-message">${escapeHtml(v.message)}</p>
      <div class="violation-details">${escapeHtml(v.details.slice(0, 10).join(", "))}${v.details.length > 10 ? ` +${v.details.length - 10} more` : ""}</div>
    `;
    violationsList.appendChild(card);
  }
}

function showFingerprintAlert(fpInfo) {
  const section = $("#fingerprint-alert");
  section.classList.remove("hidden");
  section.classList.add("fade-in");

  const methodNames = {
    canvas: "Canvas",
    webgl: "WebGL",
    audioContext: "Audio",
    fonts: "Fonts",
    mediaDevices: "Media Devices",
  };

  const labels = fpInfo.methods.map((m) => methodNames[m] || m);
  $("#fp-alert-methods").textContent = labels.join("  ·  ");
}

function showStats(report) {
  statsSection.classList.remove("hidden");
  statsSection.classList.add("fade-in");

  const b = report.baseline || {};
  const c = report.current || {};

  setText("stat-cookies-before", b.cookieCount ?? "-");
  setText("stat-cookies-after", c.cookieCount ?? "-");
  setText("stat-tracking", c.trackingCookies ?? "-");
  setText("stat-new-tracking", c.newTrackingCookies ?? "-");
  setText("stat-pixels", c.trackingPixels ?? "-");

  if (c.trackingCookies > 0) $("#stat-tracking").style.color = "var(--red)";
  if (c.newTrackingCookies > 0) $("#stat-new-tracking").style.color = "var(--red)";
}

// =========================================================
// Helpers
// =========================================================
function setText(id, val) {
  const el = $(`#${id}`);
  if (el) el.textContent = val;
}

function getScoreColor(score) {
  if (score === 0) return "var(--green)";
  if (score <= 20) return "var(--yellow)";
  if (score <= 50) return "var(--orange)";
  return "var(--red)";
}

function easeOut(t) {
  return 1 - Math.pow(1 - t, 3);
}

function escapeHtml(str) {
  const div = document.createElement("div");
  div.textContent = str;
  return div.innerHTML;
}

// =========================================================
// Tooltips — JS-positioned to stay within popup bounds
// =========================================================
let activeBubble = null;

document.addEventListener("mouseenter", (e) => {
  if (!e.target || !e.target.closest) return;
  const trigger = e.target.closest(".tooltip-trigger");
  if (!trigger) return;

  const text = trigger.getAttribute("data-tooltip");
  if (!text) return;

  // Remove any existing bubble
  if (activeBubble) activeBubble.remove();

  const bubble = document.createElement("div");
  bubble.className = "tooltip-bubble";
  bubble.textContent = text;
  document.body.appendChild(bubble);
  activeBubble = bubble;

  // Position: try above the trigger, clamped within the popup
  const triggerRect = trigger.getBoundingClientRect();
  const bubbleRect = bubble.getBoundingClientRect();
  const popupWidth = document.body.clientWidth;
  const popupHeight = document.body.clientHeight;

  // Horizontal: center on trigger, clamp to popup edges with 8px padding
  let left = triggerRect.left + triggerRect.width / 2 - bubbleRect.width / 2;
  left = Math.max(8, Math.min(left, popupWidth - bubbleRect.width - 8));

  // Vertical: prefer above, fall back to below if no room
  let top = triggerRect.top - bubbleRect.height - 6;
  if (top < 8) {
    top = triggerRect.bottom + 6;
  }

  bubble.style.left = left + "px";
  bubble.style.top = top + "px";
}, true);

document.addEventListener("mouseleave", (e) => {
  if (!e.target || !e.target.closest) return;
  const trigger = e.target.closest(".tooltip-trigger");
  if (!trigger) return;

  if (activeBubble) {
    activeBubble.remove();
    activeBubble = null;
  }
}, true);

// =========================================================
// Run
// =========================================================
init();
