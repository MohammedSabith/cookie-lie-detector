/**
 * Details page — shows full audit report with classification reasoning
 * for every cookie, pixel, and fingerprinting signal.
 *
 * Opened from the popup via chrome.tabs.create. Receives tabId via URL hash.
 */

const $ = (sel) => document.querySelector(sel);

const FP_DESCRIPTIONS = {
  canvas: "Drew invisible content on a hidden canvas and read pixel data. Each device renders slightly differently, creating a unique signature that can identify your browser without cookies.",
  webgl: "Queried your GPU vendor, renderer, and version via WebGL. Each hardware + driver combination produces a unique signature that can identify your device without cookies.",
  audioContext: "Processed inaudible sound through your audio stack. Each device's audio hardware produces slightly different output, creating a unique signature that can identify your browser without cookies.",
  fonts: "Measured text rendering with hundreds of font variations. Your installed fonts create a unique combination that can identify your device without cookies.",
  mediaDevices: "Listed your cameras and microphones. The number and type of media devices create a signature that can identify your device without cookies.",
};

const TYPE_LABELS = {
  tracking_cookies: "Tracking Cookies Persisted",
  new_tracking_cookies: "New Tracking After Rejection",
  unexpected_cookies: "Unexpected New Cookies",
  fingerprinting: "Browser Fingerprinting",
  tracking_pixels: "Tracking Pixels After Rejection",
};

async function init() {
  // Get tabId from URL hash
  const tabId = parseInt(location.hash.replace("#", ""));
  if (!tabId) {
    $("header h1").textContent = "No tab specified. Open this from the extension popup.";
    return;
  }

  // Fetch the full debug report
  const report = await new Promise((resolve) => {
    chrome.runtime.sendMessage(
      { type: "POPUP_GET_DEBUG_REPORT", tabId },
      (r) => resolve(r)
    );
  });

  if (!report || !report.url) {
    $("header h1").textContent = "No audit data for this tab.";
    return;
  }

  renderReport(report);
}

function renderReport(report) {
  // Header
  $("#site-url").textContent = report.url;
  if (report.after.timestamp) {
    $("#audit-time").textContent = `Audit completed: ${new Date(report.after.timestamp).toLocaleString()}`;
  }

  // Score summary
  const scoreEl = $("#lie-score");
  scoreEl.textContent = report.lieScore ?? "—";
  scoreEl.style.color = getColor(report.lieScore);

  const breakdown = $("#score-breakdown");

  // Consent violation signals (contribute to lie score)
  const consentSignals = [
    { label: "Persisted Tracking", pts: countSignalPts(report.violations, "tracking_cookies") },
    { label: "New Tracking", pts: countSignalPts(report.violations, "new_tracking_cookies") },
    { label: "Unexpected Cookies", pts: countSignalPts(report.violations, "unexpected_cookies") },
    { label: "Tracking Pixels", pts: countSignalPts(report.violations, "tracking_pixels") },
  ];
  for (const s of consentSignals) {
    const chip = document.createElement("span");
    chip.className = `score-chip ${s.pts > 0 ? "active" : "zero"}`;
    chip.textContent = `${s.label}: ${s.pts} pts`;
    breakdown.appendChild(chip);
  }

  // Fingerprinting (separate — doesn't contribute to consent lie score)
  const fpViolation = (report.violations || []).find((v) => v.type === "fingerprinting");
  if (fpViolation) {
    const chip = document.createElement("span");
    chip.className = "score-chip active";
    chip.style.borderColor = "var(--orange)";
    chip.style.color = "var(--orange)";
    chip.textContent = `Fingerprinting: detected (not in consent score)`;
    breakdown.appendChild(chip);
  }

  // Violations — enriched with reasons from classified data
  if (report.violations && report.violations.length > 0) {
    const list = $("#violations-list");

    // Build lookup from classified cookies for quick access
    const cookieLookup = {};
    for (const c of (report.classifiedCookies || [])) {
      cookieLookup[c.name] = c;
    }

    for (const v of report.violations) {
      const item = document.createElement("div");
      item.className = `violation-item ${v.severity}`;

      let detailsHtml = "";

      if (v.type === "tracking_cookies" || v.type === "new_tracking_cookies" || v.type === "unexpected_cookies") {
        // Cookie violations — show each cookie with its reasons
        detailsHtml = (v.details || []).map((d) => {
          // Extract cookie name from detail string (format: "name (reason...)")
          const name = d.split(" (")[0].trim();
          const cookie = cookieLookup[name];
          if (cookie && cookie.reasons) {
            const chips = cookie.reasons.map((r) => {
              let cls = "";
              if (r.includes("tracking]")) cls = "tracking";
              else if (r.includes("consent]")) cls = "consent";
              else if (r.includes("functional]")) cls = "functional";
              return `<span class="v-reason-chip ${cls}">${esc(r)}</span>`;
            }).join("");
            return `<div class="v-detail-item">
              <span class="v-detail-name">${esc(name)}</span>
              <span class="badge badge-${cookie.classification}">${cookie.classification !== "unknown" ? cookie.classification : ""}</span>
              ${cookie.isNew ? '<span class="badge badge-new">NEW</span>' : ''}
              <div class="v-detail-reasons">${chips}</div>
            </div>`;
          }
          return `<div class="v-detail-item"><span class="v-detail-name">${esc(d)}</span></div>`;
        }).join("");

      } else if (v.type === "fingerprinting") {
        // Fingerprinting — show each method with description
        detailsHtml = (v.details || []).map((method) => {
          const desc = FP_DESCRIPTIONS[method] || "";
          return `<div class="v-detail-item">
            <span class="v-detail-name">${esc(method)}</span>
            <div class="v-detail-desc">${esc(desc)}</div>
          </div>`;
        }).join("");

      } else if (v.type === "tracking_pixels") {
        // Pixels — show tracker domain with category
        const baselineSrcs = new Set((report.allPixels?.baseline || []).map((p) => p.src));
        detailsHtml = (v.details || []).map((tracker) => {
          // Find the pixel in the after list for extra info
          const pixel = (report.allPixels?.after || []).find(
            (p) => p.tracker === tracker || p.src === tracker
          );
          const cats = pixel ? (pixel.categories || []).join(", ") : "";
          return `<div class="v-detail-item">
            <span class="v-detail-name">${esc(tracker)}</span>
            ${cats ? `<span class="v-detail-desc">${esc(cats)}</span>` : ""}
            <span class="badge badge-new">NEW</span>
          </div>`;
        }).join("");

      } else {
        // Fallback
        detailsHtml = `<div class="v-detail-plain">${v.details.map(esc).join("\n")}</div>`;
      }

      item.innerHTML = `
        <div class="v-header">
          <span class="v-type">${esc(TYPE_LABELS[v.type] || v.type)}</span>
          <span class="v-severity ${v.severity}">${v.severity}</span>
        </div>
        <p class="v-message">${esc(v.message)}</p>
        <div class="v-details-rich">${detailsHtml}</div>
      `;
      list.appendChild(item);
    }
  } else {
    $("#no-violations").classList.remove("hidden");
  }

  // Cookie table (after-rejection, classified)
  const afterCookies = report.classifiedCookies || [];
  if (afterCookies.length > 0) {
    const baselineCount = (report.baselineCookies || []).length;
    $("#cookie-counts").textContent =
      `${baselineCount} cookies before rejection | ${afterCookies.length} cookies after rejection | ` +
      `${afterCookies.filter((c) => c.classification === "tracking").length} tracking | ` +
      `${afterCookies.filter((c) => c.isNew).length} new`;

    const list = $("#cookie-list");
    for (const c of afterCookies) {
      const cls = c.classification;
      const expiryStr = c.expirationDate
        ? `${Math.round((c.expirationDate - Date.now() / 1000) / 86400)}d`
        : "Session";

      const totalScore = c.scores.tracking + c.scores.consent + c.scores.functional;
      const tPct = totalScore > 0 ? (c.scores.tracking / totalScore) * 100 : 0;
      const cPct = totalScore > 0 ? (c.scores.consent / totalScore) * 100 : 0;
      const fPct = totalScore > 0 ? (c.scores.functional / totalScore) * 100 : 0;

      const reasonChips = (c.reasons || []).map((r) => {
        // Extract category from "[+N category]" suffix
        let chipClass = "";
        if (r.includes("[") && r.includes("tracking]")) chipClass = "tracking";
        else if (r.includes("consent]")) chipClass = "consent";
        else if (r.includes("functional]")) chipClass = "functional";
        return `<span class="cc-reason-chip ${chipClass}">${esc(r)}</span>`;
      }).join("");

      const card = document.createElement("div");
      card.className = "cookie-card";
      card.innerHTML = `
        <div class="cookie-card-header">
          <span class="cc-name" title="${esc(c.name)}">${esc(c.name)}</span>
          <span class="cc-domain" title="${esc(c.domain || "")}">${esc(c.domain || "—")}</span>
          <div class="cc-meta">
            ${cls !== "unknown" ? `<span class="badge badge-${cls}">${cls}</span>` : ""}
            ${c.isNew ? '<span class="badge badge-new">NEW</span>' : ''}
            <span class="cc-expiry">${expiryStr}</span>
            <span class="cc-arrow">&#9654;</span>
          </div>
        </div>
        <div class="cookie-card-body">
          <div class="cc-reasons">${reasonChips}</div>
          <div class="cc-score-bar">
            <div class="bar-segment bar-tracking" style="width:${tPct}%"></div>
            <div class="bar-segment bar-consent" style="width:${cPct}%"></div>
            <div class="bar-segment bar-functional" style="width:${fPct}%"></div>
          </div>
          <div class="cc-score-labels">
            <span>Tracking: ${c.scores.tracking}</span>
            <span>Consent: ${c.scores.consent}</span>
            <span>Functional: ${c.scores.functional}</span>
            <span>Confidence: ${Math.round(c.confidence * 100)}%</span>
          </div>
          <div class="cc-attrs" style="margin-top:8px">
            <span><span class="attr-label">HttpOnly:</span> <span class="attr-value">${c.httpOnly ? "Yes" : "No"}</span></span>
            <span><span class="attr-label">Secure:</span> <span class="attr-value">${c.secure ? "Yes" : "No"}</span></span>
            <span><span class="attr-label">SameSite:</span> <span class="attr-value">${esc(c.sameSite || "—")}</span></span>
            <span><span class="attr-label">Expiry:</span> <span class="attr-value">${expiryStr}</span></span>
          </div>
        </div>
      `;

      // Toggle expand/collapse
      card.querySelector(".cookie-card-header").addEventListener("click", () => {
        card.classList.toggle("open");
      });

      list.appendChild(card);
    }
  } else {
    $("#no-cookies").classList.remove("hidden");
  }

  // Baseline cookies table
  const baselineCookies = report.baselineCookies || [];
  if (baselineCookies.length > 0) {
    const tbody = $("#baseline-tbody");
    for (const c of baselineCookies) {
      const tr = document.createElement("tr");
      tr.innerHTML = `
        <td>${esc(c.name)}</td>
        <td>${esc(c.domain || "—")}</td>
        <td>${c.isTracking ? '<span class="badge badge-tracking">Yes</span>' : "No"}</td>
        <td>${c.httpOnly ? "Yes" : "No"}</td>
        <td>${c.secure ? "Yes" : "No"}</td>
        <td>${esc(c.sameSite || "—")}</td>
      `;
      tbody.appendChild(tr);
    }
  } else {
    $("#no-baseline").classList.remove("hidden");
  }

  // Tracking pixels table
  const allPixels = report.allPixels || {};
  const baselinePixels = allPixels.baseline || [];
  const afterPixels = allPixels.after || [];
  const baselineSrcs = new Set(baselinePixels.map((p) => p.src));
  const baselineTrackers = new Set(baselinePixels.map((p) => p.tracker));

  if (afterPixels.length > 0 || baselinePixels.length > 0) {
    const tbody = $("#pixel-tbody");

    // Show after pixels, mark new vs baseline
    for (const p of afterPixels) {
      const isNew = !baselineSrcs.has(p.src) && !baselineTrackers.has(p.tracker);
      const tr = document.createElement("tr");
      tr.innerHTML = `
        <td>${isNew ? '<span class="badge badge-new">NEW</span>' : '<span class="badge badge-baseline">baseline</span>'}</td>
        <td>${esc(p.tracker || "—")}</td>
        <td>${(p.categories || []).join(", ")}</td>
        <td style="word-break:break-all;max-width:400px;font-size:11px;">${esc(p.src || "—")}</td>
        <td>${esc(p.type || "img")}</td>
      `;
      tbody.appendChild(tr);
    }

    // Show baseline-only pixels that disappeared
    for (const p of baselinePixels) {
      const stillPresent = afterPixels.some(
        (ap) => ap.src === p.src || ap.tracker === p.tracker
      );
      if (!stillPresent) {
        const tr = document.createElement("tr");
        tr.innerHTML = `
          <td><span class="badge badge-consent" style="background:rgba(34,197,94,0.15)">Removed</span></td>
          <td>${esc(p.tracker || "—")}</td>
          <td>${(p.categories || []).join(", ")}</td>
          <td style="word-break:break-all;max-width:400px;font-size:11px;">${esc(p.src || "—")}</td>
          <td>${esc(p.type || "img")}</td>
        `;
        tbody.appendChild(tr);
      }
    }
  } else {
    $("#no-pixels").classList.remove("hidden");
  }

  // Fingerprinting details
  const fp = report.fingerprinting || {};
  const fpMethods = Object.entries(fp).filter(([, v]) => v > 0);
  if (fpMethods.length > 0) {
    const container = $("#fingerprint-details");
    for (const [method, count] of fpMethods) {
      const div = document.createElement("div");
      div.className = "fp-method";
      div.innerHTML = `
        <span class="fp-name">${esc(method)}</span>
        <span class="fp-count">${count} ${count === 1 ? "call" : "calls"}</span>
        <span class="fp-desc">${esc(FP_DESCRIPTIONS[method] || "")}</span>
      `;
      container.appendChild(div);
    }
  } else {
    $("#no-fingerprinting").classList.remove("hidden");
  }

  // Banner info
  const bannerDiv = $("#banner-details");
  if (report.bannerInfo) {
    const b = report.bannerInfo;
    bannerDiv.innerHTML = `
      <p><strong>CMP:</strong> ${esc(b.cmp || "Unknown")}</p>
      <p><strong>Detection method:</strong> ${esc(b.detectionMethod || b.selector || "—")}</p>
      <p><strong>Reject button found:</strong> ${b.hasRejectButton ? "Yes" : "No"}${b.rejectButtonText ? ` ("${esc(b.rejectButtonText)}")` : ""}</p>
      <p><strong>Consent action:</strong> ${esc(report.consentAction || "unknown")}</p>
    `;
  } else {
    bannerDiv.innerHTML = '<p class="muted">No cookie banner detected.</p>';
  }

  // Raw state toggle
  $("#raw-toggle").addEventListener("click", () => {
    const raw = $("#raw-state");
    raw.classList.toggle("hidden");
    $("#raw-toggle").textContent = raw.classList.contains("hidden")
      ? "Show Raw Data" : "Hide Raw Data";
  });
  $("#raw-state").textContent = JSON.stringify(report, null, 2);
}

// Helpers
function countSignalPts(violations, type) {
  if (!violations) return 0;
  const v = violations.find((v) => v.type === type);
  if (!v) return 0;
  // Recalculate from count
  const perItem = { tracking_cookies: 7, new_tracking_cookies: 10, unexpected_cookies: 5, tracking_pixels: 5 };
  const max = { tracking_cookies: 35, new_tracking_cookies: 25, unexpected_cookies: 15, tracking_pixels: 20 };
  return Math.min(max[type] || 20, v.count * (perItem[type] || 5));
}

function getColor(score) {
  if (score === 0 || score === null) return "#22c55e";
  if (score <= 20) return "#f59e0b";
  if (score <= 50) return "#f97316";
  return "#ef4444";
}

function esc(str) {
  const div = document.createElement("div");
  div.textContent = String(str || "");
  return div.innerHTML;
}

init();
