/**
 * Fingerprint Detector — runs in the page's MAIN world.
 *
 * Registered with "world": "MAIN" in manifest.json, so Chrome injects it
 * directly into the page's JS context. This bypasses CSP restrictions that
 * would block inline script injection via DOM manipulation.
 *
 * Communicates detections back to the content script via window.postMessage.
 */

(function () {
  "use strict";

  // Deduplicate reports — only report each method once per burst
  const reported = {};
  function report(type) {
    const now = Date.now();
    if (reported[type] && now - reported[type] < 1000) return;
    reported[type] = now;
    window.postMessage({ type: "CCLD_FINGERPRINT", method: type }, "*");
  }

  // --- Canvas fingerprinting ---
  try {
    const origToDataURL = HTMLCanvasElement.prototype.toDataURL;
    HTMLCanvasElement.prototype.toDataURL = function (...args) {
      if (this.width > 16 && this.height > 16) {
        report("canvas");
      }
      return origToDataURL.apply(this, args);
    };

    const origGetImageData = CanvasRenderingContext2D.prototype.getImageData;
    CanvasRenderingContext2D.prototype.getImageData = function (...args) {
      if (args[2] > 16 && args[3] > 16) {
        report("canvas");
      }
      return origGetImageData.apply(this, args);
    };
  } catch {}

  // --- WebGL fingerprinting ---
  try {
    const origGetParameter = WebGLRenderingContext.prototype.getParameter;
    WebGLRenderingContext.prototype.getParameter = function (param) {
      const fingerprintParams = [
        0x1f00, 0x1f01, 0x1f02, // VENDOR, RENDERER, VERSION
        0x8b8c, 0x8b8d,         // SHADING_LANGUAGE_VERSION
      ];
      if (fingerprintParams.includes(param)) {
        report("webgl");
      }
      return origGetParameter.apply(this, arguments);
    };

    // Also catch WebGL2
    if (typeof WebGL2RenderingContext !== "undefined") {
      const origGetParam2 = WebGL2RenderingContext.prototype.getParameter;
      WebGL2RenderingContext.prototype.getParameter = function (param) {
        const fingerprintParams = [0x1f00, 0x1f01, 0x1f02, 0x8b8c, 0x8b8d];
        if (fingerprintParams.includes(param)) {
          report("webgl");
        }
        return origGetParam2.apply(this, arguments);
      };
    }
  } catch {}

  // --- AudioContext fingerprinting ---
  try {
    const OrigAudioContext =
      window.AudioContext || window.webkitAudioContext;
    if (OrigAudioContext) {
      const origCreateOscillator =
        OrigAudioContext.prototype.createOscillator;
      OrigAudioContext.prototype.createOscillator = function () {
        report("audioContext");
        return origCreateOscillator.apply(this, arguments);
      };

      const origCreateDynamicsCompressor =
        OrigAudioContext.prototype.createDynamicsCompressor;
      if (origCreateDynamicsCompressor) {
        OrigAudioContext.prototype.createDynamicsCompressor = function () {
          report("audioContext");
          return origCreateDynamicsCompressor.apply(this, arguments);
        };
      }
    }
  } catch {}

  // --- Navigator.mediaDevices enumeration ---
  try {
    if (navigator.mediaDevices && navigator.mediaDevices.enumerateDevices) {
      const origEnumerate = navigator.mediaDevices.enumerateDevices;
      navigator.mediaDevices.enumerateDevices = function () {
        report("mediaDevices");
        return origEnumerate.apply(this, arguments);
      };
    }
  } catch {}

  // --- Font enumeration (via offsetWidth probing) ---
  try {
    let fontProbeCount = 0;
    const origOffsetWidth = Object.getOwnPropertyDescriptor(
      HTMLElement.prototype,
      "offsetWidth"
    );
    if (origOffsetWidth && origOffsetWidth.get) {
      Object.defineProperty(HTMLElement.prototype, "offsetWidth", {
        get: function () {
          // Detect rapid offsetWidth reads on spans with varying font-family
          // (common font enumeration pattern)
          if (
            this.tagName === "SPAN" &&
            this.style.fontFamily &&
            this.style.fontSize === "72px"
          ) {
            fontProbeCount++;
            if (fontProbeCount > 20) {
              report("fonts");
              fontProbeCount = 0; // Reset to avoid flooding
            }
          }
          return origOffsetWidth.get.call(this);
        },
      });
    }
  } catch {}
})();
