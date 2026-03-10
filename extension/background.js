// ─── PhishGuard Background Service Worker ───────────────────────────────────

const DEFAULT_API_BASE = "http://localhost:8000";
let apiBase = DEFAULT_API_BASE;

// Load saved API base on startup
chrome.storage.local.get(["apiBase"], (res) => {
  if (res.apiBase) apiBase = res.apiBase;
});

chrome.storage.onChanged.addListener((changes) => {
  if (changes.apiBase) apiBase = changes.apiBase.newValue;
});

// ─── Cache: url → { status, reason, checkedAt, deep } ───────────────────────
const cache = new Map();
const CACHE_TTL_MS = 5 * 60 * 1000; // 5 minutes

function getCached(url) {
  const entry = cache.get(url);
  if (!entry) return null;
  if (Date.now() - entry.checkedAt > CACHE_TTL_MS) {
    cache.delete(url);
    return null;
  }
  return entry;
}

// ─── Helper: fetch with manual timeout ───────────────────────────────────────
async function fetchWithTimeout(url, options, timeoutMs) {
  const controller = new AbortController();
  const timeoutId = setTimeout(() => controller.abort(), timeoutMs);
  try {
    const response = await fetch(url, { ...options, signal: controller.signal });
    clearTimeout(timeoutId);
    return response;
  } catch (err) {
    clearTimeout(timeoutId);
    throw err;
  }
}

// ─── Stage 1: Instant regex check (<100ms) ───────────────────────────────────
async function instantCheck(url) {
  const response = await fetchWithTimeout(
    `${apiBase}/analyze/instant-check`,
    {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ url }),
    },
    5000
  );
  if (!response.ok) throw new Error(`HTTP ${response.status}`);
  return response.json();
}

// ─── Stage 2: Deep analysis — domain + NLP (2-3s) ───────────────────────────
async function deepCheck(url) {
  const response = await fetchWithTimeout(
    `${apiBase}/analyze/quick-check`,
    {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ url }),
    },
    10000
  );
  if (!response.ok) throw new Error(`HTTP ${response.status}`);
  return response.json();
}

// ─── Two-stage URL check ─────────────────────────────────────────────────────
// Stage 1: instant regex — returns result immediately
// Stage 2: if regex said "safe" and it's not a known trusted domain,
//          run deep analysis in background and upgrade cache if needed
async function checkUrl(url) {
  const cached = getCached(url);
  if (cached) return cached;

  try {
    // ── Stage 1: Instant check ──
    const instantData = await instantCheck(url);

    const result = {
      status: instantData.is_malicious ? "dangerous" : "safe",
      reason: instantData.reason || "",
      score: instantData.score ?? null,
      categories: instantData.categories || [],
      checkedAt: Date.now(),
      deep: false,
    };

    cache.set(url, result);

    // ── Stage 2: If instant says safe but NOT a trusted domain, run deep check ──
    const isTrusted = (instantData.reason || "").startsWith("Trusted domain");
    if (!instantData.is_malicious && !isTrusted) {
      // Fire-and-forget deep analysis — updates cache & notifies tabs
      runDeepCheck(url);
    }

    return result;
  } catch (err) {
    return {
      status: "error",
      reason: `Could not reach PhishGuard backend: ${err.message}`,
      checkedAt: Date.now(),
      deep: false,
    };
  }
}

// ─── Deep check runner (fire-and-forget, updates cache) ──────────────────────
async function runDeepCheck(url) {
  try {
    const deepData = await deepCheck(url);

    if (deepData.is_malicious) {
      // Deep analysis found something regex missed — upgrade to dangerous
      const upgraded = {
        status: "dangerous",
        reason: deepData.reason || "Flagged by deep analysis",
        score: deepData.score ?? null,
        categories: deepData.categories || [],
        checkedAt: Date.now(),
        deep: true,
      };
      cache.set(url, upgraded);

      // Notify ALL tabs that this URL is now dangerous
      chrome.tabs.query({}, (tabs) => {
        for (const tab of tabs) {
          chrome.tabs.sendMessage(tab.id, {
            type: "DEEP_CHECK_UPDATE",
            url,
            result: upgraded,
          }).catch(() => {});
        }
      });
    } else {
      // Deep analysis confirmed safe — mark as deep-verified
      const current = cache.get(url);
      if (current) {
        current.deep = true;
        current.reason = deepData.reason || current.reason;
        cache.set(url, current);
      }
    }
  } catch (err) {
    // Deep check failed silently — keep the instant result
  }
}

// ─── Core: Check QR image URL ────────────────────────────────────────────────
async function checkQr(imageUrl) {
  const cached = getCached("qr:" + imageUrl);
  if (cached) return cached;

  try {
    const response = await fetchWithTimeout(
      `${apiBase}/analyze/check-qr`,
      {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ image_url: imageUrl }),
      },
      30000
    );

    if (!response.ok) throw new Error(`HTTP ${response.status}`);
    const data = await response.json();

    const result = {
      status: data.is_malicious ? "dangerous" : data.decoded_url ? "safe" : "no-qr",
      reason: data.reason || data.message || "",
      decodedUrl: data.decoded_url || null,
      checkedAt: Date.now(),
    };

    cache.set("qr:" + imageUrl, result);
    return result;
  } catch (err) {
    return {
      status: "error",
      reason: `QR check failed: ${err.message}`,
      checkedAt: Date.now(),
    };
  }
}

// ─── Badge helpers ───────────────────────────────────────────────────────────
function setBadge(tabId, count) {
  if (count > 0) {
    chrome.action.setBadgeText({ text: String(count), tabId });
    chrome.action.setBadgeBackgroundColor({ color: "#ef4444", tabId });
  } else {
    chrome.action.setBadgeText({ text: "", tabId });
  }
}

// ─── Context Menu ────────────────────────────────────────────────────────────
chrome.runtime.onInstalled.addListener(() => {
  chrome.contextMenus.create({
    id: "phishguard-check-link",
    title: "Check link with PhishGuard",
    contexts: ["link"],
  });
  chrome.contextMenus.create({
    id: "phishguard-check-image",
    title: "Scan image for QR code",
    contexts: ["image"],
  });
});

chrome.contextMenus.onClicked.addListener((info, tab) => {
  if (info.menuItemId === "phishguard-check-link" && info.linkUrl) {
    checkUrl(info.linkUrl).then((result) => {
      chrome.tabs.sendMessage(tab.id, {
        type: "SHOW_CONTEXT_RESULT",
        url: info.linkUrl,
        result,
      });
    });
  }
  if (info.menuItemId === "phishguard-check-image" && info.srcUrl) {
    checkQr(info.srcUrl).then((result) => {
      chrome.tabs.sendMessage(tab.id, {
        type: "SHOW_CONTEXT_RESULT",
        url: info.srcUrl,
        result,
        isQr: true,
      });
    });
  }
});

// ─── Message handler from content.js / popup.js ──────────────────────────────
chrome.runtime.onMessage.addListener((msg, sender, sendResponse) => {
  if (msg.type === "CHECK_URL") {
    checkUrl(msg.url).then(sendResponse);
    return true;
  }
  if (msg.type === "CHECK_QR") {
    checkQr(msg.imageUrl).then(sendResponse);
    return true;
  }
  if (msg.type === "SET_BADGE") {
    setBadge(sender.tab?.id, msg.count);
    return false;
  }
  if (msg.type === "GET_API_BASE") {
    sendResponse({ apiBase });
    return false;
  }
});

// ─── Intercept navigation for dangerous-site warnings ────────────────────────
chrome.webNavigation.onBeforeNavigate.addListener((details) => {
  if (details.frameId !== 0) return;
  const url = details.url;
  if (!url.startsWith("http")) return;

  checkUrl(url).then((result) => {
    if (result.status === "dangerous") {
      chrome.tabs.sendMessage(details.tabId, {
        type: "PHISHGUARD_BLOCK_WARNING",
        url,
        result,
      }).catch(() => {});

      setBadge(details.tabId, 1);
    }
  });
});
