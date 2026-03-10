// ─── PhishGuard Content Script ───────────────────────────────────────────────

(function () {
  "use strict";

  // API calls are routed through the background service worker
  // (content scripts cannot make cross-origin XHR in MV3)

  let tooltip = null;
  let hoverTimer = null;
  let dangerousCount = 0;
  const checkedLinks = new Map();

  // ─── Create Tooltip Element ────────────────────────────────────────────────
  function createTooltip() {
    const el = document.createElement("div");
    el.id = "phishguard-tooltip";
    el.innerHTML = `
      <div class="pg-tooltip-inner">
        <div class="pg-tooltip-header">
          <span class="pg-shield-icon">🛡️</span>
          <span class="pg-tooltip-title">PhishGuard</span>
          <span class="pg-status-dot"></span>
        </div>
        <div class="pg-tooltip-body">
          <div class="pg-status-label"></div>
          <div class="pg-reason"></div>
          <div class="pg-url-preview"></div>
        </div>
        <div class="pg-tooltip-footer">
          <span class="pg-powered">Powered by PhishGuard Sandbox</span>
        </div>
      </div>
    `;
    document.body.appendChild(el);
    return el;
  }

  function getTooltip() {
    if (!tooltip || !document.contains(tooltip)) {
      tooltip = createTooltip();
    }
    return tooltip;
  }

  function showTooltip(x, y, state, data) {
    const tip = getTooltip();
    const dot = tip.querySelector(".pg-status-dot");
    const label = tip.querySelector(".pg-status-label");
    const reason = tip.querySelector(".pg-reason");
    const urlPrev = tip.querySelector(".pg-url-preview");

    tip.className = "pg-state-" + state;

    const configs = {
      loading:   { dot: "⏳", text: "Checking...", color: "#f59e0b" },
      safe:      { dot: "✅", text: "Safe",        color: "#10b981" },
      dangerous: { dot: "🚨", text: "DANGEROUS",   color: "#ef4444" },
      error:     { dot: "⚠️", text: "Error",       color: "#6b7280" },
    };
    const cfg = configs[state] || configs.error;

    dot.textContent = cfg.dot;
    label.textContent = cfg.text;
    label.style.color = cfg.color;

    reason.textContent = data?.reason || "";
    reason.style.display = data?.reason ? "block" : "none";

    if (data?.url) {
      const short = data.url.length > 55 ? data.url.slice(0, 55) + "…" : data.url;
      urlPrev.textContent = short;
      urlPrev.style.display = "block";
    } else {
      urlPrev.style.display = "none";
    }

    const tipW = 280;
    const tipH = 100;
    let left = x + 14;
    let top = y - 10;
    if (left + tipW > window.innerWidth) left = x - tipW - 10;
    if (top + tipH > window.innerHeight) top = y - tipH - 10;

    tip.style.left = left + "px";
    tip.style.top = top + "px";
    tip.style.opacity = "1";
    tip.style.transform = "translateY(0)";
    tip.style.pointerEvents = "none";
  }

  function hideTooltip() {
    if (tooltip) {
      tooltip.style.opacity = "0";
      tooltip.style.transform = "translateY(4px)";
    }
  }

  // ─── Check URL via background service worker ──────────────────────────────
  function checkUrlViaBackground(url, onResult, onError) {
    try {
      chrome.runtime.sendMessage({ type: "CHECK_URL", url }, (response) => {
        if (chrome.runtime.lastError) {
          onError("Extension error: " + chrome.runtime.lastError.message);
          return;
        }
        if (!response) {
          onError("No response from background");
          return;
        }
        if (response.status === "error") {
          onError(response.reason || "Backend unreachable");
          return;
        }
        onResult(response);
      });
    } catch (e) {
      onError("Extension unavailable");
    }
  }

  // ─── Hover Logic ───────────────────────────────────────────────────────────
  document.addEventListener("mousemove", (e) => {
    const link = e.target.closest("a[href]");
    if (!link) {
      clearTimeout(hoverTimer);
      hideTooltip();
      return;
    }

    const url = link.href;
    if (!url.startsWith("http")) return;

    clearTimeout(hoverTimer);

    // Show cached result immediately
    if (checkedLinks.has(url)) {
      const result = checkedLinks.get(url);
      showTooltip(e.clientX, e.clientY, result.status, { url, reason: result.reason });
      return;
    }

    // Wait 150ms then check
    hoverTimer = setTimeout(() => {
      showTooltip(e.clientX, e.clientY, "loading", { url });

      checkUrlViaBackground(url,
        (result) => {
          checkedLinks.set(url, result);

          const hovered = document.querySelector(":hover");
          if (hovered && hovered.closest(`a[href="${CSS.escape(link.getAttribute("href"))}"]`)) {
            showTooltip(e.clientX, e.clientY, result.status, { url, reason: result.reason });
          }

          if (result.status === "dangerous") {
            markLinkDangerous(link);
            dangerousCount++;
            chrome.runtime.sendMessage({ type: "SET_BADGE", count: dangerousCount });
          }
        },
        (errMsg) => {
          showTooltip(e.clientX, e.clientY, "error", { url, reason: errMsg });
        }
      );

    }, 150);
  });

  // ─── Mark dangerous links visually ────────────────────────────────────────
  function markLinkDangerous(linkEl) {
    linkEl.classList.add("phishguard-dangerous");
    linkEl.setAttribute("data-phishguard", "dangerous");
  }

  function markLinkSafe(linkEl) {
    linkEl.classList.add("phishguard-safe");
  }

  // ─── Auto-scan visible links on page load ─────────────────────────────────
  function scanVisibleLinks() {
    const links = Array.from(document.querySelectorAll("a[href]"))
      .filter((a) => a.href.startsWith("http") && !checkedLinks.has(a.href))
      .slice(0, 30);

    links.forEach((link, i) => {
      setTimeout(() => {
        const url = link.href;
        checkUrlViaBackground(url,
          (result) => {
            checkedLinks.set(url, result);
            if (result.status === "dangerous") {
              markLinkDangerous(link);
              dangerousCount++;
              chrome.runtime.sendMessage({ type: "SET_BADGE", count: dangerousCount });
            }
          },
          () => {}
        );
      }, i * 200);
    });
  }

  if (document.readyState === "complete") {
    setTimeout(scanVisibleLinks, 1500);
  } else {
    window.addEventListener("load", () => setTimeout(scanVisibleLinks, 1500));
  }

  // ─── Message handler (from background.js) ─────────────────────────────────
  chrome.runtime.onMessage.addListener((msg, _, sendResponse) => {
    if (msg.type === "SHOW_CONTEXT_RESULT") {
      showContextResultBanner(msg.url, msg.result, msg.isQr);
    }
    if (msg.type === "PHISHGUARD_BLOCK_WARNING") {
      showBlockWarning(msg.url, msg.result);
    }
    // ── Deep analysis upgrade: regex said safe, AI says dangerous ──
    if (msg.type === "DEEP_CHECK_UPDATE") {
      const url = msg.url;
      const result = msg.result;
      checkedLinks.set(url, result);

      if (result.status === "dangerous") {
        // Mark all matching links on the page
        document.querySelectorAll(`a[href]`).forEach((link) => {
          if (link.href === url) {
            markLinkDangerous(link);
          }
        });
        dangerousCount++;
        chrome.runtime.sendMessage({ type: "SET_BADGE", count: dangerousCount });
        // Show a banner so user knows about the upgrade
        showContextResultBanner(url, result, false);
      }
    }
    if (msg.type === "GET_STATS") {
      const allLinks = document.querySelectorAll("a[href]");
      const qrImages = document.querySelectorAll("img[data-phishguard-qr]");
      let dangerous = 0, safe = 0;
      checkedLinks.forEach((r) => {
        if (r.status === "dangerous") dangerous++;
        else if (r.status === "safe") safe++;
      });
      sendResponse({
        dangerous,
        safe,
        total: allLinks.length,
        qr: qrImages.length,
      });
      return true;
    }
    if (msg.type === "RESCAN") {
      checkedLinks.clear();
      dangerousCount = 0;
      document.querySelectorAll(".phishguard-dangerous, .phishguard-safe").forEach((el) => {
        el.classList.remove("phishguard-dangerous", "phishguard-safe");
        el.removeAttribute("data-phishguard");
      });
      scanVisibleLinks();
    }
  });

  // ─── Context menu result banner ────────────────────────────────────────────
  function showContextResultBanner(url, result, isQr) {
    const existing = document.getElementById("phishguard-banner");
    if (existing) existing.remove();

    const banner = document.createElement("div");
    banner.id = "phishguard-banner";
    const isDangerous = result.status === "dangerous";

    banner.innerHTML = `
      <div class="pg-banner-inner">
        <span class="pg-banner-icon">${isDangerous ? "🚨" : result.status === "safe" ? "✅" : "⚠️"}</span>
        <div class="pg-banner-text">
          <strong>${isQr ? "QR Code" : "Link"} ${isDangerous ? "DANGEROUS" : result.status === "safe" ? "Safe" : "Unknown"}</strong>
          <span>${url.slice(0, 60)}${url.length > 60 ? "…" : ""}</span>
          ${result.reason ? `<em>${result.reason}</em>` : ""}
        </div>
        <button class="pg-banner-close">✕</button>
      </div>
    `;

    banner.className = isDangerous ? "pg-banner-danger" : result.status === "safe" ? "pg-banner-safe" : "pg-banner-warn";
    document.body.appendChild(banner);

    banner.querySelector(".pg-banner-close").onclick = () => banner.remove();
    setTimeout(() => banner?.remove(), 8000);
  }

  // ─── Block warning overlay ─────────────────────────────────────────────────
  function showBlockWarning(url, result) {
    const overlay = document.createElement("div");
    overlay.id = "phishguard-block-overlay";
    overlay.innerHTML = `
      <div class="pg-block-modal">
        <div class="pg-block-shield">🛡️</div>
        <h2>PhishGuard Alert</h2>
        <p class="pg-block-subtitle">This site has been flagged as <strong>dangerous</strong></p>
        <div class="pg-block-url">${url.slice(0, 80)}${url.length > 80 ? "…" : ""}</div>
        ${result.reason ? `<div class="pg-block-reason">${result.reason}</div>` : ""}
        <div class="pg-block-actions">
          <button id="pg-go-back" class="pg-btn-safe">← Go Back</button>
          <button id="pg-dismiss" class="pg-btn-dismiss">Dismiss Warning</button>
        </div>
      </div>
    `;

    document.body.prepend(overlay);
    document.getElementById("pg-go-back").onclick = () => history.back();
    document.getElementById("pg-dismiss").onclick = () => overlay.remove();
  }

})();