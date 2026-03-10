// ─── PhishGuard Popup ────────────────────────────────────────────────────────

// ── Tabs ──────────────────────────────────────────────────────────────────────
document.querySelectorAll(".tab").forEach((tab) => {
  tab.addEventListener("click", () => {
    document.querySelectorAll(".tab").forEach((t) => t.classList.remove("active"));
    document.querySelectorAll(".tab-content").forEach((c) => c.classList.remove("active"));
    tab.classList.add("active");
    document.getElementById("tab-" + tab.dataset.tab).classList.add("active");

    if (tab.dataset.tab === "page") loadPageStats();
  });
});

// ── API Status check ──────────────────────────────────────────────────────────
async function checkApiStatus() {
  const dot = document.getElementById("statusDot");
  const text = document.getElementById("statusText");
  const urlEl = document.getElementById("statusUrl");

  const { apiBase } = await chrome.storage.local.get(["apiBase"]);
  const base = apiBase || "http://localhost:8000";
  urlEl.textContent = base;

  try {
    const res = await fetch(`${base}/health`, { signal: AbortSignal.timeout(3000) });
    if (res.ok) {
      dot.className = "status-dot online";
      text.textContent = "Backend online";
    } else {
      throw new Error();
    }
  } catch {
    dot.className = "status-dot offline";
    text.textContent = "Backend offline";
  }
}

checkApiStatus();

// ── URL Checker ───────────────────────────────────────────────────────────────
const urlInput = document.getElementById("urlInput");
const btnCheck = document.getElementById("btnCheck");
const resultCard = document.getElementById("resultCard");
const resultIcon = document.getElementById("resultIcon");
const resultStatus = document.getElementById("resultStatus");
const resultReason = document.getElementById("resultReason");
const resultMeta = document.getElementById("resultMeta");

// Pre-fill with current tab URL
chrome.tabs.query({ active: true, currentWindow: true }, ([tab]) => {
  if (tab?.url?.startsWith("http")) urlInput.value = tab.url;
});

btnCheck.addEventListener("click", async () => {
  const url = urlInput.value.trim();
  if (!url) return;

  btnCheck.disabled = true;
  btnCheck.innerHTML = '<span class="spinner"></span>Scanning…';
  resultCard.classList.remove("show", "safe", "danger", "error");

  chrome.runtime.sendMessage({ type: "CHECK_URL", url }, (result) => {
    btnCheck.disabled = false;
    btnCheck.textContent = "Scan URL";

    if (!result) {
      showResult("error", "⚠️", "Error", "Could not reach backend.", []);
      return;
    }

    const stateMap = {
      safe: { cls: "safe", icon: "✅", label: "Safe" },
      dangerous: { cls: "danger", icon: "🚨", label: "DANGEROUS" },
      error: { cls: "error", icon: "⚠️", label: "Error" },
    };
    const s = stateMap[result.status] || stateMap.error;

    const chips = [];
    if (result.score != null) chips.push(`Score: ${result.score}`);
    if (result.categories?.length) chips.push(...result.categories);

    showResult(s.cls, s.icon, s.label, result.reason, chips);
  });
});

function showResult(cls, icon, label, reason, chips) {
  resultCard.className = "result-card show " + cls;
  resultIcon.textContent = icon;
  resultStatus.textContent = label;
  resultReason.textContent = reason || "";
  resultMeta.innerHTML = chips.map((c) => `<span class="meta-chip">${c}</span>`).join("");
}

// ── Page Stats ────────────────────────────────────────────────────────────────
function loadPageStats() {
  chrome.tabs.query({ active: true, currentWindow: true }, ([tab]) => {
    if (!tab) return;
    chrome.tabs.sendMessage(tab.id, { type: "GET_STATS" }, (resp) => {
      if (chrome.runtime.lastError || !resp) {
        document.getElementById("statDanger").textContent = "?";
        document.getElementById("statSafe").textContent = "?";
        document.getElementById("statTotal").textContent = "?";
        document.getElementById("statQr").textContent = "?";
        return;
      }
      document.getElementById("statDanger").textContent = resp.dangerous ?? 0;
      document.getElementById("statSafe").textContent = resp.safe ?? 0;
      document.getElementById("statTotal").textContent = resp.total ?? 0;
      document.getElementById("statQr").textContent = resp.qr ?? 0;
    });
  });
}

document.getElementById("btnRescan").addEventListener("click", () => {
  chrome.tabs.query({ active: true, currentWindow: true }, ([tab]) => {
    if (!tab) return;
    chrome.tabs.sendMessage(tab.id, { type: "RESCAN" });
    setTimeout(loadPageStats, 3000);
  });
});

// ── Settings ──────────────────────────────────────────────────────────────────
const apiBaseInput = document.getElementById("apiBaseInput");
const btnSave = document.getElementById("btnSave");
const saveConfirm = document.getElementById("saveConfirm");

chrome.storage.local.get(["apiBase"], ({ apiBase }) => {
  apiBaseInput.value = apiBase || "http://localhost:8000";
});

btnSave.addEventListener("click", () => {
  const val = apiBaseInput.value.trim().replace(/\/$/, "");
  if (!val) return;
  chrome.storage.local.set({ apiBase: val }, () => {
    saveConfirm.style.display = "block";
    setTimeout(() => (saveConfirm.style.display = "none"), 2000);
    checkApiStatus();
  });
});
