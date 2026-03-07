"""
sandbox_service.py
------------------
Docker mode  → thin HTTP client calling the isolated sandbox container.
Local dev    → runs Playwright directly in-process (SANDBOX_URL not set).
"""

import os
import asyncio
import base64
from urllib.parse import urlparse
from concurrent.futures import ThreadPoolExecutor

import httpx
from app.models.schemas import SignalResult

SANDBOX_URL = os.getenv("SANDBOX_URL", "")
SANDBOX_TIMEOUT = 120

SUSPICIOUS_DOM_SIGNALS = [
    "input[type='password']",
    "input[name*='otp']",
    "input[name*='pin']",
    "input[placeholder*='OTP']",
    "input[placeholder*='password']",
]

BRAND_KEYWORDS = {
    "paypal": "paypal.com", "apple": "apple.com", "google": "google.com",
    "microsoft": "microsoft.com", "amazon": "amazon.com", "netflix": "netflix.com",
    "facebook": "facebook.com", "instagram": "instagram.com",
    "whatsapp": "whatsapp.com", "bank": None,
}

URGENCY_WORDS = [
    "urgent", "verify", "suspended", "blocked", "expires", "warning",
    "immediately", "action required", "limited time", "account locked", "confirm now",
]


# ── Remote sandbox call (Docker mode) ─────────────────────────────────────

async def _call_remote_sandbox(url: str) -> dict:
    async with httpx.AsyncClient(timeout=SANDBOX_TIMEOUT) as client:
        resp = await client.post(f"{SANDBOX_URL}/run", json={"url": url})
        resp.raise_for_status()
        return resp.json()


# ── Local Playwright runner (dev mode) ────────────────────────────────────

def _run_playwright_local(url: str) -> dict:
    from playwright.sync_api import sync_playwright, TimeoutError as PlaywrightTimeout

    score = 0
    flags = []
    raw = {}
    original_url = url if url.startswith("http") else "https://" + url
    url = original_url

    try:
        with sync_playwright() as p:
            browser = p.chromium.launch(headless=True, args=[
                "--no-sandbox", "--disable-setuid-sandbox",
                "--disable-dev-shm-usage", "--disable-gpu",
            ])
            context = browser.new_context(
                viewport={"width": 1280, "height": 800},
                java_script_enabled=True,
                extra_http_headers={"DNT": "1"},
                user_agent="Mozilla/5.0 (compatible; PhishGuardBot/1.0)"
            )
            page = context.new_page()
            network_requests, console_errors = [], []

            page.on("request", lambda req: network_requests.append({
                "url": req.url, "method": req.method, "resource_type": req.resource_type
            }))
            page.on("console", lambda msg: console_errors.append(
                {"type": msg.type, "text": msg.text}
            ) if msg.type in ("error", "warning") else None)

            try:
                response = page.goto(url, timeout=60000, wait_until="networkidle")
                raw["http_status"] = response.status if response else None
            except PlaywrightTimeout:
                score += 10
                flags.append("Page timed out — suspicious")
                raw["timeout"] = True
                browser.close()
                return {"score": min(score, 25), "flags": flags, "confidence": 0.6, "raw": raw}

            # Wait for page to fully render (JS frameworks, lazy-loaded images, etc.)
            try:
                page.wait_for_timeout(8000)
            except Exception:
                pass

            final_url = page.url
            raw["final_url"] = final_url
            page_domain = urlparse(final_url).netloc

            if final_url != original_url:
                flags.append(f"Redirects to: {final_url}")
                if final_url.count("http") > 1:
                    score += 15
                    flags.append("Multiple redirect hops detected")

            suspicious_requests = [
                req for req in network_requests
                if urlparse(req["url"]).netloc not in ("", page_domain) and req["method"] == "POST"
            ]
            if suspicious_requests:
                score += 20
                flags.append("Page sends data to external server")
                raw["suspicious_network_requests"] = suspicious_requests
            raw["network_requests"] = network_requests[:100]

            # Take screenshot after full page load
            raw["screenshot_b64"] = base64.b64encode(
                page.screenshot(full_page=True, type="png")
            ).decode()

            dom_signals = {}
            for sel in SUSPICIOUS_DOM_SIGNALS:
                try:
                    c = page.locator(sel).count()
                    if c > 0:
                        dom_signals[sel] = c
                except Exception:
                    pass
            raw["dom_signals"] = dom_signals
            # NOTE: credential forms are only flagged as suspicious when
            # combined with other signals (see below after form analysis).

            forms = page.locator("form")
            suspicious_form_targets, form_actions = [], []
            for i in range(forms.count()):
                try:
                    action = forms.nth(i).get_attribute("action")
                    if action:
                        form_actions.append(action)
                        ad = urlparse(action).netloc
                        if ad and ad != page_domain:
                            suspicious_form_targets.append(action)
                    else:
                        score += 5
                        flags.append("Form without action attribute detected")
                except Exception:
                    pass
            if suspicious_form_targets:
                score += 20
                flags.append("Form submits data to external domain")
                raw["suspicious_form_targets"] = suspicious_form_targets
            raw["form_actions"] = form_actions

            # Context-aware credential form scoring:
            # Password/OTP fields are normal on legitimate login pages.
            # Only flag them when combined with OTHER suspicious signals.
            has_other_signals = bool(
                suspicious_form_targets
                or suspicious_requests
                or score >= 15   # already accumulated from redirects/timeout/etc.
            )
            if dom_signals and has_other_signals:
                score += 15
                flags.append(f"Credential form + suspicious context: {list(dom_signals.keys())}")
            elif dom_signals:
                # Just note it in raw data without adding score
                flags.append(f"Login form present (normal for sites with accounts)")

            title = page.title()
            raw["page_title"] = title
            if any(w in title.lower() for w in URGENCY_WORDS):
                score += 10
                flags.append(f"Urgency language in title: '{title}'")
            for brand, legit in BRAND_KEYWORDS.items():
                if brand in title.lower():
                    if legit is None:
                        score += 10
                        flags.append(f"Sensitive keyword '{brand}' in title")
                    elif legit not in page_domain:
                        score += 20
                        flags.append(f"Brand impersonation: '{brand}' but domain is '{page_domain}'")
                    break

            try:
                ic = page.locator("iframe").count()
                if ic > 2:
                    score += 5
                    flags.append(f"High iframe count: {ic}")
                    raw["iframe_count"] = ic
            except Exception:
                pass

            try:
                cookies = context.cookies()
                tracking = [c for c in cookies if c.get("domain", "") not in page_domain]
                raw["cookies_set"] = len(cookies)
                if tracking:
                    score += 5
                    flags.append(f"Third-party tracking cookies: {len(tracking)}")
                    raw["tracking_cookies"] = [c["name"] for c in tracking]
            except Exception:
                pass

            if console_errors:
                raw["console_errors"] = console_errors[:20]
                if sum(1 for e in console_errors if e["type"] == "error") > 5:
                    score += 5
                    flags.append("High JS error count — possible obfuscated kit")

            browser.close()

    except Exception as e:
        flags.append(f"Sandbox error: {str(e)}")
        raw["error"] = str(e)

    return {
        "score": score,
        "flags": flags,
        "confidence": 0.9 if raw.get("screenshot_b64") else 0.3,
        "raw": raw,
    }


# ── Public interface ───────────────────────────────────────────────────────

async def analyze_visual(url: str) -> SignalResult:
    if SANDBOX_URL:
        # Docker mode — isolated container
        try:
            result = await _call_remote_sandbox(url)
        except httpx.RequestError as e:
            result = {
                "score": 0,
                "flags": [f"Sandbox unreachable: {e}"],
                "confidence": 0.1,
                "raw": {},
            }
    else:
        # Local dev mode — in-process Playwright
        loop = asyncio.get_event_loop()
        with ThreadPoolExecutor() as pool:
            result = await loop.run_in_executor(pool, _run_playwright_local, url)

    return SignalResult(
        score=min(result["score"], 30),
        flags=result["flags"],
        confidence=result["confidence"],
        raw_data=result.get("raw", {}),
    )