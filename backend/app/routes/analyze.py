import asyncio
import hashlib
import base64
import re
import tldextract
from urllib.parse import urlparse
from concurrent.futures import ThreadPoolExecutor

from fastapi import APIRouter, HTTPException

from app.models.schemas import (
    AnalyzeRequest, AnalyzeResponse, RiskLevel,
    MitmSummary, BlockedRequest, RedirectHop,
    URLRequest,
)

from app.services.domain_service import analyze_domain
from app.services.nlp_service import analyze_nlp
from app.services.sandbox_service import analyze_visual
from app.services.llm_service import generate_verdict, generate_scam_arc, generate_annotations
from app.services.redirect_service import analyze_chain
from app.database import (
    get_cached_result,
    set_cached_result,
    add_to_threat_feed,
    get_threat_feed,
)

from selenium import webdriver
from selenium.webdriver.chrome.service import Service
from selenium.webdriver.chrome.options import Options
from webdriver_manager.chrome import ChromeDriverManager

router = APIRouter()


def score_to_risk(score: int) -> RiskLevel:
    if score >= 70:
        return RiskLevel.DANGEROUS
    elif score >= 40:
        return RiskLevel.SUSPICIOUS
    return RiskLevel.SAFE


def _build_mitm_summary(raw_data: dict) -> MitmSummary | None:
    """
    Extract MITM proxy traffic summary from sandbox results.
    """

    mitm = raw_data.get("mitm")
    if not mitm:
        return None

    tlog = mitm.get("traffic_log", [])
    page_domain = urlparse(raw_data.get("final_url", "")).netloc

    external_post_domains = list({
        e["host"] for e in tlog
        if e.get("method") == "POST"
        and e.get("host")
        and e["host"] != page_domain
    })

    blocked = [
        BlockedRequest(**b)
        for b in mitm.get("blocked_requests", [])
        if all(k in b for k in ["timestamp", "url", "host", "method", "reason"])
    ]

    return MitmSummary(
        terminated_early=mitm.get("terminated_early", False),
        termination_reason=mitm.get("termination_reason", ""),
        blocked_requests=blocked,
        total_requests_captured=len(tlog),
        external_post_domains=external_post_domains,
    )


@router.post("/", response_model=AnalyzeResponse)
async def analyze(req: AnalyzeRequest):

    # 1. Cache
    cache_key = hashlib.md5(req.url.encode()).hexdigest()
    cached = await get_cached_result(cache_key)

    if cached:
        cached["cached"] = True
        return AnalyzeResponse(**cached)

    # 2. Run background tasks in parallel (including redirect tracing)
    try:
        domain_result, nlp_result, visual_result, redirect_data = await asyncio.gather(
            analyze_domain(req.url),
            analyze_nlp(req.message or ""),
            analyze_visual(req.url),
            analyze_chain(req.url),
        )
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Analysis failed: {str(e)}")

    # 2a. Enrich redirect chain with sandbox-detected JS redirects
    #     httpx can only see HTTP 301/302 redirects. Playwright (sandbox) follows
    #     JS-based redirects too. If they end up on different URLs, add the
    #     browser-observed hop to the chain.
    sandbox_final = visual_result.raw_data.get("final_url", "")
    if redirect_data and sandbox_final:
        chain_final = redirect_data.final_url
        # Normalize for comparison (strip trailing slash, protocol)
        def _norm(u: str) -> str:
            return u.rstrip("/").replace("https://", "").replace("http://", "").replace("www.", "")
        if _norm(sandbox_final) != _norm(chain_final) and _norm(sandbox_final) != _norm(req.url):
            redirect_data.chain.append(RedirectHop(
                step=len(redirect_data.chain) + 1,
                url=sandbox_final,
                status=200,
                time_ms=0,
                flags=["JS Redirect (detected by sandbox)"],
            ))
            redirect_data.final_url = sandbox_final
            redirect_data.total_redirects += 1
            if "JS Redirect" not in redirect_data.risk_level:
                redirect_data.risk_level = "Medium"

    # 2b. Short-circuit for known-safe domains
    #     When the domain service identifies the URL as a known legitimate
    #     brand, we return immediately with score=0 and include the sandbox
    #     screenshots for transparency, but skip expensive LLM calls.
    if "Known legitimate domain" in domain_result.flags:
        safe_response = AnalyzeResponse(
            score=0,
            risk_level=RiskLevel.SAFE,
            verdict_en="This is a verified, legitimate website.",
            verdict_hi="यह एक सत्यापित, वैध वेबसाइट है।",
            tactics=[],
            domain_signals=domain_result.raw_data,
            nlp_signals=nlp_result.raw_data,
            visual_signals=visual_result.raw_data,
            screenshot_b64=visual_result.raw_data.get("screenshot_b64"),
            annotations=None,
            scam_arc=None,
            mitm_summary=None,
            redirect_chain=redirect_data,
        )
        await set_cached_result(cache_key, safe_response.dict())
        return safe_response

    # 3. Composite score
    raw_score = domain_result.score + nlp_result.score + visual_result.score
    composite_score = min(raw_score, 100)

    # 4. LLM verdict + scam arc
    verdict_data, scam_arc = await asyncio.gather(
        generate_verdict(req, domain_result, nlp_result, visual_result),
        generate_scam_arc(req.url, composite_score),
    )

    # 5. Screenshot annotations
    annotations = await generate_annotations(
        visual_result.raw_data.get("screenshot_b64")
    )

    # 6. MITM summary
    mitm_summary = _build_mitm_summary(visual_result.raw_data)

    # 7. Final score: use composite as ground truth, let LLM adjust ±10
    llm_score = verdict_data.get("score")
    if llm_score is not None:
        # Clamp the LLM score to within ±10 of the heuristic composite
        final_score = max(
            composite_score - 10,
            min(llm_score, composite_score + 10)
        )
    else:
        final_score = composite_score
    final_score = min(final_score, 100)

    if mitm_summary and mitm_summary.terminated_early:
        final_score = min(final_score + 20, 100)

    # 7. Build response
    response = AnalyzeResponse(
        score=final_score,
        risk_level=score_to_risk(final_score),
        verdict_en=verdict_data.get("verdict_en", "Analysis complete."),
        verdict_hi=verdict_data.get("verdict_hi", "विश्लेषण पूर्ण।"),
        tactics=verdict_data.get("tactics", []),
        domain_signals=domain_result.raw_data,
        nlp_signals=nlp_result.raw_data,
        visual_signals=visual_result.raw_data,
        screenshot_b64=visual_result.raw_data.get("screenshot_b64"),
        annotations=annotations,
        scam_arc=scam_arc,
        mitm_summary=mitm_summary,
        redirect_chain=redirect_data,
    )

    # 8. Add to threat feed if risky
    if final_score >= 40:
        extracted = tldextract.extract(req.url)
        domain = f"{extracted.domain}.{extracted.suffix}"

        await add_to_threat_feed(
            domain,
            final_score,
            verdict_data.get("tactics", [])
        )

    # 9. Cache
    await set_cached_result(cache_key, response.dict())

    return response


@router.get("/threat-feed")
async def threat_feed():
    feed = await get_threat_feed()
    return {"feed": feed, "count": len(feed)}


def _take_screenshot_sync(url: str) -> str | None:

    options = Options()
    options.add_argument("--headless")
    options.add_argument("--no-sandbox")
    options.add_argument("--disable-dev-shm-usage")
    options.add_argument("--window-size=1280,720")

    driver = webdriver.Chrome(
        service=Service(ChromeDriverManager().install()),
        options=options
    )

    try:
        driver.get(url)
        screenshot = driver.get_screenshot_as_png()
        return base64.b64encode(screenshot).decode("utf-8")

    finally:
        driver.quit()


@router.get("/screenshot")
async def take_screenshot(url: str):

    try:
        loop = asyncio.get_running_loop()

        with ThreadPoolExecutor() as pool:
            b64 = await loop.run_in_executor(
                pool,
                _take_screenshot_sync,
                url
            )

        return {"screenshot": f"data:image/png;base64,{b64}"}

    except Exception as e:
        return {"screenshot": None, "error": str(e)}



@router.post("/check-url")
async def check_url_for_extension(req: URLRequest):
    """
    Thin wrapper for the Chrome extension.
    Calls the main analyze() logic and returns extension-friendly shape.
    """
    # Reuse your existing analyze logic
    analyze_req = AnalyzeRequest(url=req.url, message=None)
    result = await analyze(analyze_req)

    return {
        "is_malicious": result.risk_level in (RiskLevel.DANGEROUS, RiskLevel.SUSPICIOUS),
        "reason": result.verdict_en,
        "score": round(result.score / 100, 2),   # normalize 0–100 → 0.0–1.0
        "categories": result.tactics,
    }

@router.post("/quick-check")
async def quick_check(req: URLRequest):
    """
    Fast check for extension hover — skips Selenium sandbox.
    Only runs domain + NLP analysis (responds in ~2-3 seconds).
    No Redis caching — always runs fresh analysis.
    """

    # Only run fast analyzers — NO sandbox/Selenium
    try:
        domain_result, nlp_result = await asyncio.gather(
            analyze_domain(req.url),
            analyze_nlp(""),
        )
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

    raw_score = domain_result.score + nlp_result.score
    composite_score = min(raw_score, 100)

    return {
        "is_malicious": composite_score >= 40,
        "reason": f"Domain + NLP signals. Score: {composite_score}/100. Flags: {', '.join(domain_result.flags[:3]) or 'none'}",
        "score": round(composite_score / 100, 2),
        "categories": domain_result.flags[:3],
        "cached": False,
    }


@router.post("/instant-check")
async def instant_check(req: URLRequest):
    """
    Zero external calls — pure regex/pattern matching.
    Responds in under 100ms always.
    """

    url = req.url.lower()
    domain = url.split("/")[2] if "//" in url else url.split("/")[0]

    # Known safe domains — instant return
    safe_domains = [
        "google.com", "gmail.com", "youtube.com", "facebook.com",
        "instagram.com", "twitter.com", "x.com", "linkedin.com",
        "github.com", "microsoft.com", "apple.com", "amazon.com",
        "wikipedia.org", "reddit.com", "netflix.com", "spotify.com",
        "whatsapp.com", "zoom.us", "slack.com", "discord.com",
        "stackoverflow.com", "medium.com", "notion.so", "figma.com",
        "dropbox.com", "adobe.com", "canva.com", "twitch.tv",
        "paypal.com", "stripe.com", "shopify.com", "ebay.com",
        "yahoo.com", "bing.com", "duckduckgo.com", "brave.com",
        "kucoin.com", "binance.com", "coinbase.com", "kraken.com",
    ]
    for safe in safe_domains:
        if domain.endswith(safe):
            return {
                "is_malicious": False,
                "reason": f"Trusted domain: {safe}",
                "score": 0.0,
                "categories": [],
            }

    # ── Suspicious TLDs (commonly abused for phishing) ──
    suspicious_tlds = (
        r"\.(xyz|top|click|loan|gq|tk|ml|ga|cf|pw|"
        r"sbs|buzz|icu|fun|monster|rest|surf|cam|"
        r"cfd|cyou|rio|uno|bid|trade|win|racing|"
        r"review|cricket|party|science|work|date|"
        r"download|stream|accountant|faith|gdn|"
        r"men|ren|kim|wang|ooo|vip|life|live|"
        r"club|site|online|store|tech|space|website)$"
    )

    # ── Brand names (used in phishing subdomains/paths) ──
    brand_pattern = (
        r"(paypal|amazon|google|apple|microsoft|bank|"
        r"secure|login|verify|account|update|confirm|"
        r"ebay|netflix|metamask|coinbase|binance|kucoin|"
        r"kraken|phantom|trustwallet|blockchain|crypto|"
        r"wallet|signin|password|recovery|support|helpdesk)"
    )

    flags = []

    # IP address as domain
    if re.search(r"\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}", domain):
        flags.append("ip_address_url")

    # Hyphens in domain (even 1 hyphen in main domain is suspicious)
    domain_parts = domain.split(".")
    main_domain = domain_parts[-2] if len(domain_parts) >= 2 else ""
    if "-" in main_domain:
        flags.append("hyphenated_domain")

    # Suspicious TLD
    if re.search(suspicious_tlds, domain):
        flags.append("suspicious_tld")

    # Brand name in subdomain or domain body
    if re.search(brand_pattern + r".*\.", domain):
        flags.append("brand_impersonation")
    elif re.search(brand_pattern, main_domain):
        flags.append("brand_in_domain")

    # Unusually long domain
    if len(domain) > 40:
        flags.append("unusually_long_domain")

    # Data URI
    if re.search(r"^data:", url):
        flags.append("data_uri")

    # URL shortener
    if re.search(r"(bit\.ly|tinyurl|t\.co|goo\.gl|ow\.ly|short\.io|is\.gd|v\.gd|rb\.gy)", domain):
        flags.append("url_shortener")

    # Numeric-heavy domain (e.g. 192x168x1.com-like patterns)
    domain_name = main_domain or domain
    digit_ratio = sum(c.isdigit() for c in domain_name) / max(len(domain_name), 1)
    if digit_ratio > 0.4 and len(domain_name) > 4:
        flags.append("numeric_heavy_domain")

    # Suspicious path keywords
    if re.search(r"/(login|signin|verify|secure|account|update|confirm|password|reset|auth)", url):
        flags.append("suspicious_path")

    score = min(len(flags) * 0.25, 1.0)
    is_malicious = len(flags) >= 1  # even one flag is suspicious

    return {
        "is_malicious": is_malicious,
        "reason": f"Flags: {', '.join(flags)}" if flags else "No suspicious patterns detected",
        "score": score,
        "categories": flags,
    }