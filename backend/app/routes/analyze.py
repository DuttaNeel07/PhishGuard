import asyncio
import hashlib
import base64
import tldextract
from urllib.parse import urlparse
from concurrent.futures import ThreadPoolExecutor

from fastapi import APIRouter, HTTPException

from app.models.schemas import (
    AnalyzeRequest, AnalyzeResponse, RiskLevel,
    MitmSummary, BlockedRequest,
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

from concurrent.futures import ThreadPoolExecutor
from playwright.async_api import async_playwright
import base64

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

    # 5. Final score: use composite as ground truth, let LLM adjust ±10
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
        loop = asyncio.get_event_loop()

        with ThreadPoolExecutor() as pool:
            b64 = await loop.run_in_executor(
                pool,
                _take_screenshot_sync,
                url
            )

        return {"screenshot": f"data:image/png;base64,{b64}"}

    except Exception as e:
        return {"screenshot": None, "error": str(e)}