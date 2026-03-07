import asyncio
import hashlib
import tldextract
from fastapi import APIRouter, HTTPException
from app.models.schemas import AnalyzeRequest, AnalyzeResponse, RiskLevel
from app.services.domain_service import analyze_domain
from app.services.nlp_service import analyze_nlp
from app.services.sandbox_service import analyze_visual
from app.services.llm_service import generate_verdict, generate_scam_arc, generate_annotations
<<<<<<< HEAD
from app.services.redirect_service import analyze_chain
from app.database import get_cached_result, set_cached_result
from playwright.async_api import async_playwright
=======
from app.database import get_cached_result, set_cached_result, add_to_threat_feed, get_threat_feed
from selenium import webdriver
from selenium.webdriver.chrome.service import Service
from selenium.webdriver.chrome.options import Options
from webdriver_manager.chrome import ChromeDriverManager
from concurrent.futures import ThreadPoolExecutor
>>>>>>> d7a9770 (threat intelligence dashboard)
import base64

router = APIRouter()

def score_to_risk(score: int) -> RiskLevel:
    if score >= 70:
        return RiskLevel.DANGEROUS
    elif score >= 40:
        return RiskLevel.SUSPICIOUS
    return RiskLevel.SAFE

@router.post("/", response_model=AnalyzeResponse)
async def analyze(req: AnalyzeRequest):

    # 1. Check cache first
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

    # 3. Composite score
    raw_score = domain_result.score + nlp_result.score + visual_result.score
    composite_score = min(raw_score, 100)

    # 4. LLM verdict + scam arc
    verdict_data, scam_arc = await asyncio.gather(
        generate_verdict(req, domain_result, nlp_result, visual_result),
        generate_scam_arc(req.url, composite_score),
    )

    # 5. Annotations from screenshot
    annotations = await generate_annotations(
        visual_result.raw_data.get("screenshot_b64")
    )

    # 6. Build response
    final_score = verdict_data.get("score", composite_score)
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
        redirect_chain=redirect_data,
    )

    # 7. Add to threat feed if high risk
    if final_score >= 40:
        extracted = tldextract.extract(req.url)
        domain = f"{extracted.domain}.{extracted.suffix}"
        await add_to_threat_feed(domain, final_score, verdict_data.get("tactics", []))

    # 8. Cache it
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
            b64 = await loop.run_in_executor(pool, _take_screenshot_sync, url)

        print(f"✅ Screenshot taken, size: {len(b64)} chars")
        return {"screenshot": f"data:image/png;base64,{b64}"}
    except Exception as e:
        print(f"❌ Screenshot error: {e}")
        return {"screenshot": None, "error": str(e)}