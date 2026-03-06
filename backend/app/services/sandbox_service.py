import asyncio
import base64
from concurrent.futures import ThreadPoolExecutor
from playwright.sync_api import sync_playwright

def _take_screenshot(url: str) -> dict:
    with sync_playwright() as p:
        browser = p.chromium.launch()
        page = browser.new_page()
        page.goto(url, timeout=60000, wait_until="domcontentloaded")
        screenshot = page.screenshot()
        browser.close()
        return {
            "screenshot": base64.b64encode(screenshot).decode("utf-8"),
            "url": url
        }

async def analyze_visual(url: str) -> dict:
    loop = asyncio.get_event_loop()
    with ThreadPoolExecutor() as pool:
        result = await loop.run_in_executor(pool, _take_screenshot, url)
    return result