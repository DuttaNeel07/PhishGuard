"""
sandbox_ws_server.py
--------------------
Standalone WebSocket server that runs INSIDE the Docker container.
Accepts WebSocket connections, launches Playwright, streams CDP screencast
frames, and forwards input events.

Run with:  uvicorn sandbox_ws_server:app --host 0.0.0.0 --port 9222
"""

import asyncio
import json
import time
from urllib.parse import unquote

from fastapi import FastAPI, WebSocket, WebSocketDisconnect

app = FastAPI(title="PhishGuard Sandbox")

MAX_CONCURRENT = 3
TIMEOUT = 120
VIEWPORT_W, VIEWPORT_H = 1280, 800
JPEG_QUALITY = 60

_sessions = 0
_lock = asyncio.Lock()


@app.websocket("/ws")
async def live_session(ws: WebSocket, url: str = ""):
    global _sessions

    await ws.accept()

    url = unquote(url).strip()
    if not url:
        await ws.send_json({"type": "error", "message": "No URL provided"})
        await ws.close()
        return

    if not url.startswith("http"):
        url = "https://" + url

    async with _lock:
        if _sessions >= MAX_CONCURRENT:
            await ws.send_json({"type": "error", "message": "Max sessions reached"})
            await ws.close()
            return
        _sessions += 1

    browser = None
    pw = None
    try:
        await ws.send_json({"type": "status", "status": "connecting"})

        from playwright.async_api import async_playwright

        pw = await async_playwright().start()
        browser = await pw.chromium.launch(
            headless=True,
            args=[
                "--disable-dev-shm-usage",
                "--disable-gpu",
                "--disable-extensions",
                "--disable-background-networking",
                "--disable-sync",
                "--no-first-run",
            ],
        )
        context = await browser.new_context(
            viewport={"width": VIEWPORT_W, "height": VIEWPORT_H},
            java_script_enabled=True,
            user_agent=(
                "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
                "AppleWebKit/537.36 (KHTML, like Gecko) "
                "Chrome/122.0.0.0 Safari/537.36"
            ),
        )
        page = await context.new_page()

        try:
            await page.goto(url, timeout=30000, wait_until="domcontentloaded")
        except Exception as e:
            await ws.send_json({"type": "error", "message": f"Load failed: {e}"})
            await ws.close()
            return

        await ws.send_json({"type": "status", "status": "connected"})
        await ws.send_json({"type": "url", "url": page.url})
        await ws.send_json({"type": "title", "title": await page.title()})

        # CDP screencast
        cdp = await page.context.new_cdp_session(page)

        async def on_frame(params: dict):
            try:
                await ws.send_json({"type": "frame", "data": params["data"]})
                await cdp.send("Page.screencastFrameAck",
                               {"sessionId": params["sessionId"]})
            except Exception:
                pass

        cdp.on("Page.screencastFrame", on_frame)
        await cdp.send("Page.startScreencast", {
            "format": "jpeg",
            "quality": JPEG_QUALITY,
            "maxWidth": VIEWPORT_W,
            "maxHeight": VIEWPORT_H,
            "everyNthFrame": 1,
        })

        # Timeout watchdog
        start = time.time()

        async def watchdog():
            while True:
                await asyncio.sleep(5)
                if time.time() - start >= TIMEOUT:
                    try:
                        await ws.send_json({"type": "timeout",
                                            "message": "Session expired (2 min)"})
                        await ws.close()
                    except Exception:
                        pass
                    return

        wd = asyncio.create_task(watchdog())

        try:
            while True:
                raw = await ws.receive_text()
                msg = json.loads(raw)
                t = msg.get("type", "")

                if t == "click":
                    await page.mouse.click(msg.get("x", 0), msg.get("y", 0),
                                           button=msg.get("button", "left"))
                    await asyncio.sleep(0.3)
                    await ws.send_json({"type": "url", "url": page.url})
                    await ws.send_json({"type": "title", "title": await page.title()})
                elif t == "dblclick":
                    await page.mouse.dblclick(msg.get("x", 0), msg.get("y", 0))
                elif t == "scroll":
                    await page.mouse.move(msg.get("x", 0), msg.get("y", 0))
                    await page.mouse.wheel(msg.get("deltaX", 0), msg.get("deltaY", 0))
                elif t == "mousemove":
                    await page.mouse.move(msg.get("x", 0), msg.get("y", 0))
                elif t == "keypress":
                    if msg.get("key"):
                        await page.keyboard.press(msg["key"])
                elif t == "type":
                    if msg.get("text"):
                        await page.keyboard.type(msg["text"])
                elif t == "navigate":
                    new_url = msg.get("url", "")
                    if new_url:
                        if not new_url.startswith("http"):
                            new_url = "https://" + new_url
                        await page.goto(new_url, timeout=15000,
                                        wait_until="domcontentloaded")
                        await ws.send_json({"type": "url", "url": page.url})
                        await ws.send_json({"type": "title", "title": await page.title()})
                elif t == "back":
                    await page.go_back()
                    await asyncio.sleep(0.5)
                    await ws.send_json({"type": "url", "url": page.url})
                elif t == "forward":
                    await page.go_forward()
                    await asyncio.sleep(0.5)
                    await ws.send_json({"type": "url", "url": page.url})
                elif t == "refresh":
                    await page.reload()
                    await asyncio.sleep(0.5)
                    await ws.send_json({"type": "url", "url": page.url})

        except WebSocketDisconnect:
            pass
        finally:
            wd.cancel()

    except Exception as e:
        try:
            await ws.send_json({"type": "error", "message": str(e)})
            await ws.close()
        except Exception:
            pass
    finally:
        if browser:
            try:
                await browser.close()
            except Exception:
                pass
        if pw:
            try:
                await pw.stop()
            except Exception:
                pass
        async with _lock:
            _sessions -= 1


@app.get("/health")
async def health():
    return {"status": "ok", "sessions": _sessions}
