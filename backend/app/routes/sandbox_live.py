"""
sandbox_live.py
---------------
WebSocket endpoint for live, interactive sandbox browser sessions.
Uses Chrome DevTools Protocol (CDP) screencast to stream JPEG frames
and forwards mouse/keyboard input back to the Playwright browser.
"""

import asyncio
import json
import time
from urllib.parse import unquote

from fastapi import APIRouter, WebSocket, WebSocketDisconnect

router = APIRouter()

# ── Resource limits ──────────────────────────────────────────────────────
MAX_CONCURRENT_SESSIONS = 3
SESSION_TIMEOUT_SECONDS = 120
VIEWPORT_WIDTH = 1280
VIEWPORT_HEIGHT = 800
FRAME_QUALITY = 60  # JPEG quality (0-100)

_active_sessions = 0
_session_lock = asyncio.Lock()


@router.websocket("/live")
async def sandbox_live(ws: WebSocket, url: str = ""):
    """
    Live sandbox browser session over WebSocket.

    Query params:
        url  – The URL to load in the sandbox browser.

    Messages FROM client (JSON):
        {"type": "click",     "x": int, "y": int, "button": "left"|"right"}
        {"type": "dblclick",  "x": int, "y": int}
        {"type": "scroll",    "x": int, "y": int, "deltaX": int, "deltaY": int}
        {"type": "mousemove", "x": int, "y": int}
        {"type": "keypress",  "key": str}
        {"type": "type",      "text": str}
        {"type": "navigate",  "url": str}
        {"type": "back"}
        {"type": "forward"}
        {"type": "refresh"}

    Messages TO client (JSON):
        {"type": "frame",   "data": "<base64 JPEG>"}
        {"type": "url",     "url": str}
        {"type": "title",   "title": str}
        {"type": "status",  "status": "connecting"|"connected"|"closed"}
        {"type": "error",   "message": str}
        {"type": "timeout", "message": str}
    """
    global _active_sessions

    await ws.accept()

    url = unquote(url).strip()
    if not url:
        await ws.send_json({"type": "error", "message": "No URL provided"})
        await ws.close()
        return

    if not url.startswith("http"):
        url = "https://" + url

    # Check concurrency limit
    async with _session_lock:
        if _active_sessions >= MAX_CONCURRENT_SESSIONS:
            await ws.send_json({
                "type": "error",
                "message": f"Max {MAX_CONCURRENT_SESSIONS} live sessions. Try again later.",
            })
            await ws.close()
            return
        _active_sessions += 1

    browser = None
    try:
        await ws.send_json({"type": "status", "status": "connecting"})

        # Launch browser
        from playwright.async_api import async_playwright

        pw = await async_playwright().start()
        browser = await pw.chromium.launch(
            headless=True,
            args=[
                "--no-sandbox",
                "--disable-setuid-sandbox",
                "--disable-dev-shm-usage",
                "--disable-gpu",
            ],
        )
        context = await browser.new_context(
            viewport={"width": VIEWPORT_WIDTH, "height": VIEWPORT_HEIGHT},
            java_script_enabled=True,
            user_agent="Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36",
        )
        page = await context.new_page()

        # Navigate to URL
        try:
            await page.goto(url, timeout=30000, wait_until="domcontentloaded")
        except Exception as e:
            await ws.send_json({"type": "error", "message": f"Failed to load: {str(e)}"})
            await ws.close()
            return

        await ws.send_json({"type": "status", "status": "connected"})
        await ws.send_json({"type": "url", "url": page.url})
        await ws.send_json({"type": "title", "title": await page.title()})

        # ── CDP Screencast setup ─────────────────────────────────────
        cdp = await page.context.new_cdp_session(page)

        # Screencast frame callback → send to client
        async def on_screencast_frame(params: dict):
            try:
                await ws.send_json({
                    "type": "frame",
                    "data": params["data"],  # base64 JPEG
                })
                # Acknowledge frame so CDP sends the next one
                await cdp.send("Page.screencastFrameAck", {
                    "sessionId": params["sessionId"],
                })
            except Exception:
                pass

        cdp.on("Page.screencastFrame", on_screencast_frame)

        await cdp.send("Page.startScreencast", {
            "format": "jpeg",
            "quality": FRAME_QUALITY,
            "maxWidth": VIEWPORT_WIDTH,
            "maxHeight": VIEWPORT_HEIGHT,
            "everyNthFrame": 1,
        })

        # ── Session loop ─────────────────────────────────────────────
        start_time = time.time()

        async def check_timeout():
            while True:
                await asyncio.sleep(5)
                elapsed = time.time() - start_time
                if elapsed >= SESSION_TIMEOUT_SECONDS:
                    try:
                        await ws.send_json({
                            "type": "timeout",
                            "message": "Session expired (2 min limit)",
                        })
                        await ws.close()
                    except Exception:
                        pass
                    return

        timeout_task = asyncio.create_task(check_timeout())

        try:
            while True:
                raw = await ws.receive_text()
                msg = json.loads(raw)
                msg_type = msg.get("type", "")

                if msg_type == "click":
                    x, y = msg.get("x", 0), msg.get("y", 0)
                    button = msg.get("button", "left")
                    await page.mouse.click(x, y, button=button)
                    # After click, page might navigate
                    await asyncio.sleep(0.3)
                    await ws.send_json({"type": "url", "url": page.url})
                    await ws.send_json({"type": "title", "title": await page.title()})

                elif msg_type == "dblclick":
                    x, y = msg.get("x", 0), msg.get("y", 0)
                    await page.mouse.dblclick(x, y)

                elif msg_type == "scroll":
                    x, y = msg.get("x", 0), msg.get("y", 0)
                    dx, dy = msg.get("deltaX", 0), msg.get("deltaY", 0)
                    await page.mouse.move(x, y)
                    await page.mouse.wheel(dx, dy)

                elif msg_type == "mousemove":
                    await page.mouse.move(msg.get("x", 0), msg.get("y", 0))

                elif msg_type == "keypress":
                    key = msg.get("key", "")
                    if key:
                        await page.keyboard.press(key)

                elif msg_type == "type":
                    text = msg.get("text", "")
                    if text:
                        await page.keyboard.type(text)

                elif msg_type == "navigate":
                    new_url = msg.get("url", "")
                    if new_url:
                        if not new_url.startswith("http"):
                            new_url = "https://" + new_url
                        await page.goto(new_url, timeout=15000, wait_until="domcontentloaded")
                        await ws.send_json({"type": "url", "url": page.url})
                        await ws.send_json({"type": "title", "title": await page.title()})

                elif msg_type == "back":
                    await page.go_back()
                    await asyncio.sleep(0.5)
                    await ws.send_json({"type": "url", "url": page.url})

                elif msg_type == "forward":
                    await page.go_forward()
                    await asyncio.sleep(0.5)
                    await ws.send_json({"type": "url", "url": page.url})

                elif msg_type == "refresh":
                    await page.reload()
                    await asyncio.sleep(0.5)
                    await ws.send_json({"type": "url", "url": page.url})

        except WebSocketDisconnect:
            pass
        finally:
            timeout_task.cancel()

    except Exception as e:
        try:
            await ws.send_json({"type": "error", "message": str(e)})
            await ws.close()
        except Exception:
            pass

    finally:
        # Cleanup
        if browser:
            try:
                await browser.close()
            except Exception:
                pass
            try:
                await pw.stop()
            except Exception:
                pass

        async with _session_lock:
            _active_sessions -= 1
