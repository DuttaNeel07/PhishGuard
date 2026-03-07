"""
sandbox_live.py
---------------
WebSocket endpoint for live, interactive sandbox browser sessions.

Two modes:
  Docker (production) → Proxies WebSocket to isolated Docker container
                         Set SANDBOX_LIVE_URL=ws://localhost:9222
  Local  (dev)        → Runs Playwright directly in-process
"""

import os
import asyncio
import json
import time
from urllib.parse import unquote

from fastapi import APIRouter, WebSocket, WebSocketDisconnect

router = APIRouter()

# ── Configuration ────────────────────────────────────────────────────────
# Set this env var to enable Docker-isolated mode:
#   SANDBOX_LIVE_URL=ws://localhost:9222
SANDBOX_LIVE_URL = os.getenv("SANDBOX_LIVE_URL", "")

MAX_CONCURRENT_SESSIONS = 3
SESSION_TIMEOUT_SECONDS = 120
VIEWPORT_WIDTH = 1280
VIEWPORT_HEIGHT = 800
FRAME_QUALITY = 60

_active_sessions = 0
_session_lock = asyncio.Lock()


# ── Docker proxy mode ──────────────────────────────────────────────────
async def _proxy_to_docker(ws: WebSocket, url: str):
    """
    Proxy WebSocket messages between the frontend client and the
    Docker sandbox container. The container runs the actual browser.
    """
    import websockets

    sandbox_ws_url = f"{SANDBOX_LIVE_URL}/ws?url={url}"

    try:
        async with websockets.connect(sandbox_ws_url) as sandbox_ws:

            async def forward_to_client():
                """Relay messages from sandbox container → frontend client."""
                try:
                    async for message in sandbox_ws:
                        await ws.send_text(message)
                except Exception:
                    pass

            async def forward_to_sandbox():
                """Relay messages from frontend client → sandbox container."""
                try:
                    while True:
                        data = await ws.receive_text()
                        await sandbox_ws.send(data)
                except WebSocketDisconnect:
                    pass
                except Exception:
                    pass

            # Run both directions concurrently
            done, pending = await asyncio.wait(
                [
                    asyncio.create_task(forward_to_client()),
                    asyncio.create_task(forward_to_sandbox()),
                ],
                return_when=asyncio.FIRST_COMPLETED,
            )
            for task in pending:
                task.cancel()

    except Exception as e:
        await ws.send_json({"type": "error", "message": f"Sandbox container error: {e}"})


# ── Local Playwright mode (dev fallback) ──────────────────────────────
async def _run_local(ws: WebSocket, url: str):
    """Run Playwright directly in-process (for development only)."""
    browser = None
    pw = None
    try:
        await ws.send_json({"type": "status", "status": "connecting"})

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

        try:
            await page.goto(url, timeout=30000, wait_until="domcontentloaded")
        except Exception as e:
            await ws.send_json({"type": "error", "message": f"Failed to load: {str(e)}"})
            return

        await ws.send_json({"type": "status", "status": "connected"})
        await ws.send_json({"type": "url", "url": page.url})
        await ws.send_json({"type": "title", "title": await page.title()})

        # CDP screencast
        cdp = await page.context.new_cdp_session(page)

        async def on_screencast_frame(params: dict):
            try:
                await ws.send_json({"type": "frame", "data": params["data"]})
                await cdp.send("Page.screencastFrameAck", {"sessionId": params["sessionId"]})
            except Exception:
                pass

        cdp.on("Page.screencastFrame", on_screencast_frame)
        await cdp.send("Page.startScreencast", {
            "format": "jpeg", "quality": FRAME_QUALITY,
            "maxWidth": VIEWPORT_WIDTH, "maxHeight": VIEWPORT_HEIGHT,
            "everyNthFrame": 1,
        })

        start_time = time.time()

        async def check_timeout():
            while True:
                await asyncio.sleep(5)
                if time.time() - start_time >= SESSION_TIMEOUT_SECONDS:
                    try:
                        await ws.send_json({"type": "timeout", "message": "Session expired (2 min limit)"})
                        await ws.close()
                    except Exception:
                        pass
                    return

        timeout_task = asyncio.create_task(check_timeout())

        try:
            while True:
                raw = await ws.receive_text()
                msg = json.loads(raw)
                t = msg.get("type", "")

                if t == "click":
                    await page.mouse.click(msg.get("x", 0), msg.get("y", 0), button=msg.get("button", "left"))
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
                        await page.goto(new_url, timeout=15000, wait_until="domcontentloaded")
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
            timeout_task.cancel()

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


# ── Main WebSocket endpoint ──────────────────────────────────────────
@router.websocket("/live")
async def sandbox_live(ws: WebSocket, url: str = ""):
    """
    Live sandbox browser session over WebSocket.

    Automatically uses Docker isolation when SANDBOX_LIVE_URL is set,
    otherwise falls back to local Playwright (dev mode).
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

    # Concurrency check
    async with _session_lock:
        if _active_sessions >= MAX_CONCURRENT_SESSIONS:
            await ws.send_json({
                "type": "error",
                "message": f"Max {MAX_CONCURRENT_SESSIONS} live sessions. Try again later.",
            })
            await ws.close()
            return
        _active_sessions += 1

    try:
        if SANDBOX_LIVE_URL:
            # Docker mode — fully isolated
            await _proxy_to_docker(ws, url)
        else:
            # Dev mode — local Playwright (less secure, but works without Docker)
            await _run_local(ws, url)
    except Exception as e:
        try:
            await ws.send_json({"type": "error", "message": str(e)})
            await ws.close()
        except Exception:
            pass
    finally:
        async with _session_lock:
            _active_sessions -= 1
