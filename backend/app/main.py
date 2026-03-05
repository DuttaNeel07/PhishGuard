import asyncio
import sys
from fastapi import FastAPI
from app.routes.analyze import router as analyze_router
from app.routes.qr import router as qr_router

# Fix for Playwright on Windows
if sys.platform == "win32":
    asyncio.set_event_loop_policy(asyncio.WindowsProactorEventLoopPolicy())

app = FastAPI(title="PhishGuard API")

app.include_router(analyze_router)
app.include_router(qr_router)

@app.get("/")
async def root():
    return {"message": "PhishGuard API is running ✅"}