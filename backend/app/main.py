import asyncio
import sys
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from app.routes.analyze import router as analyze_router
from app.routes.qr import router as qr_router
from app.routes.sandbox_live import router as sandbox_router
from app.database import init_db

if sys.platform == "win32":
    asyncio.set_event_loop_policy(asyncio.WindowsProactorEventLoopPolicy())

app = FastAPI(title="PhishGuard API")

app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "http://localhost:5173",  
        "http://localhost:5000",
        "http://127.0.0.1:5173",
        "http://127.0.0.1:5000",
    ],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

@app.on_event("startup")
async def startup():
    await init_db()

app.include_router(analyze_router, prefix="/analyze")
app.include_router(qr_router, prefix="/analyze")
app.include_router(sandbox_router, prefix="/sandbox")

@app.get("/")
async def root():
    return {"message": "PhishGuard API is running ✅"}