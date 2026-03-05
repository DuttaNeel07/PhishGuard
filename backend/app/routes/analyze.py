from fastapi import APIRouter
from app.services.sandbox_service import analyze_visual

router = APIRouter()

@router.post("/analyze")
async def analyze_url(data: dict):
    url = data.get("url")
    result = await analyze_visual(url)
    return {
        "url": url,
        "screenshot": result.get("screenshot"),
        "verdict": "pending"
    }