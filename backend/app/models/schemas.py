from pydantic import BaseModel
from typing import Optional, List
from enum import Enum

class RiskLevel(str, Enum):
    SAFE = "safe"
    SUSPICIOUS = "suspicious"
    DANGEROUS = "dangerous"

class AnalyzeRequest(BaseModel):
    url: str
    message: Optional[str] = None

class SignalResult(BaseModel):
    score: int
    flags: List[str]
    confidence: float
    raw_data: dict = {}

class AnnotationBox(BaseModel):
    element: str
    bbox: List[float]
    explanation: str

class AnalyzeResponse(BaseModel):
    score: int
    risk_level: RiskLevel
    verdict_en: str
    verdict_hi: str
    tactics: List[str]
    domain_signals: dict
    nlp_signals: dict
    visual_signals: dict
    screenshot_b64: Optional[str] = None
    annotations: Optional[List[AnnotationBox]] = None
    scam_arc: Optional[str] = None
    cached: bool = False

class ReportRequest(BaseModel):
    url: str
    user_city: Optional[str] = None
    notes: Optional[str] = None