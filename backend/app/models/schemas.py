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


# ── New: structured mitm proxy data returned in the response ──────────────

class BlockedRequest(BaseModel):
    timestamp: str
    url: str
    host: str
    method: str
    reason: str
    at_response: bool = False


class MitmSummary(BaseModel):
    terminated_early: bool = False
    termination_reason: str = ""
    blocked_requests: List[BlockedRequest] = []
    total_requests_captured: int = 0
    external_post_domains: List[str] = []

class RedirectHop(BaseModel):
    step: int
    url: str
    status: int
    time_ms: int
    flags: List[str]

class RedirectChainData(BaseModel):
    initial_url: str
    final_url: str
    total_redirects: int
    risk_level: str
    chain: List[RedirectHop]

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
    # mitmproxy summary — None when running in local dev (no proxy)
    mitm_summary: Optional[MitmSummary] = None
    redirect_chain: Optional[RedirectChainData] = None
    cached: bool = False


class ReportRequest(BaseModel):
    url: str
    user_city: Optional[str] = None
    notes: Optional[str] = None