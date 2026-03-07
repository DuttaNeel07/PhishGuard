import json
import httpx
from app.models.schemas import SignalResult, AnnotationBox, AnalyzeRequest
from app.config import settings

GROQ_API_URL = "https://api.groq.com/openai/v1/chat/completions"
MODEL = "llama-3.3-70b-versatile"

SYSTEM_PROMPT = """You are a senior cybersecurity analyst specializing in Indian digital fraud.
You analyze phishing attempts targeting Indian users — banking fraud, UPI scams, government impersonation, fake KYC notices.

OUTPUT FORMAT (strict JSON only — no markdown, no code fences, no extra text):
{"score": <integer 0-100>, "tactics": ["urgency_pressure", "authority_spoofing", "visual_clone", "credential_harvest", "prize_scam", "fear_legal", "brand_impersonation", "otp_theft"], "verdict_en": "<2-3 sentences plain English>", "verdict_hi": "<same in Hindi>"}

MANDATORY SCORING RULES (these override everything else):
- If typosquatting is detected (domain visually similar to a brand, e.g. 'rnicrosoft.com', 'paypa1.com', 'arnazon.com'), score MUST be >= 75
- If subdomain spoofing is detected (brand name in subdomain but real domain is different, e.g. 'google.com.evil.net'), score MUST be >= 80
- If domain was registered less than 7 days ago AND impersonates a brand, score MUST be >= 90
- If domain was registered less than 30 days ago AND impersonates a brand, score MUST be >= 80
- If a password/OTP/credential form is detected on the page, score MUST be >= 65
- If OTP sharing is explicitly requested, score MUST be >= 85
- If VirusTotal flagged the domain as malicious, score MUST be >= 80
- Never score a confirmed brand impersonation below 70
- Score 0-30 = safe, 31-69 = suspicious, 70-100 = dangerous

VERDICT RULES:
- Never repeat the URL in the verdict
- Be specific: say exactly which brand is being impersonated
- If domain age < 30 days, always mention it
- If OTP sharing requested, always mention it
- If typosquatting detected, explicitly call out which letters were swapped
- Output ONLY the JSON object. Nothing before it, nothing after it.

EXAMPLES:

Input: domain_age=2 days, impersonating=SBI, password_field=true, urgency=account blocked
Output: {"score": 95, "tactics": ["visual_clone", "credential_harvest", "urgency_pressure"], "verdict_en": "This page impersonates SBI net banking. The domain was registered 2 days ago and harvests login credentials. The account blocked message is a fear tactic to force immediate action.", "verdict_hi": "यह पेज SBI नेट बैंकिंग की नकल करता है। डोमेन 2 दिन पहले बना था और लॉगिन जानकारी चुराता है। खाता बंद होने का संदेश डर पैदा करने की चाल है।"}

Input: typosquat=rnicrosoft.com (rn looks like m), impersonating=Microsoft
Output: {"score": 82, "tactics": ["brand_impersonation", "visual_clone"], "verdict_en": "This domain impersonates Microsoft by replacing 'm' with 'rn' which appears identical in most fonts — a classic typosquatting attack. Users visiting this site may believe they are on a legitimate Microsoft page. Do not enter any credentials.", "verdict_hi": "यह डोमेन Microsoft की नकल करता है, जहाँ 'm' को 'rn' से बदला गया है जो अधिकांश फॉन्ट में एक जैसा दिखता है। यह एक क्लासिक टाइपोस्क्वाटिंग हमला है। कोई भी जानकारी दर्ज न करें।"}

Input: nlp_tactic=authority_claim, entity=RBI, fear_legal=true
Output: {"score": 78, "tactics": ["authority_spoofing", "fear_legal"], "verdict_en": "This message impersonates the Reserve Bank of India to threaten legal action. The RBI never contacts individuals via SMS about account suspensions. This is a social engineering attack.", "verdict_hi": "यह संदेश RBI की नकल करके कानूनी कार्रवाई की धमकी देता है। RBI कभी SMS से खाता निलंबन की सूचना नहीं देता। यह एक सोशल इंजीनियरिंग हमला है।"}"""


async def _call_groq(messages: list, max_tokens: int = 800, system: str = SYSTEM_PROMPT) -> str:
    headers = {
        "Authorization": f"Bearer {settings.GROQ_API_KEY}",
        "Content-Type": "application/json",
    }
    payload = {
        "model": MODEL,
        "max_tokens": max_tokens,
        "temperature": 0,
        "messages": [
            {"role": "system", "content": system},
            *messages
        ],
    }
    async with httpx.AsyncClient(timeout=30) as client:
        r = await client.post(GROQ_API_URL, headers=headers, json=payload)
        r.raise_for_status()
        return r.json()["choices"][0]["message"]["content"]


def _safe_parse_json(text: str) -> dict | None:
    clean = text.strip()
    clean = clean.replace("```json", "").replace("```", "").strip()
    start = clean.find("{")
    end = clean.rfind("}") + 1
    if start != -1 and end > start:
        clean = clean[start:end]
    try:
        return json.loads(clean)
    except json.JSONDecodeError:
        return None


def _enforce_minimum_score(parsed: dict, domain_raw: dict, domain_flags: list) -> dict:
    """Enforce mandatory minimum scores that the LLM must not go below."""
    score = parsed.get("score", 0)
    impersonating = domain_raw.get("impersonating")
    age = domain_raw.get("domain_age_days", 9999)
    flags_str = " ".join(domain_flags).lower()

    # Typosquatting
    if "typosquat" in flags_str or "impersonation (distance=" in flags_str:
        score = max(score, 75)

    # Subdomain spoofing
    if "subdomain spoofing" in flags_str:
        score = max(score, 80)

    # Brand impersonation with new domain
    if impersonating and impersonating != "none detected":
        score = max(score, 70)
        if age < 7:
            score = max(score, 90)
        elif age < 30:
            score = max(score, 80)

    # VirusTotal flagged
    if "virustotal" in flags_str:
        score = max(score, 80)

    parsed["score"] = min(score, 100)
    return parsed


async def generate_verdict(
    req: AnalyzeRequest,
    domain: SignalResult,
    nlp: SignalResult,
    visual: SignalResult,
) -> dict:
    composite_score = domain.score + nlp.score + visual.score

    user_content = f"""Analyze this URL for phishing and return the JSON verdict:

URL: {req.url}
Message text: {req.message or "(none)"}

DOMAIN SIGNALS (score {domain.score}/60):
Flags: {domain.flags}
Domain age: {domain.raw_data.get('domain_age_days', 'unknown')} days
Impersonating: {domain.raw_data.get('impersonating', 'none detected')}
Real domain: {domain.raw_data.get('real_domain', 'unknown')}
Subdomain: {domain.raw_data.get('subdomain', 'none')}

NLP SIGNALS (score {nlp.score}/35):
Flags: {nlp.flags}
Tactics found: {nlp.raw_data.get('tactics_found', [])}
OTP request: {nlp.raw_data.get('otp_request', False)}

VISUAL SIGNALS (score {visual.score}/30):
Flags: {visual.flags}
Password fields: {bool(visual.raw_data.get('dom_signals', {}))}
Page title: {visual.raw_data.get('page_title', 'N/A')}

Total raw score: {composite_score}/100

CRITICAL: Apply the MANDATORY SCORING RULES from your system prompt before returning the score.
Return only the JSON object."""

    try:
        text = await _call_groq([{"role": "user", "content": user_content}])
        print(f"[LLM] Raw response: {text}")
        parsed = _safe_parse_json(text)
        print(f"[LLM] Parsed: {parsed}")
        if parsed:
            # Apply hard minimum score enforcement as a safety net
            parsed = _enforce_minimum_score(parsed, domain.raw_data, domain.flags)
            print(f"[LLM] Final score after enforcement: {parsed['score']}")
            return parsed
    except Exception as e:
        import traceback
        print(f"[LLM] generate_verdict error: {e}")
        traceback.print_exc()

<<<<<<< HEAD
    raw_score = domain.score + nlp.score + visual.score
    capped_score = min(raw_score, 100)

    # Generate score-appropriate fallback verdicts
    if capped_score < 30:
        verdict_en = "No significant threats detected. This appears to be a legitimate website."
        verdict_hi = "कोई महत्वपूर्ण खतरा नहीं मिला। यह एक वैध वेबसाइट प्रतीत होती है।"
    elif capped_score < 70:
        flag_summary = " ".join(domain.flags[:2]).strip()
        verdict_en = f"Some risk signals found. {flag_summary}".strip()
        verdict_hi = "कुछ जोखिम संकेत मिले। सावधानी बरतें।"
    else:
        flag_summary = " ".join(domain.flags[:2]).strip()
        verdict_en = f"Multiple risk signals detected. {flag_summary}".strip()
        verdict_hi = "कई जोखिम संकेत मिले। इस लिंक से बचें।"

    return {
        "score": capped_score,
=======
    return {
        "score": min(composite_score, 100),
>>>>>>> 4f10eb3 (redirect chaining added)
        "tactics": list(set(nlp.raw_data.get("tactics_found", []))),
        "verdict_en": verdict_en,
        "verdict_hi": verdict_hi,
    }


async def generate_scam_arc(url: str, score: int) -> str:
    if score < 40:
        return ""

    prompt = f"""A victim in India received this suspicious link. Risk score: {score}/100.

Write exactly 4 sentences describing what would happen if they clicked, in second person:
1. What they see when the page loads
2. What they are asked to enter or do
3. How their money or data gets stolen
4. What the attacker does next

Be specific to Indian context (UPI, OTP, Aadhaar, bank names). No markdown, no bullet points, just 4 plain sentences."""

    try:
        text = await _call_groq(
            [{"role": "user", "content": prompt}],
            max_tokens=250,
            system="You are a cybersecurity educator explaining scam tactics to Indian users. Be specific and realistic."
        )
        return text.strip()
    except Exception:
        return ""


async def generate_annotations(screenshot_b64: str | None) -> list:
    if not screenshot_b64:
        return []
    return [
        AnnotationBox(
            element="credential_form",
            bbox=[0.1, 0.3, 0.8, 0.25],
            explanation="Login form detected — submitting here sends your credentials to the attacker"
        ),
        AnnotationBox(
            element="fake_logo",
            bbox=[0.35, 0.05, 0.3, 0.15],
            explanation="Brand logo copied from a legitimate site to appear trustworthy"
        ),
        AnnotationBox(
            element="urgency_text",
            bbox=[0.05, 0.2, 0.9, 0.08],
            explanation="Urgency message designed to panic you into acting without thinking"
        ),
    ]