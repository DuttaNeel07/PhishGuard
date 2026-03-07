import re
import whois
import httpx
import tldextract
import Levenshtein
from urllib.parse import urlparse
from datetime import datetime, timezone
from app.models.schemas import SignalResult
from app.config import settings

BRAND_DOMAINS = {
    "sbi.co.in": "SBI",
    "hdfcbank.com": "HDFC Bank",
    "icicibank.com": "ICICI Bank",
    "axisbank.com": "Axis Bank",
    "kotakbank.com": "Kotak Bank",
    "paytm.com": "Paytm",
    "phonepe.com": "PhonePe",
    "npci.org.in": "NPCI",
    "rbi.org.in": "RBI",
    "irctc.co.in": "IRCTC",
    "amazon.in": "Amazon",
    "amazon.com": "Amazon",
    "flipkart.com": "Flipkart",
    "uidai.gov.in": "UIDAI",
    "incometax.gov.in": "Income Tax",
    "epfindia.gov.in": "EPFO",
    "google.com": "Google",
    "paypal.com": "PayPal",
    "apple.com": "Apple",
    "microsoft.com": "Microsoft",
    "facebook.com": "Facebook",
    "instagram.com": "Instagram",
    "netflix.com": "Netflix",
    "linkedin.com": "LinkedIn",
}

# Set of all known-safe domains for fast exact-match lookup
SAFE_DOMAINS = set(BRAND_DOMAINS.keys())

# Map brand base keyword → set of all legitimate domains for that brand
# e.g. "amazon" → {"amazon.in", "amazon.com"}
BRAND_KEYWORD_TO_DOMAINS: dict[str, set[str]] = {}
for _domain, _name in BRAND_DOMAINS.items():
    _keyword = _domain.split(".")[0]
    BRAND_KEYWORD_TO_DOMAINS.setdefault(_keyword, set()).add(_domain)

# Reverse map: brand display name → set of all legitimate domains
# e.g. "Amazon" → {"amazon.in", "amazon.com"}
BRAND_NAME_TO_DOMAINS: dict[str, set[str]] = {}
for _domain, _name in BRAND_DOMAINS.items():
    BRAND_NAME_TO_DOMAINS.setdefault(_name, set()).add(_domain)

# Brand keywords extracted from above for quick lookup
BRAND_KEYWORDS = {domain.split(".")[0]: name for domain, name in BRAND_DOMAINS.items()}

# Minimum keyword length for subdomain/keyword spoofing checks.
# Set to 3 to catch important short brands (sbi, rbi) while
# _keyword_in_text's word-boundary matching prevents false positives.
MIN_KEYWORD_LEN = 3

SUSPICIOUS_TLDS = {
    ".xyz", ".top", ".click", ".loan", ".work",
    ".gq", ".ml", ".tk", ".cf", ".info", ".live",
}
# NOTE: .net was removed — it is a mainstream gTLD used by millions of legitimate sites


def _keyword_in_text(keyword: str, text: str) -> bool:
    """
    Check if `keyword` appears in `text` as a distinct word/segment,
    separated by word boundaries or common delimiters (-, .).
    Prevents 'pay' from matching 'payday' while still catching 'pay-pal-verify'.
    """
    pattern = r"(?:^|[\.\-_])" + re.escape(keyword) + r"(?:$|[\.\-_])"
    return bool(re.search(pattern, text))


async def analyze_domain(url: str) -> SignalResult:
    score = 0
    flags = []
    raw = {}

    try:
        parsed = urlparse(url if url.startswith("http") else f"http://{url}")
        full_host = parsed.netloc.lower().replace("www.", "")

        # Use tldextract to correctly identify real domain vs subdomain
        extracted = tldextract.extract(url)
        real_domain = f"{extracted.domain}.{extracted.suffix}"   # e.g. login-verify.net
        subdomain = extracted.subdomain                           # e.g. google.com
        tld = f".{extracted.suffix}"

        raw["domain"] = full_host
        raw["real_domain"] = real_domain
        raw["subdomain"] = subdomain

        # ── FIX 1: Early-exit for known-safe domains ──────────────────────
        if real_domain in SAFE_DOMAINS:
            return SignalResult(
                score=0,
                flags=["Known legitimate domain"],
                confidence=0.99,
                raw_data=raw,
            )

        # Track whether we already flagged brand impersonation to avoid
        # double-counting the same signal (Fix 7)
        impersonation_detected = False

        # 1. Subdomain spoofing — brand name in subdomain but real domain
        #    is different (Fix 6: require keyword len >= MIN_KEYWORD_LEN
        #    and use word-boundary matching)
        if not impersonation_detected:
            for brand_domain, brand_name in BRAND_DOMAINS.items():
                brand_keyword = brand_domain.split(".")[0]
                if len(brand_keyword) < MIN_KEYWORD_LEN:
                    continue
                if _keyword_in_text(brand_keyword, subdomain.lower()):
                    # Make sure the real domain isn't one of that brand's
                    # legitimate domains (Fix 2: multi-TLD check)
                    legit_domains = BRAND_KEYWORD_TO_DOMAINS.get(brand_keyword, set())
                    if real_domain not in legit_domains:
                        score += 50
                        flags.append(
                            f"Subdomain spoofing: '{brand_keyword}' in subdomain "
                            f"but real domain is '{real_domain}' — classic "
                            f"{brand_name} impersonation"
                        )
                        raw["impersonating"] = brand_name
                        impersonation_detected = True
                        break

        # 2. Domain age via WHOIS
        try:
            w = whois.whois(real_domain)
            creation = w.creation_date
            if isinstance(creation, list):
                creation = creation[0]
            if creation:
                if creation.tzinfo is None:
                    creation = creation.replace(tzinfo=timezone.utc)
                age_days = (datetime.now(timezone.utc) - creation).days
                raw["domain_age_days"] = age_days
                if age_days < 7:
                    score += 30
                    flags.append(f"Domain registered only {age_days} days ago")
                elif age_days < 30:
                    score += 20
                    flags.append(f"Very new domain ({age_days} days old)")
                elif age_days < 90:
                    score += 10
                    flags.append(f"Recent domain ({age_days} days old)")
            else:
                score += 5
                flags.append("Domain age unknown — WHOIS lookup returned no data")
        except Exception as e:
            score += 5
            flags.append("Domain age unknown — WHOIS lookup failed")
            raw["whois_error"] = str(e)

        # 3. Suspicious TLD (Fix 4: .net removed from the set)
        if tld in SUSPICIOUS_TLDS:
            score += 20
            flags.append(f"Suspicious TLD: {tld}")
        raw["tld"] = tld

        # 4. Typosquatting check against real domain
        #    Fix 3: skip if the input domain's base name matches the brand's
        #    base name (prevents amazon.in flagged vs amazon.com)
        if not impersonation_detected:
            input_base = extracted.domain  # e.g. "amazon" from "amazon.in"
            for legit_domain, brand_name in BRAND_DOMAINS.items():
                legit_base = legit_domain.split(".")[0]
                # If the base names are identical, this is just a TLD variant,
                # not typosquatting (e.g. amazon.in vs amazon.com)
                if input_base == legit_base:
                    continue
                dist = Levenshtein.distance(real_domain, legit_domain)
                if 0 < dist <= 3:
                    score += 35
                    flags.append(
                        f"Possible {brand_name} impersonation "
                        f"(distance={dist} from {legit_domain})"
                    )
                    raw["impersonating"] = brand_name
                    impersonation_detected = True
                    break

        # 5. Brand keyword in real domain (not subdomain)
        #    Fix 5: use word-boundary matching instead of substring `in`
        #    Fix 2: check against all legitimate domains for that brand
        if not impersonation_detected:
            for brand_domain, brand_name in BRAND_DOMAINS.items():
                brand_keyword = brand_domain.split(".")[0]
                if len(brand_keyword) < MIN_KEYWORD_LEN:
                    continue
                # If the domain name IS exactly the brand keyword, this is
                # most likely a TLD variant (e.g. amazon.us, google.co.uk),
                # not impersonation. Impersonation adds extra words like
                # "amazon-login.xyz" or "pay-amazon.tk".
                if extracted.domain == brand_keyword:
                    continue
                # Use the domain part only (without suffix) to check for keyword
                if _keyword_in_text(brand_keyword, extracted.domain):
                    legit_domains = BRAND_KEYWORD_TO_DOMAINS.get(brand_keyword, set())
                    if real_domain not in legit_domains:
                        score += 30
                        flags.append(
                            f"Brand keyword '{brand_keyword}' in suspicious "
                            f"domain '{real_domain}' — possible "
                            f"{brand_name} impersonation"
                        )
                        raw["impersonating"] = brand_name
                        impersonation_detected = True
                        break

        # 6. IP address URL
        if re.match(r"^\d{1,3}(\.\d{1,3}){3}$", extracted.domain):
            score += 30
            flags.append("URL uses raw IP address instead of domain name")

        # 7. VirusTotal
        if settings.VIRUSTOTAL_API_KEY:
            try:
                vt_result = await check_virustotal(real_domain)
                raw["virustotal"] = vt_result
                if vt_result.get("malicious", 0) > 2:
                    score += 25
                    flags.append(f"VirusTotal: {vt_result['malicious']} engines flagged this")
            except Exception as e:
                raw["vt_error"] = str(e)

        # 8. HTTPS check
        if not url.startswith("https://"):
            score += 10
            flags.append("Not using HTTPS")

    except Exception as e:
        flags.append(f"Domain analysis error: {str(e)}")

    return SignalResult(
        score=min(score, 60),  # domain service contributes up to 60
        flags=flags,
        confidence=0.85,
        raw_data=raw
    )

async def check_virustotal(domain: str) -> dict:
    url = f"https://www.virustotal.com/api/v3/domains/{domain}"
    headers = {"x-apikey": settings.VIRUSTOTAL_API_KEY}
    async with httpx.AsyncClient() as client:
        r = await client.get(url, headers=headers, timeout=5)
        if r.status_code == 200:
            data = r.json()
            stats = data.get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
            return {
                "malicious": stats.get("malicious", 0),
                "suspicious": stats.get("suspicious", 0),
                "harmless": stats.get("harmless", 0),
            }
    return {}