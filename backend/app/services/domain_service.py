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

# Brand keywords extracted from above for quick lookup
BRAND_KEYWORDS = {domain.split(".")[0]: name for domain, name in BRAND_DOMAINS.items()}

SUSPICIOUS_TLDS = {".xyz", ".top", ".click", ".loan", ".work", ".gq", ".ml", ".tk", ".cf", ".net", ".info", ".live"}

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

        # 1. Subdomain spoofing — brand name in subdomain but real domain is different
        for brand_domain, brand_name in BRAND_DOMAINS.items():
            brand_keyword = brand_domain.split(".")[0]
            if brand_keyword in subdomain.lower():
                if not full_host.endswith(brand_domain):
                    score += 50
                    flags.append(
                        f"Subdomain spoofing: '{brand_keyword}' in subdomain but real domain is '{real_domain}' — classic {brand_name} impersonation"
                    )
                    raw["impersonating"] = brand_name
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
                score += 15
                flags.append("Domain age unknown — WHOIS lookup failed")
        except Exception as e:
            score += 15
            flags.append("Domain age unknown — WHOIS lookup failed")
            raw["whois_error"] = str(e)

        # 3. Suspicious TLD
        if tld in SUSPICIOUS_TLDS:
            score += 20
            flags.append(f"Suspicious TLD: {tld}")
        raw["tld"] = tld

        # 4. Typosquatting check against real domain
        for legit_domain, brand_name in BRAND_DOMAINS.items():
            dist = Levenshtein.distance(real_domain, legit_domain)
            if 0 < dist <= 3:
                score += 35
                flags.append(f"Possible {brand_name} impersonation (distance={dist} from {legit_domain})")
                raw["impersonating"] = brand_name
                break

        # 5. Brand keyword in real domain (not subdomain)
        for brand_domain, brand_name in BRAND_DOMAINS.items():
            brand_keyword = brand_domain.split(".")[0]
            if brand_keyword in real_domain and not real_domain == brand_domain:
                score += 30
                flags.append(f"Brand keyword '{brand_keyword}' in suspicious domain '{real_domain}' — possible {brand_name} impersonation")
                raw["impersonating"] = brand_name
                break

        # 6. IP address URL
        import re
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