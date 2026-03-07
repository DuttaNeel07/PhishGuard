import httpx
import time
import base64
import re
from typing import List, Dict, Any

from app.models.schemas import RedirectHop, RedirectChainData

# List of common TDS/tracker parameters
SUSPICIOUS_PARAMS = {"clickid", "subid", "aff_id", "cid", "tracking_id", "utm_source", "ref"}
# Trusted domains that might be abused for open redirects
TRUSTED_DOMAINS = {"google.com", "bing.com", "yahoo.com", "duckduckgo.com"}

def _check_obfuscation(url: str) -> bool:
    """Check for Base64 or long Hex strings in the URL that look like obscured URLs."""
    # Simple heuristic: Look for long strings of alphanumeric characters
    # Or common Base64 patterns (though this can be prone to false positives, we keep it simple)
    # Hex: [0-9a-fA-F]{20,}
    # Base64-like: (?:[A-Za-z0-9+/]{4}){10,}(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?
    if re.search(r'[0-9a-fA-F]{30,}', url):
         return True
    
    # Check if there's a base64 encoded string that might decode to a URL
    parts = re.split(r'[?&/=\-]', url) # split by common delimiters
    for part in parts:
        if len(part) > 20 and len(part) % 4 == 0 and re.match(r'^[A-Za-z0-9+/]+={0,2}$', part):
            try:
                decoded = base64.b64decode(part).decode('utf-8')
                if "http://" in decoded or "https://" in decoded:
                    return True
            except Exception:
                pass
    return False

def _check_meta_refresh(html_content: str) -> str | None:
    """Check if the HTML contains a meta refresh tag or basic JS redirect and extract target."""
    if not html_content:
        return None
    
    # Check meta refresh: <meta http-equiv="refresh" content="0;url=http://example.com">
    meta_match = re.search(r'<meta[^>]*http-equiv=["\']refresh["\'][^>]*content=["\']\d+;\s*url=([^"\']+)["\']', html_content, re.IGNORECASE)
    if meta_match:
        return meta_match.group(1)
        
    # Check basic JS redirect: window.location = "http://example.com"
    js_match = re.search(r'window\.location(?:\.href)?\s*=\s*["\']([^"\']+)["\']', html_content, re.IGNORECASE)
    if js_match:
        return js_match.group(1)
        
    return None

async def analyze_chain(initial_url: str) -> RedirectChainData:
    chain: List[RedirectHop] = []
    current_url = initial_url
    max_hops = 10
    total_redirects = 0
    risk_level = "Safe"
    chain_flags = set()

    # Configure a custom client that does not automatically follow redirects
    # so we can inspect every hop manually.
    async with httpx.AsyncClient(timeout=10.0, follow_redirects=False, verify=False) as client:
        
        for step in range(1, max_hops + 1):
            hop_flags = []
            start_time = time.time()
            
            try:
                # Add headers to mimic a normal browser to avoid simple bot blocking
                headers = {
                    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36"
                }
                
                # We use GET to mimic browser fetching, avoiding HEAD as some servers treat it differently
                response = await client.get(current_url, headers=headers)
                time_taken_ms = int((time.time() - start_time) * 1000)
                
                status_code = response.status_code
                
                # Heuristics for Current URL
                # 1. Suspicious Parameters
                if any(f"{param}=" in current_url.lower() for param in SUSPICIOUS_PARAMS):
                    if "Suspected TDS" not in hop_flags:
                        hop_flags.append("Suspected TDS")
                
                # 2. Obfuscation Detection
                if _check_obfuscation(current_url):
                    if "Obfuscation Detected" not in hop_flags:
                        hop_flags.append("Obfuscation Detected")
                
                # 3. Protocol Downgrade
                if step > 1 and chain[-1].url.startswith("https://") and current_url.startswith("http://"):
                     hop_flags.append("Protocol Downgrade")

                # 4. Open Redirect Abuse
                if step > 1:
                    prev_domain = httpx.URL(chain[-1].url).host
                    if any(td in prev_domain for td in TRUSTED_DOMAINS) and "http" in chain[-1].url.lower():
                        if "Open Redirect Abuse" not in chain[-1].flags:
                             chain[-1].flags.append("Open Redirect Abuse")
                             chain_flags.add("Open Redirect Abuse") # Add to global set

                # 5. Fast Flux/Timing Anomaly
                # Evasive redirects often bounce in under 50ms as they just issue a 302 without rendering.
                # Adjust threshold based on real-world testing, but 50ms is a good starting point for a fast hop.
                if time_taken_ms < 50 and status_code in (301, 302, 303, 307, 308):
                     hop_flags.append("Fast Flux Timing")
                     
                # Extract headers
                server_hdr = response.headers.get("Server")
                via_hdr = response.headers.get("Via")
                set_cookie_hdr = response.headers.get("Set-Cookie")
                
                # Add jump to chain immediately
                hop = RedirectHop(
                    step=step,
                    url=current_url,
                    status=status_code,
                    time_ms=time_taken_ms,
                    flags=hop_flags
                )
                chain.append(hop)
                
                for flag in hop_flags:
                    chain_flags.add(flag)
                
                # Determine Next URL
                if status_code in (301, 302, 303, 307, 308):
                    next_url = response.headers.get("Location")
                    if not next_url:
                        break # Cannot follow redirect without location
                        
                    # Handle relative redirects
                    if next_url.startswith("/"):
                        parsed_current = httpx.URL(current_url)
                        next_url = f"{parsed_current.scheme}://{parsed_current.host}{next_url}"
                    elif not next_url.startswith("http"):
                         break # Invalid scheme

                    current_url = next_url
                    total_redirects += 1
                    
                elif status_code == 200:
                    # 6. Meta-Refresh Fallback
                    # Read body text for meta refresh or JS
                    html_content = response.text
                    meta_target = _check_meta_refresh(html_content)
                    
                    if meta_target:
                         hop.flags.append("Meta-Refresh Redirect")
                         chain_flags.add("Meta-Refresh Redirect")
                         
                         # Handle relative URLs in meta refresh
                         if meta_target.startswith("/"):
                             parsed_current = httpx.URL(current_url)
                             meta_target = f"{parsed_current.scheme}://{parsed_current.host}{meta_target}"
                         elif not meta_target.startswith("http"):
                             # might be a missing scheme, try to add it
                             # this is simpler, a more robust parser might be needed for edge cases
                             pass

                         current_url = meta_target
                         total_redirects += 1
                    else:
                        break # Normal page loaded, stop tracing
                else:
                    break # Unhandled status code (e.g. 404, 500), stop tracing

            except httpx.RequestError as e:
                # Connection failed, etc.
                time_taken_ms = int((time.time() - start_time) * 1000)
                hop = RedirectHop(
                    step=step,
                    url=current_url,
                    status=0, # Use 0 to indicate error
                    time_ms=time_taken_ms,
                    flags=["Connection Error"]
                )
                chain.append(hop)
                break
            except Exception:
                 break

    # Determine risk level based on flags
    # You can tune this logic based on your requirements
    if any(f in chain_flags for f in ["Obfuscation Detected", "Open Redirect Abuse", "Protocol Downgrade"]):
        risk_level = "High"
    elif any(f in chain_flags for f in ["Suspected TDS", "Fast Flux Timing", "Meta-Refresh Redirect"]):
        risk_level = "Medium"
    else:
        risk_level = "Low"

    return RedirectChainData(
        initial_url=initial_url,
        final_url=current_url,
        total_redirects=total_redirects,
        risk_level=risk_level,
        chain=chain
    )
