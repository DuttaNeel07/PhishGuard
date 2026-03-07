import cv2
import numpy as np
from fastapi import APIRouter, UploadFile, File, HTTPException
import httpx  
from app.models.schemas import QRRequest  

router = APIRouter()


def _try_decode_qr(image: np.ndarray) -> list[str]:
    """Try to decode QR codes using aggressive preprocessing strategies."""
    detector = cv2.QRCodeDetector()

    def _attempt(img: np.ndarray) -> list[str]:
        """Try both single and multi QR detection on an image."""
        # Try multi first
        try:
            retval, data, _, _ = detector.detectAndDecodeMulti(img)
            if retval and data:
                decoded = [d.strip() for d in data if d and d.strip()]
                if decoded:
                    return decoded
        except Exception:
            pass
        # Fallback to single
        try:
            val, _, _ = detector.detectAndDecode(img)
            if val and val.strip():
                return [val.strip()]
        except Exception:
            pass
        return []

    gray = cv2.cvtColor(image, cv2.COLOR_BGR2GRAY)

    # Build list of preprocessed images to try
    candidates: list[np.ndarray] = []

    # 1. Original
    candidates.append(image)

    # 2. Grayscale as BGR
    candidates.append(cv2.cvtColor(gray, cv2.COLOR_GRAY2BGR))

    # 3. CLAHE contrast enhancement (key for compressed images)
    clahe = cv2.createCLAHE(clipLimit=3.0, tileGridSize=(8, 8))
    enhanced = clahe.apply(gray)
    candidates.append(cv2.cvtColor(enhanced, cv2.COLOR_GRAY2BGR))

    # 4. OTSU threshold
    _, otsu = cv2.threshold(gray, 0, 255, cv2.THRESH_BINARY + cv2.THRESH_OTSU)
    candidates.append(cv2.cvtColor(otsu, cv2.COLOR_GRAY2BGR))

    # 5. CLAHE + OTSU
    _, clahe_otsu = cv2.threshold(enhanced, 0, 255, cv2.THRESH_BINARY + cv2.THRESH_OTSU)
    candidates.append(cv2.cvtColor(clahe_otsu, cv2.COLOR_GRAY2BGR))

    # 6. Gaussian blur (remove JPEG noise) + OTSU
    blurred = cv2.GaussianBlur(gray, (5, 5), 0)
    _, blur_otsu = cv2.threshold(blurred, 0, 255, cv2.THRESH_BINARY + cv2.THRESH_OTSU)
    candidates.append(cv2.cvtColor(blur_otsu, cv2.COLOR_GRAY2BGR))

    # 7. Adaptive threshold (handles uneven lighting)
    adaptive = cv2.adaptiveThreshold(gray, 255, cv2.ADAPTIVE_THRESH_GAUSSIAN_C,
                                      cv2.THRESH_BINARY, 51, 10)
    candidates.append(cv2.cvtColor(adaptive, cv2.COLOR_GRAY2BGR))

    # 8. Morphological close to fill gaps in QR modules
    kernel = cv2.getStructuringElement(cv2.MORPH_RECT, (3, 3))
    morph = cv2.morphologyEx(otsu, cv2.MORPH_CLOSE, kernel)
    candidates.append(cv2.cvtColor(morph, cv2.COLOR_GRAY2BGR))

    # 9. Sharpen
    sharp_kernel = np.array([[0, -1, 0], [-1, 5, -1], [0, -1, 0]])
    sharpened = cv2.filter2D(image, -1, sharp_kernel)
    candidates.append(sharpened)

    # 10. Upscale 2x
    h, w = image.shape[:2]
    upscaled = cv2.resize(image, (w * 2, h * 2), interpolation=cv2.INTER_CUBIC)
    candidates.append(upscaled)

    # 11. Upscale 3x (very small QR codes)
    upscaled3 = cv2.resize(image, (w * 3, h * 3), interpolation=cv2.INTER_CUBIC)
    candidates.append(upscaled3)

    # 12. Inverted
    candidates.append(cv2.bitwise_not(image))

    # 13. Histogram equalization
    eq = cv2.equalizeHist(gray)
    candidates.append(cv2.cvtColor(eq, cv2.COLOR_GRAY2BGR))

    # 14. Denoise + sharpen combo
    denoised = cv2.fastNlMeansDenoising(gray, h=10)
    denoised_sharp = cv2.filter2D(cv2.cvtColor(denoised, cv2.COLOR_GRAY2BGR), -1, sharp_kernel)
    candidates.append(denoised_sharp)

    # Try each candidate
    for img in candidates:
        result = _attempt(img)
        if result:
            return result

    # Last resort: try center-cropping at different ratios
    for ratio in [0.9, 0.8, 0.7, 0.5]:
        ch, cw = int(h * ratio), int(w * ratio)
        y_start, x_start = (h - ch) // 2, (w - cw) // 2
        cropped = image[y_start:y_start + ch, x_start:x_start + cw]
        cropped_up = cv2.resize(cropped, (cw * 2, ch * 2), interpolation=cv2.INTER_CUBIC)
        result = _attempt(cropped_up)
        if result:
            return result

    return []


@router.post("/qr")
async def analyze_qr(file: UploadFile = File(...)):
    contents = await file.read()

    nparr = np.frombuffer(contents, np.uint8)
    image = cv2.imdecode(nparr, cv2.IMREAD_COLOR)

    if image is None:
        raise HTTPException(status_code=400, detail="Invalid image file")

    decoded_list = _try_decode_qr(image)

    if not decoded_list:
        raise HTTPException(status_code=422, detail="No QR code found in image. Try a clearer photo.")

    results = []
    for decoded in decoded_list:
        if not decoded:
            continue
        decoded = decoded.strip()

        if decoded.startswith("upi://"):
            result = await analyze_upi_qr(decoded)
            results.append(result)
        elif decoded.startswith("http"):
            results.append({
                "type": "url",
                "decoded": decoded,
                "message": "Submit this URL to /analyze/ for full analysis",
                "url_for_analysis": decoded,
            })
        else:
            results.append({
                "type": "text",
                "decoded": decoded,
                "risk": "unknown",
                "note": "Not a URL or UPI string"
            })

    if not results:
        raise HTTPException(status_code=422, detail="No QR code found in image")

    return {"qr_results": results, "count": len(results)}


async def analyze_upi_qr(upi_string: str) -> dict:
    try:
        query = upi_string.replace("upi://pay?", "")
        params = dict(p.split("=") for p in query.split("&") if "=" in p)

        payee_vpa = params.get("pa", "")
        payee_name = params.get("pn", "").replace("+", " ")
        amount = params.get("am", "0")

        flags = []
        score = 0

        payee_name_lower = payee_name.lower()
        vpa_domain = payee_vpa.split("@")[-1] if "@" in payee_vpa else ""

        official_keywords = ["sbi", "hdfc", "rbi", "bank", "customer care",
                             "helpline", "support", "irctc"]
        if any(kw in payee_name_lower for kw in official_keywords):
            legit_vpa_domains = ["sbi.in", "hdfcbank", "icici", "axisbank",
                                 "paytm", "phonepe", "ybl", "upi"]
            if not any(d in vpa_domain for d in legit_vpa_domains):
                score += 40
                flags.append(
                    f"Display name '{payee_name}' does not match "
                    f"VPA domain '{vpa_domain}' — classic impersonation"
                )

        try:
            amt_float = float(amount)
            if amt_float > 0:
                score += 10
                flags.append(f"Pre-set payment amount: ₹{amount}")
            if amt_float > 10000:
                score += 20
                flags.append(f"Very large pre-set amount: ₹{amount}")
        except ValueError:
            pass

        risk_level = "dangerous" if score >= 40 else "suspicious" if score >= 20 else "safe"

        return {
            "type": "upi",
            "decoded": upi_string,
            "payee_vpa": payee_vpa,
            "payee_name": payee_name,
            "amount": amount,
            "vpa_domain": vpa_domain,
            "score": score,
            "risk_level": risk_level,
            "flags": flags,
        }

    except Exception as e:
        return {
            "type": "upi",
            "decoded": upi_string,
            "error": str(e),
            "risk_level": "unknown"
        }
@router.post("/check-qr")
async def check_qr_for_extension(req: QRRequest):
    """
    Wrapper for Chrome extension — accepts image_url, 
    downloads it, then runs your existing QR analysis.
    """
    # 1. Download the image from the URL
    try:
        async with httpx.AsyncClient(timeout=10) as client:
            response = await client.get(req.image_url)
            response.raise_for_status()
            image_bytes = response.content
    except Exception as e:
        return {
            "is_malicious": False,
            "decoded_url": None,
            "reason": f"Could not download image: {str(e)}",
        }

    # 2. Run your existing QR detection logic
    nparr = np.frombuffer(image_bytes, np.uint8)
    image = cv2.imdecode(nparr, cv2.IMREAD_COLOR)

    if image is None:
        return {"is_malicious": False, "decoded_url": None, "reason": "Invalid image"}

    detector = cv2.QRCodeDetector()
    retval, data, _, _ = detector.detectAndDecodeMulti(image)

    if not retval or not data:
        return {"is_malicious": False, "decoded_url": None, "reason": "No QR code found in image"}

    # 3. Analyze first valid QR code found
    for decoded in data:
        if not decoded:
            continue
        decoded = decoded.strip()

        if decoded.startswith("upi://"):
            result = await analyze_upi_qr(decoded)
            return {
                "is_malicious": result["risk_level"] in ("dangerous", "suspicious"),
                "decoded_url": decoded,
                "reason": "; ".join(result.get("flags", [])) or f"UPI QR — risk: {result['risk_level']}",
            }

        elif decoded.startswith("http"):
            # Forward the decoded URL to your analyze pipeline
            from app.routes.analyze import analyze
            from app.models.schemas import AnalyzeRequest, RiskLevel
            try:
                analyze_result = await analyze(AnalyzeRequest(url=decoded, message=None))
                return {
                    "is_malicious": analyze_result.risk_level in (RiskLevel.DANGEROUS, RiskLevel.SUSPICIOUS),
                    "decoded_url": decoded,
                    "reason": analyze_result.verdict_en,
                }
            except Exception as e:
                return {
                    "is_malicious": False,
                    "decoded_url": decoded,
                    "reason": f"Decoded URL found but analysis failed: {str(e)}",
                }

        else:
            return {
                "is_malicious": False,
                "decoded_url": None,
                "reason": f"QR contains text (not a URL): {decoded[:80]}",
            }

    return {"is_malicious": False, "decoded_url": None, "reason": "No valid QR data found"}