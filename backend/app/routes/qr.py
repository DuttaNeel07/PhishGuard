from fastapi import APIRouter, UploadFile, File
from pyzbar.pyzbar import decode
from PIL import Image
import io

router = APIRouter()

@router.post("/analyze/qr")
async def analyze_qr(file: UploadFile = File(...)):
    contents = await file.read()
    image = Image.open(io.BytesIO(contents))
    decoded = decode(image)

    if not decoded:
        return {"error": "No QR code found"}

    qr_data = decoded[0].data.decode("utf-8")
    is_upi = qr_data.startswith("upi://")

    return {
        "decoded": qr_data,
        "is_upi": is_upi,
        "verdict": "suspicious" if is_upi else "clean"
    }