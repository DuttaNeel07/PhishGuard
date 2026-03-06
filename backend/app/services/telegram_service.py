import os
import httpx
from telegram import Update
from telegram.ext import Application, MessageHandler, filters, ContextTypes
from dotenv import load_dotenv

load_dotenv()
BOT_TOKEN = os.getenv("TELEGRAM_BOT_TOKEN")

async def handle_message(update: Update, context: ContextTypes.DEFAULT_TYPE):
    text = update.message.text

    if "http://" in text or "https://" in text:
        await update.message.reply_text("🔍 Analyzing URL...")

        try:
            async with httpx.AsyncClient(timeout=30) as client:
                response = await client.post(
                    "http://localhost:8000/analyze",
                    json={"url": text.strip()}
                )
                data = response.json()

            verdict = data.get("verdict", "unknown")
            score = data.get("score", "N/A")

            await update.message.reply_text(
                f"🔍 URL: {text}\n"
                f"📊 Score: {score}\n"
                f"✅ Verdict: {verdict}"
            )

        except Exception as e:
            await update.message.reply_text(f"❌ Error: {str(e)}")

    else:
        await update.message.reply_text("ℹ️ Please send a URL starting with http:// or https://")


async def handle_photo(update: Update, context: ContextTypes.DEFAULT_TYPE):
    await update.message.reply_text("📷 QR code received, analyzing...")

    try:
        # Download image from Telegram
        photo = update.message.photo[-1]  # highest resolution
        file = await context.bot.get_file(photo.file_id)
        
        async with httpx.AsyncClient(timeout=30) as client:
            # Download the image
            image_response = await client.get(file.file_path)
            
            # Send to /analyze/qr endpoint
            response = await client.post(
                "http://localhost:8000/analyze/qr",
                files={"file": ("qr.png", image_response.content, "image/png")}
            )
            data = response.json()

        if "error" in data:
            await update.message.reply_text(f"❌ {data['error']}")
        else:
            is_upi = data.get("is_upi", False)
            verdict = data.get("verdict", "unknown")
            decoded = data.get("decoded", "unknown")

            await update.message.reply_text(
                f"🔍 QR Decoded: {decoded}\n"
                f"💳 UPI: {'Yes ⚠️' if is_upi else 'No ✅'}\n"
                f"📊 Verdict: {verdict}"
            )

    except Exception as e:
        await update.message.reply_text(f"❌ Error: {str(e)}")


def run_bot():
    app = Application.builder().token(BOT_TOKEN).build()
    app.add_handler(MessageHandler(filters.TEXT & ~filters.COMMAND, handle_message))
    app.add_handler(MessageHandler(filters.PHOTO, handle_photo))  # ← handles images
    print("🤖 PhishGuard bot is running...")
    app.run_polling()

if __name__ == "__main__":
    run_bot()