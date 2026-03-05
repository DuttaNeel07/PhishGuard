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
                f" URL: {text}\n"
                f" Score: {score}\n"
                f" Verdict: {verdict}"
            )

        except Exception as e:
            await update.message.reply_text(f"❌ Error: {str(e)}")

def run_bot():
    app = Application.builder().token(BOT_TOKEN).build()
    app.add_handler(MessageHandler(filters.TEXT & ~filters.COMMAND, handle_message))
    print("PhishGuard bot is running...")
    app.run_polling()

if __name__ == "__main__":
    run_bot()