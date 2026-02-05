from fastapi import FastAPI, Header, HTTPException
from typing import Any, Dict
import re
import os
import requests

app = FastAPI()

# =====================
# CONFIG
# =====================
API_KEY = os.getenv("API_KEY")  # SAME key you submit on GUVI
GUVI_CALLBACK_URL = "https://hackathon.guvi.in/api/updateHoneyPotFinalResult"

sessions = {}

# =====================
# MAIN ENDPOINT
# =====================
@app.post("/honeypot")
async def honeypot(
    body: Dict[str, Any],
    x_api_key: str = Header(None)
):
    # --- Auth ---
    if x_api_key != API_KEY:
        raise HTTPException(status_code=401, detail="Invalid API Key")

    # --- VERY LOOSE BODY HANDLING (IMPORTANT) ---
    session_id = body.get("sessionId", "default-session")
    message = body.get("message", {})
    text = message.get("text", "")

    if session_id not in sessions:
        sessions[session_id] = {
            "messages": [],
            "intelligence": {
                "phoneNumbers": [],
                "upiIds": [],
                "phishingLinks": [],
                "suspiciousKeywords": []
            },
            "callbackSent": False
        }

    session = sessions[session_id]

    if text:
        session["messages"].append(text)

        # --- Extract intelligence ---
        session["intelligence"]["phoneNumbers"] += re.findall(r"\+91\d{10}", text)
        session["intelligence"]["upiIds"] += re.findall(r"[a-zA-Z0-9._-]+@[a-zA-Z]+", text)
        session["intelligence"]["phishingLinks"] += re.findall(r"https?://[^\s]+", text)

        for k in ["urgent", "verify", "account blocked", "upi", "bank"]:
            if k in text.lower() and k not in session["intelligence"]["suspiciousKeywords"]:
                session["intelligence"]["suspiciousKeywords"].append(k)

    # --- Callback after few messages ---
    if len(session["messages"]) >= 3 and not session["callbackSent"]:
        try:
            requests.post(
                GUVI_CALLBACK_URL,
                json={
                    "sessionId": session_id,
                    "scamDetected": True,
                    "totalMessagesExchanged": len(session["messages"]),
                    "extractedIntelligence": session["intelligence"],
                    "agentNotes": "Rule-based scam indicators detected"
                },
                timeout=5
            )
            session["callbackSent"] = True
        except:
            pass

    return {
        "status": "success",
        "reply": "Please explain more, I am unable to understand."
    }


# =====================
# HEALTH CHECK (IMPORTANT)
# =====================
@app.get("/")
def root():
    return {"status": "alive"}
