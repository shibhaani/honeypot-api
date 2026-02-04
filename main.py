from fastapi import FastAPI, Header, HTTPException, Body
import re
import requests
from typing import Dict

app = FastAPI(title="Agentic Honeypot API")

import os
API_KEY = os.getenv("API_KEY") # SAME key you submit to GUVI
GUVI_CALLBACK_URL = "https://hackathon.guvi.in/api/updateHoneyPotFinalResult"

sessions: Dict[str, Dict] = {}

# ---------------------------
# Scam Detection
# ---------------------------
def detect_scam(text: str) -> bool:
    keywords = ["account blocked", "verify", "urgent", "upi", "suspended", "bank"]
    return sum(k in text.lower() for k in keywords) >= 2

# ---------------------------
# Intelligence Extraction
# ---------------------------
def extract_intelligence(text: str, intel: Dict):
    intel.setdefault("phoneNumbers", [])
    intel.setdefault("upiIds", [])
    intel.setdefault("phishingLinks", [])
    intel.setdefault("suspiciousKeywords", [])

    for p in re.findall(r"\+91\d{10}", text):
        if p not in intel["phoneNumbers"]:
            intel["phoneNumbers"].append(p)

    for u in re.findall(r"[a-zA-Z0-9._-]+@[a-zA-Z]+", text):
        if u not in intel["upiIds"]:
            intel["upiIds"].append(u)

    for url in re.findall(r"https?://[^\s]+", text):
        if url not in intel["phishingLinks"]:
            intel["phishingLinks"].append(url)

    for k in ["urgent", "verify now", "account blocked"]:
        if k in text.lower() and k not in intel["suspiciousKeywords"]:
            intel["suspiciousKeywords"].append(k)

# ---------------------------
# Agent Logic
# ---------------------------
def agent_reply(history):
    last = history[-1]["text"].lower()

    if "blocked" in last:
        return "Why will my account be blocked?"
    if "upi" in last:
        return "Which bank is this related to?"
    if "verify" in last:
        return "I already verified earlier. What is the issue now?"

    return "Can you please explain more clearly?"

# ---------------------------
# GUVI Callback
# ---------------------------
def send_final_callback(session_id: str, session: Dict):
    if session.get("callbackSent"):
        return

    payload = {
        "sessionId": session_id,
        "scamDetected": True,
        "totalMessagesExchanged": len(session["messages"]),
        "extractedIntelligence": session["intelligence"],
        "agentNotes": "Urgency-based social engineering detected"
    }

    try:
        requests.post(GUVI_CALLBACK_URL, json=payload, timeout=5)
        session["callbackSent"] = True
    except:
        pass

# ---------------------------
# Main Endpoint
# ---------------------------
@app.post("/honeypot")
async def honeypot(
    data: dict = Body(...),
    x_api_key: str = Header(None)
):


    if "sessionId" not in data or "message" not in data:
        raise HTTPException(status_code=400, detail="Invalid request format")

    session_id = data["sessionId"]
    message = data["message"]

    sessions.setdefault(session_id, {
        "messages": [],
        "intelligence": {},
        "scamDetected": False,
        "callbackSent": False
    })

    session = sessions[session_id]
    session["messages"].append(message)

    if not session["scamDetected"]:
        session["scamDetected"] = detect_scam(message["text"])

    extract_intelligence(message["text"], session["intelligence"])

    reply = agent_reply(session["messages"])

    if session["scamDetected"] and len(session["messages"]) >= 5:
        send_final_callback(session_id, session)

    return {
        "status": "success",
        "reply": reply
    }



