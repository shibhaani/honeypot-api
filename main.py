from fastapi import FastAPI, Request, Header, HTTPException
import re
import requests
from typing import Dict
import os

app = FastAPI(title="Agentic Honeypot API")

# ---------------------------
# Config
# ---------------------------
API_KEY = os.getenv("API_KEY")  # Same key you submit on GUVI
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
    if session["callbackSent"]:
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
from typing import Any, Dict

@app.post("/honeypot")
async def honeypot(
    payload: Dict[str, Any],
    x_api_key: str = Header(None)
):
    if x_api_key != API_KEY:
        raise HTTPException(status_code=401, detail="Invalid API Key")

    session_id = payload.get("sessionId")
    message = payload.get("message", {})
    text = message.get("text")

    if not session_id or not text:
        return {
            "status": "success",
            "reply": "Can you explain the issue?"
        }

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
    session["messages"].append(text.lower())

    # Simple extraction
    session["intelligence"]["phoneNumbers"] += re.findall(r"\+91\d{10}", text)
    session["intelligence"]["upiIds"] += re.findall(r"[a-zA-Z0-9._-]+@[a-zA-Z]+", text)
    session["intelligence"]["phishingLinks"] += re.findall(r"https?://[^\s]+", text)

    for k in ["urgent", "verify", "account blocked"]:
        if k in text.lower():
            session["intelligence"]["suspiciousKeywords"].append(k)

    reply = "Why will my account be blocked?"

    if len(session["messages"]) >= 5 and not session["callbackSent"]:
        try:
            requests.post(
                GUVI_CALLBACK_URL,
                json={
                    "sessionId": session_id,
                    "scamDetected": True,
                    "totalMessagesExchanged": len(session["messages"]),
                    "extractedIntelligence": session["intelligence"],
                    "agentNotes": "Urgency-based scam behavior detected"
                },
                timeout=5
            )
            session["callbackSent"] = True
        except:
            pass

    return {
        "status": "success",
        "reply": reply
    }
