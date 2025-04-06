# type: ignore
# Twitch EventSub Webhook Handler

import os
import json
import hmac
import hashlib
from datetime import UTC, datetime
from fastapi import FastAPI, Request, HTTPException, Query
from fastapi.responses import JSONResponse
from google.cloud import storage

app = FastAPI()

EVENTSUB_SECRET = os.getenv("EVENTSUB_SECRET", "")
BUCKET_NAME = os.getenv("BUCKET_NAME", "")
STATE_FILENAME_TEMPLATE = "state_{user_id}.json"

storage_client = storage.Client()
user_states = {}


def get_current_month():
    return datetime.now(UTC).strftime("%Y-%m")


def get_state_file(user_id: str):
    return STATE_FILENAME_TEMPLATE.format(user_id=user_id)


def load_user_state(user_id: str):
    try:
        bucket = storage_client.bucket(BUCKET_NAME)
        blob = bucket.blob(get_state_file(user_id))
        if blob.exists():
            data = json.loads(blob.download_as_string())
            user_states[user_id] = {
                "plus_points": data.get("plus_points", 0),
                "month": data.get("month", get_current_month()),
            }
            print(f"Loaded state for {user_id}: {user_states[user_id]}")
        else:
            user_states[user_id] = {"plus_points": 0, "month": get_current_month()}
    except Exception as e:
        print(f"Error loading state for {user_id}: {e}")
        user_states[user_id] = {"plus_points": 0, "month": get_current_month()}

def save_user_state(user_id: str):
    try:
        bucket = storage_client.bucket(BUCKET_NAME)
        blob = bucket.blob(get_state_file(user_id))
        blob.upload_from_string(
            json.dumps(user_states[user_id]),
            content_type='application/json'
        )
        print(f"Saved state for {user_id}")
    except Exception as e:
        print(f"Error saving state for {user_id}: {e}")

def verify_signature(request: Request, body: bytes):
    if not EVENTSUB_SECRET:
        return True
    try:
        message_id = request.headers["Twitch-Eventsub-Message-Id"]
        timestamp = request.headers["Twitch-Eventsub-Message-Timestamp"]
        message = message_id + timestamp + body.decode()
        signature = hmac.new(EVENTSUB_SECRET.encode(), message.encode(), hashlib.sha256).hexdigest()
        expected = f"sha256={signature}"
        return hmac.compare_digest(request.headers["Twitch-Eventsub-Message-Signature"], expected)
    except Exception:
        return False
    
@app.get("/points")
def get_points(user_id: str = Query(None)):
    if user_id:
        if user_id not in user_states:
            load_user_state(user_id)
        return {user_id: user_states[user_id]}
    else:
        return user_states

@app.post("/set-points")
def set_points(user_id: str, value: int):
    if user_id not in user_states:
        load_user_state(user_id)
    user_states[user_id]["plus_points"] = value
    user_states[user_id]["month"] = get_current_month()
    save_user_state(user_id)
    return {"message": f"Points updated for {user_id}", "plus_points": value}

@app.post("/webhook")
async def handle_webhook(request: Request):
    body = await request.body()
    if not verify_signature(request, body):
        raise HTTPException(status_code=403, detail="Invalid signature")

    payload = await request.json()
    msg_type = request.headers.get("Twitch-Eventsub-Message-Type")

    if msg_type == "webhook_callback_verification":
        return JSONResponse(content=payload["challenge"])

    elif msg_type == "notification":
        event = payload.get("event", {})
        user_id = event.get("broadcaster_user_id")
        if not user_id:
            raise HTTPException(status_code=400, detail="Missing broadcaster_user_id")

        if user_id not in user_states:
            load_user_state(user_id)

        now = get_current_month()
        if now != user_states[user_id]["month"]:
            user_states[user_id]["plus_points"] = 0
            user_states[user_id]["month"] = now

        tier = event.get("tier")
        amount = 1 if tier == "1000" else 2 if tier == "2000" else 2.5 if tier == "3000" else 0
        user_states[user_id]["plus_points"] += amount
        save_user_state(user_id)
        return {"message": f"Added {amount} points to {user_id}"}

    return {"message": "Unhandled"}