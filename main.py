from fastapi import FastAPI, WebSocket, WebSocketDisconnect
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel

from predict import analyze_message_complete


# ============================================================
# SCAMSHIELD BACKEND
# ============================================================

app = FastAPI(
    title="ScamShield AI Backend",
    description="AI-powered scam message detection API",
    version="1.0.0"
)


# ============================================================
# CORS
# ============================================================

app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "http://localhost:8501",
        "http://127.0.0.1:8501",
        "http://localhost:3000",
        "http://localhost:5173"
    ],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


# ============================================================
# DATA MODELS
# ============================================================

class MessageRequest(BaseModel):
    message: str


class Alert(BaseModel):
    timestamp: str
    violation_type: str
    severity: str


# ============================================================
# STORAGE
# ============================================================

logs = []
connected_clients = []


# ============================================================
# ROOT
# ============================================================

@app.get("/")
async def root():

    return {
        "status": "running",
        "service": "ScamShield AI Backend",
        "version": "1.0.0"
    }


# ============================================================
# AI SCAM ANALYSIS
# ============================================================

@app.post("/api/analyze")
async def analyze_message(request: MessageRequest):

    message = request.message.strip()

    if not message:
        return {
            "error": "Message cannot be empty."
        }

    result = analyze_message_complete(message)

    return result


# ============================================================
# ALERT SYSTEM
# ============================================================

@app.post("/api/alerts")
async def receive_alert(alert: Alert):

    logs.append(alert)

    for client in connected_clients.copy():

        try:

            await client.send_json({
                "timestamp": alert.timestamp,
                "violation_type": alert.violation_type,
                "severity": alert.severity
            })

        except Exception:

            if client in connected_clients:
                connected_clients.remove(client)

    return {
        "status": "success",
        "message": "Alert received",
        "alert": {
            "timestamp": alert.timestamp,
            "violation_type": alert.violation_type,
            "severity": alert.severity
        }
    }


# ============================================================
# ALERT LOGS
# ============================================================

@app.get("/api/logs")
async def get_logs():

    return {
        "count": len(logs),
        "logs": [
            {
                "timestamp": alert.timestamp,
                "violation_type": alert.violation_type,
                "severity": alert.severity
            }
            for alert in logs
        ]
    }


# ============================================================
# WEBSOCKET ALERTS
# ============================================================

@app.websocket("/ws/alerts")
async def websocket_alerts(websocket: WebSocket):

    await websocket.accept()

    connected_clients.append(websocket)

    try:

        while True:

            await websocket.receive_text()

    except WebSocketDisconnect:

        if websocket in connected_clients:
            connected_clients.remove(websocket)