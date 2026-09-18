from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel

from predict import analyze_message_complete


# ============================================================
# APP
# ============================================================

app = FastAPI(
    title="ScamShield AI API"
)


# ============================================================
# CORS
# ============================================================

app.add_middleware(
    CORSMiddleware,

    allow_origins=["*"],

    allow_credentials=False,

    allow_methods=["*"],

    allow_headers=["*"],
)


# ============================================================
# REQUEST MODEL
# ============================================================

class MessageRequest(BaseModel):

    message: str


# ============================================================
# ROOT
# ============================================================

@app.get("/")
async def root():

    return {
        "status": "running",
        "service": "ScamShield AI"
    }


# ============================================================
# ANALYZE MESSAGE
# ============================================================

@app.post("/api/analyze")
async def analyze(request: MessageRequest):

    message = request.message.strip()

    if not message:

        return {
            "error": "Message cannot be empty"
        }


    # YOUR ACTUAL ML + RISK ENGINE

    result = analyze_message_complete(
        message
    )


    return result