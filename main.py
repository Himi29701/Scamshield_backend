import json
import os
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import StreamingResponse
from pydantic import BaseModel

from agent import run_investigation

app = FastAPI(title="ScamShield API")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # tighten to your dashboard's origin before sharing publicly
    allow_methods=["*"],
    allow_headers=["*"],
)


class AnalyzeRequest(BaseModel):
    text: str


@app.get("/health")
def health():
    return {"status": "ok", "has_api_key": bool(os.environ.get("ANTHROPIC_API_KEY"))}


@app.post("/analyze")
def analyze(req: AnalyzeRequest):
    """
    Streams newline-delimited JSON (NDJSON), one event per pipeline step,
    so the dashboard can render the investigation as it happens rather
    than waiting for the whole thing to finish.
    """
    def event_stream():
        for event in run_investigation(req.text):
            yield json.dumps(event, default=str) + "\n"

    return StreamingResponse(event_stream(), media_type="application/x-ndjson")
