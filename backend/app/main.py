from __future__ import annotations

import time

from fastapi import FastAPI, WebSocket, WebSocketDisconnect
from fastapi.middleware.cors import CORSMiddleware

from .detector import FrameDetector, InvalidFrameError
from .threat_engine import TemporalThreatEngine

app = FastAPI(title="GlassWall AI Local Detection API", version="1.0.0")
app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:5173", "http://127.0.0.1:5173"],
    allow_credentials=False,
    allow_methods=["GET"],
    allow_headers=["*"],
)

detector = FrameDetector()


@app.get("/health")
def health() -> dict[str, object]:
    return {
        "status": "ok",
        "face_detector": "opencv-haar",
        "phone_model_loaded": False,
        "phone_model_note": "Phone detection requires adding a YOLO/COCO model file.",
    }


@app.websocket("/ws/analyze")
async def analyze(websocket: WebSocket) -> None:
    await websocket.accept()
    engine = TemporalThreatEngine()
    try:
        while True:
            payload = await websocket.receive_json()
            timestamp = int(payload.get("timestamp", time.time_ns() // 1_000_000))
            if payload.get("type") == "reset":
                engine.reset(timestamp)
                await websocket.send_json(engine.evaluate([], timestamp).model_dump(mode="json"))
                continue
            frame = payload.get("frame")
            if not isinstance(frame, str):
                await websocket.send_json({"error": "frame must be a base64 JPEG string", "timestamp": timestamp})
                continue
            try:
                detections = detector.analyze(frame)
            except InvalidFrameError as exc:
                await websocket.send_json({"error": str(exc), "timestamp": timestamp})
                continue
            response = engine.evaluate(detections, timestamp)
            await websocket.send_json(response.model_dump(mode="json"))
    except WebSocketDisconnect:
        return
