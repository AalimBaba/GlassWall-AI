from __future__ import annotations

import time
from datetime import datetime, timezone
import os

from fastapi import FastAPI, WebSocket, WebSocketDisconnect
from fastapi.middleware.cors import CORSMiddleware

from .detector import FrameDetector, InvalidFrameError
from .saas_repository import HeartbeatInput, SaaSRepository, TenantAccessError
from .schemas import AdminOverviewResponse, EndpointHeartbeatRequest, EndpointHealthResponse
from .threat_engine import TemporalThreatEngine

app = FastAPI(title="GlassWall AI Local Detection API", version="1.0.0")
app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:5173", "http://127.0.0.1:5173"],
    allow_credentials=False,
    allow_methods=["GET", "POST"],
    allow_headers=["*"],
)

detector = FrameDetector()
saas_repo = SaaSRepository(os.getenv("GLASSWALL_DB_URL", "sqlite:///./glasswall-dev.db"))
saas_repo.create_schema()


@app.get("/health")
def health() -> dict[str, object]:
    return {
        "status": "ok",
        "face_detector": "opencv-haar",
        "phone_model_loaded": False,
        "phone_model_note": "Phone detection requires adding a YOLO/COCO model file.",
    }


def _timestamp_to_datetime(timestamp: int | None) -> datetime | None:
    if timestamp is None:
        return None
    return datetime.fromtimestamp(timestamp / 1000, timezone.utc)


@app.post("/api/organizations/{organization_id}/heartbeats", response_model=EndpointHealthResponse)
def record_endpoint_heartbeat(organization_id: str, payload: EndpointHeartbeatRequest) -> EndpointHealthResponse:
    try:
        snapshot = saas_repo.record_heartbeat(
            organization_id,
            HeartbeatInput(
                session_id=payload.session_id,
                workspace_id=payload.workspace_id,
                device_id=payload.device_id,
                user_id=payload.user_id,
                session_state=payload.session_state,
                camera_permission=payload.camera_permission,
                backend_connected=payload.backend_connected,
                model_loaded=payload.model_loaded,
                inference_latency_ms=payload.inference_latency_ms,
                latest_risk_score=payload.latest_risk_score,
                last_detection_at=_timestamp_to_datetime(payload.last_detection_timestamp),
                application_version=payload.application_version,
            ),
        )
    except TenantAccessError as exc:
        from fastapi import HTTPException

        raise HTTPException(status_code=404, detail=str(exc)) from exc
    return EndpointHealthResponse(
        session_id=snapshot.session_id,
        workspace_id=snapshot.workspace_id,
        device_id=snapshot.device_id,
        state=snapshot.state,
        health=snapshot.health.value,
        latest_risk_score=snapshot.latest_risk_score,
        last_heartbeat_at=snapshot.last_heartbeat_at.isoformat() if snapshot.last_heartbeat_at else None,
        application_version=snapshot.application_version,
    )


@app.get("/api/organizations/{organization_id}/admin/overview", response_model=AdminOverviewResponse)
def admin_overview(organization_id: str) -> AdminOverviewResponse:
    return AdminOverviewResponse(**saas_repo.admin_overview(organization_id))


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
