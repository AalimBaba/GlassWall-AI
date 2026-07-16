from __future__ import annotations

import time
import asyncio
from datetime import datetime, timezone
import os
from dataclasses import dataclass

from fastapi import FastAPI, WebSocket, WebSocketDisconnect
from fastapi.middleware.cors import CORSMiddleware

from .detector import FrameDetector, InvalidFrameError
from .saas_repository import HeartbeatInput, SaaSRepository, TenantAccessError
from .schemas import AdminOverviewResponse, DeviceInventoryResponse, EndpointHeartbeatRequest, EndpointHealthResponse
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


@dataclass(slots=True)
class BackendPipelineMetrics:
    frames_received: int = 0
    frames_processed: int = 0
    frames_dropped: int = 0
    inference_errors: int = 0
    active_sessions: int = 0
    total_inference_latency_ms: float = 0.0

    def snapshot(self) -> dict[str, float | int]:
        average = self.total_inference_latency_ms / self.frames_processed if self.frames_processed else 0.0
        return {
            "frames_received": self.frames_received,
            "frames_processed": self.frames_processed,
            "frames_dropped": self.frames_dropped,
            "inference_errors": self.inference_errors,
            "active_sessions": self.active_sessions,
            "average_inference_latency_ms": round(average, 2),
        }


backend_metrics = BackendPipelineMetrics()
opencv_semaphore = asyncio.Semaphore(2)


@app.get("/health")
def health() -> dict[str, object]:
    return {
        "status": "ok",
        "face_detector": "opencv-haar",
        "phone_model_loaded": False,
        "phone_model_note": "Phone detection requires adding a YOLO/COCO model file.",
        "pipeline_metrics": backend_metrics.snapshot(),
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
        workspace_name=snapshot.workspace_name,
        device_id=snapshot.device_id,
        device_name=snapshot.device_name,
        state=snapshot.state,
        health=snapshot.health.value,
        latest_risk_score=snapshot.latest_risk_score,
        camera_permission=snapshot.camera_permission,
        backend_connected=snapshot.backend_connected,
        model_loaded=snapshot.model_loaded,
        inference_latency_ms=snapshot.inference_latency_ms,
        last_detection_at=snapshot.last_detection_at.isoformat() if snapshot.last_detection_at else None,
        last_heartbeat_at=snapshot.last_heartbeat_at.isoformat() if snapshot.last_heartbeat_at else None,
        application_version=snapshot.application_version,
    )


@app.get("/api/organizations/{organization_id}/admin/overview", response_model=AdminOverviewResponse)
def admin_overview(organization_id: str) -> AdminOverviewResponse:
    try:
        return AdminOverviewResponse(**saas_repo.admin_overview(organization_id))
    except TenantAccessError as exc:
        from fastapi import HTTPException

        raise HTTPException(status_code=404, detail=str(exc)) from exc


@app.get("/api/organizations/{organization_id}/devices", response_model=DeviceInventoryResponse)
def device_inventory(organization_id: str) -> DeviceInventoryResponse:
    try:
        snapshots = saas_repo.list_endpoint_health(organization_id)
    except TenantAccessError as exc:
        from fastapi import HTTPException

        raise HTTPException(status_code=404, detail=str(exc)) from exc
    return DeviceInventoryResponse(
        organization_id=organization_id,
        devices=[
            EndpointHealthResponse(
                session_id=snapshot.session_id,
                workspace_id=snapshot.workspace_id,
                workspace_name=snapshot.workspace_name,
                device_id=snapshot.device_id,
                device_name=snapshot.device_name,
                state=snapshot.state,
                health=snapshot.health.value,
                latest_risk_score=snapshot.latest_risk_score,
                camera_permission=snapshot.camera_permission,
                backend_connected=snapshot.backend_connected,
                model_loaded=snapshot.model_loaded,
                inference_latency_ms=snapshot.inference_latency_ms,
                last_detection_at=snapshot.last_detection_at.isoformat() if snapshot.last_detection_at else None,
                last_heartbeat_at=snapshot.last_heartbeat_at.isoformat() if snapshot.last_heartbeat_at else None,
                application_version=snapshot.application_version,
            )
            for snapshot in snapshots
        ],
    )


@app.websocket("/ws/analyze")
async def analyze(websocket: WebSocket) -> None:
    await websocket.accept()
    backend_metrics.active_sessions += 1
    engine = TemporalThreatEngine()
    try:
        while True:
            payload = await websocket.receive_json()
            timestamp = int(payload.get("timestamp", time.time_ns() // 1_000_000))
            frame_id = payload.get("frame_id")
            frame_id = int(frame_id) if isinstance(frame_id, int | float | str) and str(frame_id).isdigit() else None
            if payload.get("type") == "reset":
                engine.reset(timestamp)
                await websocket.send_json(engine.evaluate([], timestamp, frame_id).model_dump(mode="json"))
                continue
            frame = payload.get("frame")
            if not isinstance(frame, str):
                await websocket.send_json({"error": "frame must be a base64 JPEG string", "timestamp": timestamp})
                continue
            backend_metrics.frames_received += 1
            if opencv_semaphore.locked():
                backend_metrics.frames_dropped += 1
                await websocket.send_json({"error": "backend inference busy; frame dropped", "timestamp": timestamp, "frame_id": frame_id})
                continue
            try:
                started = time.perf_counter()
                async with opencv_semaphore:
                    detections = await asyncio.to_thread(detector.analyze, frame)
                backend_metrics.frames_processed += 1
                backend_metrics.total_inference_latency_ms += (time.perf_counter() - started) * 1000
            except InvalidFrameError as exc:
                backend_metrics.inference_errors += 1
                await websocket.send_json({"error": str(exc), "timestamp": timestamp})
                continue
            response = engine.evaluate(detections, timestamp, frame_id)
            await websocket.send_json(response.model_dump(mode="json"))
    except WebSocketDisconnect:
        return
    finally:
        backend_metrics.active_sessions = max(0, backend_metrics.active_sessions - 1)
