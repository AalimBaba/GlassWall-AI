from __future__ import annotations

import time
import asyncio
from datetime import datetime, timezone
from dataclasses import dataclass
import logging
from contextlib import asynccontextmanager
import json

from fastapi import FastAPI, Query, WebSocket, WebSocketDisconnect
from fastapi.middleware.cors import CORSMiddleware

from .config import load_settings
from .detector import FrameDetector, InvalidFrameError
from .logging_config import configure_logging
from .saas_repository import HeartbeatInput, SaaSRepository, TenantAccessError
from .schemas import (
    AdminOverviewResponse,
    AnalystNoteRequest,
    AnalystNoteResponse,
    DeviceInventoryResponse,
    EndpointHeartbeatRequest,
    EndpointHealthResponse,
    IncidentEventResponse,
    IncidentListResponse,
    IncidentSignalResponse,
    IncidentStatusUpdateRequest,
    RemediationActionResponse,
    ThreatIncidentDetailResponse,
    ThreatIncidentSummaryResponse,
)
from .threat_engine import TemporalThreatEngine

settings = load_settings()
configure_logging(settings.log_level)
logger = logging.getLogger("glasswall.backend")


@asynccontextmanager
async def lifespan(_app: FastAPI):
    logger.info("glasswall backend started")
    try:
        yield
    finally:
        logger.info("glasswall backend shutting down")


app = FastAPI(title="GlassWall AI Detection and Control Plane API", version="1.0.0", lifespan=lifespan)
app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.allowed_origins,
    allow_credentials=False,
    allow_methods=["GET", "POST"],
    allow_headers=["*"],
)

detector = FrameDetector(max_frame_bytes=settings.max_frame_bytes)
saas_repo = SaaSRepository(settings.database_url)
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
        "environment": settings.environment,
        "face_detector": "opencv-haar",
        "phone_model_loaded": False,
        "phone_model_note": "Phone detection runs in the browser through COCO-SSD.",
        "database_configured": bool(settings.database_url),
        "allowed_origins": settings.allowed_origins,
        "max_frame_bytes": settings.max_frame_bytes,
        "heartbeat_expiry_seconds": settings.heartbeat_expiry_seconds,
        "pipeline_metrics": backend_metrics.snapshot(),
    }


@app.get("/ready")
def readiness() -> dict[str, object]:
    saas_repo.ping()
    return {
        "status": "ready",
        "database": "reachable",
        "environment": settings.environment,
    }


def _timestamp_to_datetime(timestamp: int | None) -> datetime | None:
    if timestamp is None:
        return None
    return datetime.fromtimestamp(timestamp / 1000, timezone.utc)


def _json(value: str, fallback):
    try:
        return json.loads(value)
    except json.JSONDecodeError:
        return fallback


def _incident_summary(incident) -> ThreatIncidentSummaryResponse:
    return ThreatIncidentSummaryResponse(
        id=incident.id,
        organization_id=incident.organization_id,
        workspace_id=incident.workspace_id,
        device_id=incident.device_id,
        session_id=incident.session_id,
        state=incident.state,
        status=incident.status,
        severity=incident.severity,
        threat_type=incident.threat_type,
        started_at=incident.started_at.isoformat(),
        ended_at=incident.ended_at.isoformat() if incident.ended_at else None,
        duration_ms=incident.duration_ms,
        peak_risk_score=incident.peak_risk_score,
        current_risk_score=incident.current_risk_score,
        phone_confidence=incident.phone_confidence,
        face_count=incident.face_count,
        backend_connected=incident.backend_connected,
        model_loaded=incident.model_loaded,
        assigned_analyst_id=incident.assigned_analyst_id,
        resolution_reason=incident.resolution_reason,
        created_at=incident.created_at.isoformat(),
        updated_at=incident.updated_at.isoformat(),
    )


def _incident_detail(incident, events, signals, actions, notes) -> ThreatIncidentDetailResponse:
    summary = _incident_summary(incident).model_dump()
    return ThreatIncidentDetailResponse(
        **summary,
        events=[
            IncidentEventResponse(
                id=event.id,
                event_type=event.event_type,
                source=event.source,
                message=event.message,
                risk_score=event.risk_score,
                confidence=event.confidence,
                frame_id=event.frame_id,
                metadata=_json(event.metadata_json, {}),
                occurred_at=event.occurred_at.isoformat(),
            )
            for event in events
        ],
        signals=[
            IncidentSignalResponse(
                id=signal.id,
                signal_type=signal.signal_type,
                confidence=signal.confidence,
                frame_id=signal.frame_id,
                bbox=_json(signal.bbox_json, []),
                frame_hash=signal.frame_hash,
                metadata=_json(signal.metadata_json, {}),
                observed_at=signal.observed_at.isoformat(),
            )
            for signal in signals
        ],
        remediation_actions=[
            RemediationActionResponse(
                id=action.id,
                action_type=action.action_type,
                status=action.status,
                requested_by_user_id=action.requested_by_user_id,
                created_at=action.created_at.isoformat(),
            )
            for action in actions
        ],
        analyst_notes=[
            AnalystNoteResponse(id=note.id, analyst_id=note.analyst_id, note=note.note, created_at=note.created_at.isoformat())
            for note in notes
        ],
    )


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
        return AdminOverviewResponse(**saas_repo.admin_overview(organization_id, expiry_seconds=settings.heartbeat_expiry_seconds))
    except TenantAccessError as exc:
        from fastapi import HTTPException

        raise HTTPException(status_code=404, detail=str(exc)) from exc


@app.get("/api/organizations/{organization_id}/devices", response_model=DeviceInventoryResponse)
def device_inventory(organization_id: str) -> DeviceInventoryResponse:
    try:
        snapshots = saas_repo.list_endpoint_health(organization_id, expiry_seconds=settings.heartbeat_expiry_seconds)
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


@app.get("/api/organizations/{organization_id}/incidents", response_model=IncidentListResponse)
def list_incidents(
    organization_id: str,
    status: str | None = None,
    severity: str | None = None,
    device: str | None = None,
    workspace: str | None = None,
    threat_type: str | None = None,
    limit: int = Query(50, ge=1, le=100),
    offset: int = Query(0, ge=0),
) -> IncidentListResponse:
    try:
        incidents = saas_repo.list_incidents(
            organization_id,
            status=status,
            severity=severity,
            device_id=device,
            workspace_id=workspace,
            threat_type=threat_type,
            limit=limit,
            offset=offset,
        )
        total = saas_repo.count_incidents(
            organization_id,
            status=status,
            severity=severity,
            device_id=device,
            workspace_id=workspace,
            threat_type=threat_type,
        )
    except TenantAccessError as exc:
        from fastapi import HTTPException

        raise HTTPException(status_code=404, detail=str(exc)) from exc
    return IncidentListResponse(
        organization_id=organization_id,
        incidents=[_incident_summary(item) for item in incidents],
        total=total,
        limit=limit,
        offset=offset,
        sample_data=False,
    )


@app.get("/api/organizations/{organization_id}/incidents/{incident_id}", response_model=ThreatIncidentDetailResponse)
def get_incident(organization_id: str, incident_id: str) -> ThreatIncidentDetailResponse:
    try:
        return _incident_detail(*saas_repo.get_incident_detail(organization_id, incident_id))
    except TenantAccessError as exc:
        from fastapi import HTTPException

        raise HTTPException(status_code=404, detail=str(exc)) from exc


@app.post("/api/organizations/{organization_id}/incidents/{incident_id}/status", response_model=ThreatIncidentDetailResponse)
def update_incident_status(organization_id: str, incident_id: str, payload: IncidentStatusUpdateRequest) -> ThreatIncidentDetailResponse:
    try:
        saas_repo.update_incident_status(organization_id, incident_id, payload.status, payload.reason, payload.analyst_id)
        return _incident_detail(*saas_repo.get_incident_detail(organization_id, incident_id))
    except ValueError as exc:
        from fastapi import HTTPException

        raise HTTPException(status_code=400, detail=str(exc)) from exc
    except TenantAccessError as exc:
        from fastapi import HTTPException

        raise HTTPException(status_code=404, detail=str(exc)) from exc


@app.post("/api/organizations/{organization_id}/incidents/{incident_id}/notes", response_model=ThreatIncidentDetailResponse)
def add_incident_note(organization_id: str, incident_id: str, payload: AnalystNoteRequest) -> ThreatIncidentDetailResponse:
    try:
        saas_repo.add_analyst_note(organization_id, incident_id, payload.note, payload.analyst_id)
        return _incident_detail(*saas_repo.get_incident_detail(organization_id, incident_id))
    except TenantAccessError as exc:
        from fastapi import HTTPException

        raise HTTPException(status_code=404, detail=str(exc)) from exc


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
