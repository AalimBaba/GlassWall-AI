from __future__ import annotations

from enum import StrEnum
from typing import Literal

from pydantic import BaseModel, Field


class SecurityState(StrEnum):
    SECURE = "SECURE"
    WARNING = "WARNING"
    LOCKDOWN = "LOCKDOWN"


class Detection(BaseModel):
    type: Literal["FACE", "PHONE", "CAMERA"]
    confidence: float = Field(ge=0.0, le=1.0)
    bbox: tuple[int, int, int, int]


class AnalysisResponse(BaseModel):
    state: SecurityState
    detections: list[Detection]
    faces_count: int
    phone_detected: bool
    threat_reason: str | None
    action: Literal["NONE", "BLUR", "LOCKDOWN"]
    timestamp: int
    frame_id: int | None = None
    phone_model_loaded: bool = False
    backend: Literal["opencv-haar"] = "opencv-haar"


class EndpointHeartbeatRequest(BaseModel):
    session_id: str
    workspace_id: str
    device_id: str
    user_id: str | None = None
    session_state: str = "SECURE"
    camera_permission: bool
    backend_connected: bool
    model_loaded: bool
    inference_latency_ms: int = Field(ge=0)
    latest_risk_score: int = Field(ge=0, le=100)
    last_detection_timestamp: int | None = None
    application_version: str = "unknown"


class EndpointHealthResponse(BaseModel):
    session_id: str
    workspace_id: str
    workspace_name: str | None = None
    device_id: str
    device_name: str | None = None
    state: str
    health: str
    latest_risk_score: int
    camera_permission: bool
    backend_connected: bool
    model_loaded: bool
    inference_latency_ms: int
    last_detection_at: str | None = None
    last_heartbeat_at: str | None
    application_version: str


class AdminOverviewResponse(BaseModel):
    organization_id: str
    endpoint_count: int
    health_counts: dict[str, int]
    state_counts: dict[str, int]
    incident_count: int
    open_incident_count: int
    sample_data: bool = False


class DeviceInventoryResponse(BaseModel):
    organization_id: str
    devices: list[EndpointHealthResponse]
    sample_data: bool = False


class IncidentEventResponse(BaseModel):
    id: str
    event_type: str
    source: str
    message: str
    risk_score: int | None = None
    confidence: float | None = None
    frame_id: int | None = None
    metadata: dict[str, object]
    occurred_at: str


class IncidentSignalResponse(BaseModel):
    id: str
    signal_type: str
    confidence: float | None = None
    frame_id: int | None = None
    bbox: list[object]
    frame_hash: str | None = None
    metadata: dict[str, object]
    observed_at: str


class RemediationActionResponse(BaseModel):
    id: str
    action_type: str
    status: str
    requested_by_user_id: str | None = None
    created_at: str


class AnalystNoteResponse(BaseModel):
    id: str
    analyst_id: str | None = None
    note: str
    created_at: str


class ThreatIncidentSummaryResponse(BaseModel):
    id: str
    organization_id: str
    workspace_id: str
    device_id: str
    session_id: str
    state: str
    status: str
    severity: str
    threat_type: str
    started_at: str
    ended_at: str | None = None
    duration_ms: int | None = None
    peak_risk_score: int
    current_risk_score: int
    phone_confidence: float | None = None
    face_count: int | None = None
    backend_connected: bool
    model_loaded: bool
    assigned_analyst_id: str | None = None
    resolution_reason: str | None = None
    created_at: str
    updated_at: str


class IncidentListResponse(BaseModel):
    organization_id: str
    incidents: list[ThreatIncidentSummaryResponse]
    total: int
    limit: int
    offset: int
    sample_data: bool = False


class ThreatIncidentDetailResponse(ThreatIncidentSummaryResponse):
    events: list[IncidentEventResponse]
    signals: list[IncidentSignalResponse]
    remediation_actions: list[RemediationActionResponse]
    analyst_notes: list[AnalystNoteResponse]


class IncidentStatusUpdateRequest(BaseModel):
    status: Literal["OPEN", "INVESTIGATING", "RESOLVED", "FALSE_POSITIVE", "DISMISSED"]
    reason: str | None = None
    analyst_id: str | None = None


class AnalystNoteRequest(BaseModel):
    note: str = Field(min_length=1, max_length=4000)
    analyst_id: str | None = None


class ProtectedZoneRequest(BaseModel):
    name: str = Field(min_length=1, max_length=180)
    description: str = ""
    relative_x: float = Field(ge=0.0, le=1.0)
    relative_y: float = Field(ge=0.0, le=1.0)
    relative_width: float = Field(gt=0.0, le=1.0)
    relative_height: float = Field(gt=0.0, le=1.0)
    sensitivity: Literal["LOW", "MEDIUM", "HIGH", "CRITICAL"] = "HIGH"
    protection_action: Literal["BLUR", "REDACT", "HIDE", "WATERMARK"] = "BLUR"
    enabled: bool = True


class ProtectedZonePatchRequest(BaseModel):
    name: str | None = Field(default=None, min_length=1, max_length=180)
    description: str | None = None
    relative_x: float | None = Field(default=None, ge=0.0, le=1.0)
    relative_y: float | None = Field(default=None, ge=0.0, le=1.0)
    relative_width: float | None = Field(default=None, gt=0.0, le=1.0)
    relative_height: float | None = Field(default=None, gt=0.0, le=1.0)
    sensitivity: Literal["LOW", "MEDIUM", "HIGH", "CRITICAL"] | None = None
    protection_action: Literal["BLUR", "REDACT", "HIDE", "WATERMARK"] | None = None
    enabled: bool | None = None


class ProtectedZoneResponse(BaseModel):
    id: str
    organization_id: str
    workspace_id: str
    name: str
    description: str
    relative_x: float
    relative_y: float
    relative_width: float
    relative_height: float
    sensitivity: str
    protection_action: str
    enabled: bool
    created_at: str
    updated_at: str


class ProtectedZoneListResponse(BaseModel):
    organization_id: str
    workspace_id: str
    zones: list[ProtectedZoneResponse]
    sample_data: bool = False
