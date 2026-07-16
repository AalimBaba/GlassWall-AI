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
