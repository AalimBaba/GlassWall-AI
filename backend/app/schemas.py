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
