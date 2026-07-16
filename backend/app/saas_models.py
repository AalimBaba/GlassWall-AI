from __future__ import annotations

from datetime import datetime, timezone
from enum import StrEnum
from uuid import uuid4

from sqlalchemy import Boolean, DateTime, Float, ForeignKey, Integer, String, Text
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column


def new_id() -> str:
    return uuid4().hex


def utcnow() -> datetime:
    return datetime.now(timezone.utc)


class Base(DeclarativeBase):
    pass


class Role(StrEnum):
    OWNER = "OWNER"
    SECURITY_ADMIN = "SECURITY_ADMIN"
    ANALYST = "ANALYST"
    AUDITOR = "AUDITOR"
    EMPLOYEE = "EMPLOYEE"


class EndpointHealth(StrEnum):
    ONLINE = "Online"
    DEGRADED = "Degraded"
    MONITORING_INTERRUPTED = "Monitoring Interrupted"
    OFFLINE = "Offline"


class IncidentStatus(StrEnum):
    OPEN = "OPEN"
    INVESTIGATING = "INVESTIGATING"
    RESOLVED = "RESOLVED"
    FALSE_POSITIVE = "FALSE_POSITIVE"
    DISMISSED = "DISMISSED"


class IncidentSeverity(StrEnum):
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


class ZoneSensitivity(StrEnum):
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


class ProtectionAction(StrEnum):
    BLUR = "BLUR"
    REDACT = "REDACT"
    HIDE = "HIDE"
    WATERMARK = "WATERMARK"


class EvidenceMode(StrEnum):
    METADATA_ONLY = "Metadata Only"
    BLURRED_EVIDENCE = "Blurred Evidence"
    NO_EVIDENCE = "No Evidence"


class TenantMixin:
    organization_id: Mapped[str] = mapped_column(String(64), index=True, nullable=False)


class Organization(Base):
    __tablename__ = "organizations"

    id: Mapped[str] = mapped_column(String(64), primary_key=True, default=new_id)
    name: Mapped[str] = mapped_column(String(180), nullable=False)
    slug: Mapped[str] = mapped_column(String(180), unique=True, nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, nullable=False)


class Workspace(TenantMixin, Base):
    __tablename__ = "workspaces"

    id: Mapped[str] = mapped_column(String(64), primary_key=True, default=new_id)
    name: Mapped[str] = mapped_column(String(180), nullable=False)
    sensitivity: Mapped[str] = mapped_column(String(32), default="standard", nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, nullable=False)


class User(TenantMixin, Base):
    __tablename__ = "users"

    id: Mapped[str] = mapped_column(String(64), primary_key=True, default=new_id)
    email: Mapped[str] = mapped_column(String(240), nullable=False)
    display_name: Mapped[str] = mapped_column(String(180), nullable=False)
    role: Mapped[str] = mapped_column(String(32), nullable=False)
    password_hash: Mapped[str | None] = mapped_column(String(255))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, nullable=False)


class Device(TenantMixin, Base):
    __tablename__ = "devices"

    id: Mapped[str] = mapped_column(String(64), primary_key=True, default=new_id)
    display_name: Mapped[str] = mapped_column(String(180), nullable=False)
    device_key: Mapped[str] = mapped_column(String(180), nullable=False)
    registered_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, nullable=False)


class EndpointSession(TenantMixin, Base):
    __tablename__ = "endpoint_sessions"

    id: Mapped[str] = mapped_column(String(64), primary_key=True, default=new_id)
    workspace_id: Mapped[str] = mapped_column(String(64), nullable=False)
    device_id: Mapped[str] = mapped_column(String(64), nullable=False)
    user_id: Mapped[str | None] = mapped_column(String(64))
    state: Mapped[str] = mapped_column(String(32), default="SECURE", nullable=False)
    camera_permission: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    backend_connected: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    model_loaded: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    inference_latency_ms: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    latest_risk_score: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    last_detection_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    last_heartbeat_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    application_version: Mapped[str] = mapped_column(String(64), default="unknown", nullable=False)
    started_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, nullable=False)


class ProtectionPolicy(TenantMixin, Base):
    __tablename__ = "protection_policies"

    id: Mapped[str] = mapped_column(String(64), primary_key=True, default=new_id)
    workspace_id: Mapped[str | None] = mapped_column(String(64))
    name: Mapped[str] = mapped_column(String(180), nullable=False)
    evidence_mode: Mapped[str] = mapped_column(String(32), default=EvidenceMode.METADATA_ONLY.value, nullable=False)
    risk_weights_json: Mapped[str] = mapped_column(Text, default="{}", nullable=False)
    actions_json: Mapped[str] = mapped_column(Text, default="{}", nullable=False)
    enabled: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)


class ProtectedZone(TenantMixin, Base):
    __tablename__ = "protected_zones"

    id: Mapped[str] = mapped_column(String(64), primary_key=True, default=new_id)
    workspace_id: Mapped[str] = mapped_column(String(64), nullable=False)
    name: Mapped[str] = mapped_column(String(180), nullable=False)
    description: Mapped[str] = mapped_column(Text, default="", nullable=False)
    relative_x: Mapped[float] = mapped_column("x", Float, nullable=False)
    relative_y: Mapped[float] = mapped_column("y", Float, nullable=False)
    relative_width: Mapped[float] = mapped_column("width", Float, nullable=False)
    relative_height: Mapped[float] = mapped_column("height", Float, nullable=False)
    sensitivity: Mapped[str] = mapped_column(String(32), default=ZoneSensitivity.HIGH.value, nullable=False)
    protection_action: Mapped[str] = mapped_column(String(32), default=ProtectionAction.BLUR.value, nullable=False)
    enabled: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, nullable=False)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, onupdate=utcnow, nullable=False)


class DetectionSignal(TenantMixin, Base):
    __tablename__ = "detection_signals"

    id: Mapped[str] = mapped_column(String(64), primary_key=True, default=new_id)
    session_id: Mapped[str] = mapped_column(String(64), nullable=False)
    incident_id: Mapped[str | None] = mapped_column(String(64))
    signal_type: Mapped[str] = mapped_column(String(64), nullable=False)
    confidence: Mapped[float] = mapped_column(Float, nullable=False)
    bbox_json: Mapped[str] = mapped_column(Text, default="[]", nullable=False)
    model_version: Mapped[str] = mapped_column(String(120), default="unknown", nullable=False)
    frame_hash: Mapped[str | None] = mapped_column(String(128))
    observed_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, nullable=False)


class ThreatIncident(TenantMixin, Base):
    __tablename__ = "threat_incidents"

    id: Mapped[str] = mapped_column(String(64), primary_key=True, default=new_id)
    workspace_id: Mapped[str] = mapped_column(String(64), nullable=False)
    device_id: Mapped[str] = mapped_column(String(64), nullable=False)
    session_id: Mapped[str] = mapped_column(String(64), nullable=False)
    state: Mapped[str] = mapped_column(String(32), default="WARNING", nullable=False)
    threat_type: Mapped[str] = mapped_column(String(64), nullable=False)
    severity: Mapped[str] = mapped_column(String(32), nullable=False)
    peak_risk_score: Mapped[int] = mapped_column(Integer, nullable=False)
    current_risk_score: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    detection_duration_ms: Mapped[int | None] = mapped_column(Integer)
    phone_confidence: Mapped[float | None] = mapped_column(Float)
    face_count: Mapped[int | None] = mapped_column(Integer)
    backend_connected: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    model_loaded: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    status: Mapped[str] = mapped_column(String(32), default=IncidentStatus.OPEN.value, nullable=False)
    started_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, nullable=False)
    ended_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    duration_ms: Mapped[int | None] = mapped_column(Integer)
    signals_json: Mapped[str] = mapped_column(Text, default="[]", nullable=False)
    actions_json: Mapped[str] = mapped_column(Text, default="[]", nullable=False)
    analyst_notes: Mapped[str] = mapped_column(Text, default="", nullable=False)
    assigned_analyst_id: Mapped[str | None] = mapped_column(String(64))
    resolution_reason: Mapped[str | None] = mapped_column(Text)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, nullable=False)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, onupdate=utcnow, nullable=False)


class IncidentEvent(TenantMixin, Base):
    __tablename__ = "incident_events"

    id: Mapped[str] = mapped_column(String(64), primary_key=True, default=new_id)
    incident_id: Mapped[str] = mapped_column(String(64), ForeignKey("threat_incidents.id"), nullable=False)
    event_type: Mapped[str] = mapped_column(String(80), nullable=False)
    source: Mapped[str] = mapped_column(String(80), default="system", nullable=False)
    message: Mapped[str] = mapped_column(Text, nullable=False)
    risk_score: Mapped[int | None] = mapped_column(Integer)
    confidence: Mapped[float | None] = mapped_column(Float)
    frame_id: Mapped[int | None] = mapped_column(Integer)
    metadata_json: Mapped[str] = mapped_column(Text, default="{}", nullable=False)
    occurred_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, nullable=False)


class IncidentSignal(TenantMixin, Base):
    __tablename__ = "incident_signals"

    id: Mapped[str] = mapped_column(String(64), primary_key=True, default=new_id)
    incident_id: Mapped[str] = mapped_column(String(64), ForeignKey("threat_incidents.id"), nullable=False)
    signal_type: Mapped[str] = mapped_column(String(64), nullable=False)
    confidence: Mapped[float | None] = mapped_column(Float)
    frame_id: Mapped[int | None] = mapped_column(Integer)
    bbox_json: Mapped[str] = mapped_column(Text, default="[]", nullable=False)
    frame_hash: Mapped[str | None] = mapped_column(String(128))
    metadata_json: Mapped[str] = mapped_column(Text, default="{}", nullable=False)
    observed_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, nullable=False)


class RemediationAction(TenantMixin, Base):
    __tablename__ = "remediation_actions"

    id: Mapped[str] = mapped_column(String(64), primary_key=True, default=new_id)
    incident_id: Mapped[str] = mapped_column(String(64), nullable=False)
    action_type: Mapped[str] = mapped_column(String(80), nullable=False)
    status: Mapped[str] = mapped_column(String(32), default="PENDING", nullable=False)
    requested_by_user_id: Mapped[str | None] = mapped_column(String(64))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, nullable=False)


class AnalystNote(TenantMixin, Base):
    __tablename__ = "analyst_notes"

    id: Mapped[str] = mapped_column(String(64), primary_key=True, default=new_id)
    incident_id: Mapped[str] = mapped_column(String(64), ForeignKey("threat_incidents.id"), nullable=False)
    analyst_id: Mapped[str | None] = mapped_column(String(64))
    note: Mapped[str] = mapped_column(Text, nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, nullable=False)


class AuditRecord(TenantMixin, Base):
    __tablename__ = "audit_records"

    id: Mapped[str] = mapped_column(String(64), primary_key=True, default=new_id)
    actor_user_id: Mapped[str | None] = mapped_column(String(64))
    action: Mapped[str] = mapped_column(String(120), nullable=False)
    resource_type: Mapped[str] = mapped_column(String(80), nullable=False)
    resource_id: Mapped[str] = mapped_column(String(64), nullable=False)
    metadata_json: Mapped[str] = mapped_column(Text, default="{}", nullable=False)
    occurred_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, nullable=False)


class SubscriptionPlan(Base):
    __tablename__ = "subscription_plans"

    id: Mapped[str] = mapped_column(String(64), primary_key=True, default=new_id)
    code: Mapped[str] = mapped_column(String(64), unique=True, nullable=False)
    name: Mapped[str] = mapped_column(String(120), nullable=False)
    limits_json: Mapped[str] = mapped_column(Text, default="{}", nullable=False)
    features_json: Mapped[str] = mapped_column(Text, default="{}", nullable=False)


class UsageRecord(TenantMixin, Base):
    __tablename__ = "usage_records"

    id: Mapped[str] = mapped_column(String(64), primary_key=True, default=new_id)
    metric: Mapped[str] = mapped_column(String(80), nullable=False)
    quantity: Mapped[int] = mapped_column(Integer, nullable=False)
    period_start: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    period_end: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)


class Integration(TenantMixin, Base):
    __tablename__ = "integrations"

    id: Mapped[str] = mapped_column(String(64), primary_key=True, default=new_id)
    name: Mapped[str] = mapped_column(String(120), nullable=False)
    adapter_type: Mapped[str] = mapped_column(String(80), nullable=False)
    enabled: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    config_json: Mapped[str] = mapped_column(Text, default="{}", nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, nullable=False)
