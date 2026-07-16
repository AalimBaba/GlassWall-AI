from __future__ import annotations

from contextlib import contextmanager
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Iterator
import json

from sqlalchemy import Engine, create_engine, inspect, select
from sqlalchemy import text
from sqlalchemy import func
from sqlalchemy.orm import Session, sessionmaker

from .saas_models import (
    AuditRecord,
    Base,
    Device,
    EndpointHealth,
    EndpointSession,
    AnalystNote,
    IncidentEvent,
    IncidentSeverity,
    IncidentSignal,
    IncidentStatus,
    Organization,
    ProtectionPolicy,
    ProtectionAction,
    ProtectedZone,
    RemediationAction,
    ThreatIncident,
    Workspace,
    ZoneSensitivity,
)
from .watermark import watermark_fingerprint


class TenantAccessError(PermissionError):
    pass


@dataclass(frozen=True, slots=True)
class HeartbeatInput:
    session_id: str
    workspace_id: str
    device_id: str
    user_id: str | None
    session_state: str
    camera_permission: bool
    backend_connected: bool
    model_loaded: bool
    inference_latency_ms: int
    latest_risk_score: int
    last_detection_at: datetime | None
    application_version: str


@dataclass(frozen=True, slots=True)
class EndpointHealthSnapshot:
    session_id: str
    workspace_id: str
    workspace_name: str | None
    device_id: str
    device_name: str | None
    state: str
    health: EndpointHealth
    latest_risk_score: int
    camera_permission: bool
    backend_connected: bool
    model_loaded: bool
    inference_latency_ms: int
    last_detection_at: datetime | None
    last_heartbeat_at: datetime | None
    application_version: str


@dataclass(frozen=True, slots=True)
class IncidentRecordInput:
    workspace_id: str
    device_id: str
    session_id: str
    state: str
    threat_type: str
    severity: str
    current_risk_score: int
    peak_risk_score: int
    phone_confidence: float | None = None
    face_count: int | None = None
    backend_connected: bool = False
    model_loaded: bool = False
    detection_duration_ms: int | None = None
    action: str | None = None
    message: str | None = None


class SaaSRepository:
    """Tenant-scoped repository boundary for the SaaS control plane."""

    def __init__(self, database_url: str = "sqlite:///./glasswall-dev.db", engine: Engine | None = None) -> None:
        self.engine = engine or create_engine(database_url, connect_args={"check_same_thread": False} if database_url.startswith("sqlite") else {})
        self.SessionLocal = sessionmaker(bind=self.engine, expire_on_commit=False)

    def create_schema(self) -> None:
        Base.metadata.create_all(self.engine)
        self._ensure_sqlite_incident_columns()
        self._ensure_sqlite_zone_columns()
        self._ensure_sqlite_policy_columns()

    def _ensure_sqlite_incident_columns(self) -> None:
        if self.engine.dialect.name != "sqlite":
            return
        inspector = inspect(self.engine)
        if "threat_incidents" not in inspector.get_table_names():
            return
        existing = {column["name"] for column in inspector.get_columns("threat_incidents")}
        incident_columns = {
            "state": "VARCHAR(32) NOT NULL DEFAULT 'WARNING'",
            "current_risk_score": "INTEGER NOT NULL DEFAULT 0",
            "detection_duration_ms": "INTEGER",
            "phone_confidence": "FLOAT",
            "face_count": "INTEGER",
            "backend_connected": "BOOLEAN NOT NULL DEFAULT 0",
            "model_loaded": "BOOLEAN NOT NULL DEFAULT 0",
            "resolution_reason": "TEXT",
            "created_at": "DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP",
            "updated_at": "DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP",
        }
        event_existing = {column["name"] for column in inspector.get_columns("incident_events")} if "incident_events" in inspector.get_table_names() else set()
        event_columns = {
            "source": "VARCHAR(80) NOT NULL DEFAULT 'system'",
            "confidence": "FLOAT",
            "frame_id": "INTEGER",
        }
        with self.engine.begin() as connection:
            for name, definition in incident_columns.items():
                if name not in existing:
                    connection.execute(text(f"ALTER TABLE threat_incidents ADD COLUMN {name} {definition}"))
            for name, definition in event_columns.items():
                if name not in event_existing:
                    connection.execute(text(f"ALTER TABLE incident_events ADD COLUMN {name} {definition}"))

    def _ensure_sqlite_zone_columns(self) -> None:
        if self.engine.dialect.name != "sqlite":
            return
        inspector = inspect(self.engine)
        if "protected_zones" not in inspector.get_table_names():
            return
        existing = {column["name"] for column in inspector.get_columns("protected_zones")}
        columns = {
            "description": "TEXT NOT NULL DEFAULT ''",
            "protection_action": "VARCHAR(32) NOT NULL DEFAULT 'BLUR'",
            "created_at": "DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP",
            "updated_at": "DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP",
        }
        with self.engine.begin() as connection:
            for name, definition in columns.items():
                if name not in existing:
                    connection.execute(text(f"ALTER TABLE protected_zones ADD COLUMN {name} {definition}"))

    def _ensure_sqlite_policy_columns(self) -> None:
        if self.engine.dialect.name != "sqlite":
            return
        inspector = inspect(self.engine)
        if "protection_policies" not in inspector.get_table_names():
            return
        existing = {column["name"] for column in inspector.get_columns("protection_policies")}
        columns = {
            "warning_threshold": "INTEGER NOT NULL DEFAULT 60",
            "lockdown_threshold": "INTEGER NOT NULL DEFAULT 80",
            "recovery_seconds": "INTEGER NOT NULL DEFAULT 2",
            "monitoring_required": "BOOLEAN NOT NULL DEFAULT 0",
            "watermark_mode": "VARCHAR(32) NOT NULL DEFAULT 'ON_THREAT'",
            "warning_default_action": "VARCHAR(32) NOT NULL DEFAULT 'BLUR'",
            "lockdown_default_action": "VARCHAR(32) NOT NULL DEFAULT 'HIDE'",
            "protect_high_zones_on_warning": "BOOLEAN NOT NULL DEFAULT 1",
            "protect_all_zones_on_lockdown": "BOOLEAN NOT NULL DEFAULT 1",
            "require_reauthentication_after_lockdown": "BOOLEAN NOT NULL DEFAULT 0",
            "created_at": "DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP",
            "updated_at": "DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP",
        }
        with self.engine.begin() as connection:
            for name, definition in columns.items():
                if name not in existing:
                    connection.execute(text(f"ALTER TABLE protection_policies ADD COLUMN {name} {definition}"))

    def ping(self) -> None:
        with self.engine.connect() as connection:
            connection.execute(text("SELECT 1"))

    @contextmanager
    def session_scope(self) -> Iterator[Session]:
        session = self.SessionLocal()
        try:
            yield session
            session.commit()
        except Exception:
            session.rollback()
            raise
        finally:
            session.close()

    def create_organization(self, name: str, slug: str) -> Organization:
        with self.session_scope() as session:
            org = Organization(name=name, slug=slug)
            session.add(org)
            session.flush()
            return org

    def create_workspace(self, organization_id: str, name: str, sensitivity: str = "standard") -> Workspace:
        with self.session_scope() as session:
            workspace = Workspace(organization_id=organization_id, name=name, sensitivity=sensitivity)
            session.add(workspace)
            session.flush()
            return workspace

    def get_workspace(self, organization_id: str, workspace_id: str) -> Workspace:
        with self.session_scope() as session:
            return self._tenant_get(session, Workspace, organization_id, workspace_id)

    def create_device(self, organization_id: str, display_name: str, device_key: str) -> Device:
        with self.session_scope() as session:
            device = Device(organization_id=organization_id, display_name=display_name, device_key=device_key)
            session.add(device)
            session.flush()
            return device

    def create_endpoint_session(
        self,
        organization_id: str,
        workspace_id: str,
        device_id: str,
        user_id: str | None = None,
    ) -> EndpointSession:
        with self.session_scope() as session:
            self._tenant_get(session, Workspace, organization_id, workspace_id)
            self._tenant_get(session, Device, organization_id, device_id)
            endpoint = EndpointSession(
                organization_id=organization_id,
                workspace_id=workspace_id,
                device_id=device_id,
                user_id=user_id,
            )
            session.add(endpoint)
            session.flush()
            return endpoint

    def record_heartbeat(self, organization_id: str, heartbeat: HeartbeatInput, at: datetime | None = None) -> EndpointHealthSnapshot:
        now = at or datetime.now(timezone.utc)
        with self.session_scope() as session:
            endpoint = self._tenant_get(session, EndpointSession, organization_id, heartbeat.session_id)
            if endpoint.workspace_id != heartbeat.workspace_id or endpoint.device_id != heartbeat.device_id:
                raise TenantAccessError("heartbeat does not match the registered endpoint session")
            endpoint.user_id = heartbeat.user_id
            endpoint.state = heartbeat.session_state
            endpoint.camera_permission = heartbeat.camera_permission
            endpoint.backend_connected = heartbeat.backend_connected
            endpoint.model_loaded = heartbeat.model_loaded
            endpoint.inference_latency_ms = max(0, heartbeat.inference_latency_ms)
            endpoint.latest_risk_score = min(100, max(0, heartbeat.latest_risk_score))
            endpoint.last_detection_at = heartbeat.last_detection_at
            endpoint.last_heartbeat_at = now
            endpoint.application_version = heartbeat.application_version
            self._sync_incident_for_heartbeat(session, organization_id, endpoint, heartbeat, now)
            return self._health_for(endpoint, now)

    def list_endpoint_health(
        self,
        organization_id: str,
        at: datetime | None = None,
        expiry_seconds: int = 60,
    ) -> list[EndpointHealthSnapshot]:
        now = at or datetime.now(timezone.utc)
        with self.session_scope() as session:
            if session.get(Organization, organization_id) is None:
                raise TenantAccessError("Organization is not available")
            endpoints = session.scalars(
                select(EndpointSession).where(EndpointSession.organization_id == organization_id)
            ).all()
            workspaces = {
                item.id: item.name
                for item in session.scalars(select(Workspace).where(Workspace.organization_id == organization_id)).all()
            }
            devices = {
                item.id: item.display_name
                for item in session.scalars(select(Device).where(Device.organization_id == organization_id)).all()
            }
            return [self._health_for(item, now, expiry_seconds, workspaces.get(item.workspace_id), devices.get(item.device_id)) for item in endpoints]

    def create_incident(
        self,
        organization_id: str,
        workspace_id: str,
        device_id: str,
        session_id: str,
        threat_type: str,
        severity: str,
        peak_risk_score: int,
    ) -> ThreatIncident:
        with self.session_scope() as session:
            self._tenant_get(session, Workspace, organization_id, workspace_id)
            self._tenant_get(session, Device, organization_id, device_id)
            self._tenant_get(session, EndpointSession, organization_id, session_id)
            incident = ThreatIncident(
                organization_id=organization_id,
                workspace_id=workspace_id,
                device_id=device_id,
                session_id=session_id,
                state="LOCKDOWN" if peak_risk_score >= 80 else "WARNING",
                threat_type=threat_type,
                severity=severity,
                peak_risk_score=min(100, max(0, peak_risk_score)),
                current_risk_score=min(100, max(0, peak_risk_score)),
            )
            session.add(incident)
            session.flush()
            return incident

    def add_incident_event(
        self,
        organization_id: str,
        incident_id: str,
        event_type: str,
        message: str,
        risk_score: int | None = None,
        source: str = "system",
        confidence: float | None = None,
        frame_id: int | None = None,
        metadata: dict[str, object] | None = None,
    ) -> IncidentEvent:
        with self.session_scope() as session:
            self._tenant_get(session, ThreatIncident, organization_id, incident_id)
            event = IncidentEvent(
                organization_id=organization_id,
                incident_id=incident_id,
                event_type=event_type,
                source=source,
                message=message,
                risk_score=risk_score,
                confidence=confidence,
                frame_id=frame_id,
                metadata_json=json.dumps(metadata or {}),
            )
            session.add(event)
            session.flush()
            return event

    def list_incidents(
        self,
        organization_id: str,
        status: str | None = None,
        severity: str | None = None,
        device_id: str | None = None,
        workspace_id: str | None = None,
        threat_type: str | None = None,
        limit: int = 50,
        offset: int = 0,
    ) -> list[ThreatIncident]:
        with self.session_scope() as session:
            if session.get(Organization, organization_id) is None:
                raise TenantAccessError("Organization is not available")
            query = select(ThreatIncident).where(ThreatIncident.organization_id == organization_id)
            if status:
                query = query.where(ThreatIncident.status == status)
            if severity:
                query = query.where(ThreatIncident.severity == severity)
            if device_id:
                query = query.where(ThreatIncident.device_id == device_id)
            if workspace_id:
                query = query.where(ThreatIncident.workspace_id == workspace_id)
            if threat_type:
                query = query.where(ThreatIncident.threat_type == threat_type)
            query = query.order_by(ThreatIncident.started_at.desc()).limit(max(1, min(limit, 100))).offset(max(0, offset))
            return list(session.scalars(query).all())

    def count_incidents(
        self,
        organization_id: str,
        status: str | None = None,
        severity: str | None = None,
        device_id: str | None = None,
        workspace_id: str | None = None,
        threat_type: str | None = None,
    ) -> int:
        with self.session_scope() as session:
            if session.get(Organization, organization_id) is None:
                raise TenantAccessError("Organization is not available")
            query = select(func.count()).select_from(ThreatIncident).where(ThreatIncident.organization_id == organization_id)
            if status:
                query = query.where(ThreatIncident.status == status)
            if severity:
                query = query.where(ThreatIncident.severity == severity)
            if device_id:
                query = query.where(ThreatIncident.device_id == device_id)
            if workspace_id:
                query = query.where(ThreatIncident.workspace_id == workspace_id)
            if threat_type:
                query = query.where(ThreatIncident.threat_type == threat_type)
            return int(session.scalar(query) or 0)

    def get_incident_detail(self, organization_id: str, incident_id: str) -> tuple[ThreatIncident, list[IncidentEvent], list[IncidentSignal], list[RemediationAction], list[AnalystNote]]:
        with self.session_scope() as session:
            incident = self._tenant_get(session, ThreatIncident, organization_id, incident_id)
            events = list(session.scalars(select(IncidentEvent).where(IncidentEvent.organization_id == organization_id, IncidentEvent.incident_id == incident_id).order_by(IncidentEvent.occurred_at.asc())).all())
            signals = list(session.scalars(select(IncidentSignal).where(IncidentSignal.organization_id == organization_id, IncidentSignal.incident_id == incident_id).order_by(IncidentSignal.observed_at.asc())).all())
            actions = list(session.scalars(select(RemediationAction).where(RemediationAction.organization_id == organization_id, RemediationAction.incident_id == incident_id).order_by(RemediationAction.created_at.asc())).all())
            notes = list(session.scalars(select(AnalystNote).where(AnalystNote.organization_id == organization_id, AnalystNote.incident_id == incident_id).order_by(AnalystNote.created_at.asc())).all())
            return incident, events, signals, actions, notes

    def update_incident_status(
        self,
        organization_id: str,
        incident_id: str,
        status: str,
        reason: str | None = None,
        analyst_id: str | None = None,
        at: datetime | None = None,
    ) -> ThreatIncident:
        now = at or datetime.now(timezone.utc)
        if status not in {item.value for item in IncidentStatus}:
            raise ValueError("unsupported incident status")
        with self.session_scope() as session:
            incident = self._tenant_get(session, ThreatIncident, organization_id, incident_id)
            incident.status = status
            incident.resolution_reason = reason
            incident.assigned_analyst_id = analyst_id or incident.assigned_analyst_id
            incident.updated_at = now
            if status in {IncidentStatus.RESOLVED.value, IncidentStatus.FALSE_POSITIVE.value, IncidentStatus.DISMISSED.value} and incident.ended_at is None:
                incident.ended_at = now
                incident.duration_ms = self._duration_ms(incident.started_at, now)
            session.add(IncidentEvent(
                organization_id=organization_id,
                incident_id=incident_id,
                event_type="status_changed",
                source="analyst",
                message=f"Incident status changed to {status}.",
                risk_score=incident.current_risk_score,
                metadata_json=json.dumps({"reason": reason, "analyst_id": analyst_id}),
            ))
            session.flush()
            return incident

    def add_analyst_note(
        self,
        organization_id: str,
        incident_id: str,
        note: str,
        analyst_id: str | None = None,
    ) -> AnalystNote:
        with self.session_scope() as session:
            self._tenant_get(session, ThreatIncident, organization_id, incident_id)
            record = AnalystNote(organization_id=organization_id, incident_id=incident_id, analyst_id=analyst_id, note=note)
            session.add(record)
            session.add(IncidentEvent(
                organization_id=organization_id,
                incident_id=incident_id,
                event_type="analyst_note_added",
                source="analyst",
                message="Analyst note added.",
                metadata_json=json.dumps({"analyst_id": analyst_id}),
            ))
            session.flush()
            return record

    def add_protected_zone(
        self,
        organization_id: str,
        workspace_id: str,
        name: str,
        relative_x: float,
        relative_y: float,
        relative_width: float,
        relative_height: float,
        sensitivity: str = ZoneSensitivity.HIGH.value,
        protection_action: str = ProtectionAction.BLUR.value,
        description: str = "",
        enabled: bool = True,
    ) -> ProtectedZone:
        with self.session_scope() as session:
            self._tenant_get(session, Workspace, organization_id, workspace_id)
            self._validate_zone(name, relative_x, relative_y, relative_width, relative_height, sensitivity, protection_action)
            zone = ProtectedZone(
                organization_id=organization_id,
                workspace_id=workspace_id,
                name=name,
                description=description,
                relative_x=relative_x,
                relative_y=relative_y,
                relative_width=relative_width,
                relative_height=relative_height,
                sensitivity=sensitivity,
                protection_action=protection_action,
                enabled=enabled,
            )
            session.add(zone)
            session.flush()
            return zone

    def list_protected_zones(self, organization_id: str, workspace_id: str) -> list[ProtectedZone]:
        with self.session_scope() as session:
            self._tenant_get(session, Workspace, organization_id, workspace_id)
            return list(session.scalars(
                select(ProtectedZone)
                .where(ProtectedZone.organization_id == organization_id, ProtectedZone.workspace_id == workspace_id)
                .order_by(ProtectedZone.created_at.asc())
            ).all())

    def update_protected_zone(
        self,
        organization_id: str,
        workspace_id: str,
        zone_id: str,
        updates: dict[str, object],
    ) -> ProtectedZone:
        with self.session_scope() as session:
            self._tenant_get(session, Workspace, organization_id, workspace_id)
            zone = self._tenant_get(session, ProtectedZone, organization_id, zone_id)
            if zone.workspace_id != workspace_id:
                raise TenantAccessError("ProtectedZone is not available in workspace scope")
            name = str(updates.get("name", zone.name))
            relative_x = float(updates.get("relative_x", zone.relative_x))
            relative_y = float(updates.get("relative_y", zone.relative_y))
            relative_width = float(updates.get("relative_width", zone.relative_width))
            relative_height = float(updates.get("relative_height", zone.relative_height))
            sensitivity = str(updates.get("sensitivity", zone.sensitivity))
            protection_action = str(updates.get("protection_action", zone.protection_action))
            self._validate_zone(name, relative_x, relative_y, relative_width, relative_height, sensitivity, protection_action)
            zone.name = name
            zone.description = str(updates.get("description", zone.description))
            zone.relative_x = relative_x
            zone.relative_y = relative_y
            zone.relative_width = relative_width
            zone.relative_height = relative_height
            zone.sensitivity = sensitivity
            zone.protection_action = protection_action
            zone.enabled = bool(updates.get("enabled", zone.enabled))
            zone.updated_at = datetime.now(timezone.utc)
            session.flush()
            return zone

    def delete_protected_zone(self, organization_id: str, workspace_id: str, zone_id: str) -> None:
        with self.session_scope() as session:
            self._tenant_get(session, Workspace, organization_id, workspace_id)
            zone = self._tenant_get(session, ProtectedZone, organization_id, zone_id)
            if zone.workspace_id != workspace_id:
                raise TenantAccessError("ProtectedZone is not available in workspace scope")
            session.delete(zone)

    def list_policies(self, organization_id: str, workspace_id: str | None = None) -> list[ProtectionPolicy]:
        with self.session_scope() as session:
            if session.get(Organization, organization_id) is None:
                raise TenantAccessError("Organization is not available")
            query = select(ProtectionPolicy).where(ProtectionPolicy.organization_id == organization_id)
            if workspace_id:
                self._tenant_get(session, Workspace, organization_id, workspace_id)
                query = query.where(ProtectionPolicy.workspace_id == workspace_id)
            return list(session.scalars(query.order_by(ProtectionPolicy.created_at.desc())).all())

    def create_policy_from_preset(self, organization_id: str, workspace_id: str, preset: str) -> ProtectionPolicy:
        config = policy_preset(preset)
        with self.session_scope() as session:
            self._tenant_get(session, Workspace, organization_id, workspace_id)
            policy = ProtectionPolicy(organization_id=organization_id, workspace_id=workspace_id, **config)
            session.add(policy)
            session.flush()
            return policy

    def update_policy(self, organization_id: str, policy_id: str, updates: dict[str, object]) -> ProtectionPolicy:
        with self.session_scope() as session:
            policy = self._tenant_get(session, ProtectionPolicy, organization_id, policy_id)
            for key in [
                "name", "enabled", "warning_threshold", "lockdown_threshold", "recovery_seconds", "monitoring_required",
                "watermark_mode", "warning_default_action", "lockdown_default_action", "protect_high_zones_on_warning",
                "protect_all_zones_on_lockdown", "require_reauthentication_after_lockdown",
            ]:
                if key in updates:
                    setattr(policy, key, updates[key])
            if policy.warning_threshold >= policy.lockdown_threshold:
                raise ValueError("warning threshold must be lower than lockdown threshold")
            policy.updated_at = datetime.now(timezone.utc)
            session.flush()
            return policy

    def admin_overview(self, organization_id: str, at: datetime | None = None, expiry_seconds: int = 60) -> dict[str, object]:
        with self.session_scope() as session:
            if session.get(Organization, organization_id) is None:
                raise TenantAccessError("Organization is not available")
        endpoints = self.list_endpoint_health(organization_id, at=at, expiry_seconds=expiry_seconds)
        incidents = self.list_incidents(organization_id)
        health_counts = {item.value: 0 for item in EndpointHealth}
        state_counts = {"SECURE": 0, "WARNING": 0, "LOCKDOWN": 0}
        for endpoint in endpoints:
            health_counts[endpoint.health.value] += 1
            if endpoint.state in state_counts:
                state_counts[endpoint.state] += 1
        open_incidents = sum(1 for item in incidents if item.status in {"OPEN", "INVESTIGATING"})
        return {
            "organization_id": organization_id,
            "endpoint_count": len(endpoints),
            "health_counts": health_counts,
            "state_counts": state_counts,
            "incident_count": len(incidents),
            "open_incident_count": open_incidents,
            "sample_data": False,
        }

    @staticmethod
    def _health_for(
        endpoint: EndpointSession,
        now: datetime,
        expiry_seconds: int = 60,
        workspace_name: str | None = None,
        device_name: str | None = None,
    ) -> EndpointHealthSnapshot:
        last_seen = endpoint.last_heartbeat_at
        if last_seen is not None and last_seen.tzinfo is None:
            last_seen = last_seen.replace(tzinfo=timezone.utc)
        last_detection = endpoint.last_detection_at
        if last_detection is not None and last_detection.tzinfo is None:
            last_detection = last_detection.replace(tzinfo=timezone.utc)
        if now.tzinfo is None:
            now = now.replace(tzinfo=timezone.utc)
        if last_seen is None or now - last_seen > timedelta(seconds=expiry_seconds):
            health = EndpointHealth.OFFLINE
        elif endpoint.state == "MONITORING_INTERRUPTED" or not endpoint.camera_permission or not endpoint.model_loaded:
            health = EndpointHealth.MONITORING_INTERRUPTED
        elif not endpoint.backend_connected:
            health = EndpointHealth.DEGRADED
        else:
            health = EndpointHealth.ONLINE
        return EndpointHealthSnapshot(
            session_id=endpoint.id,
            workspace_id=endpoint.workspace_id,
            workspace_name=workspace_name,
            device_id=endpoint.device_id,
            device_name=device_name,
            state=endpoint.state,
            health=health,
            latest_risk_score=endpoint.latest_risk_score,
            camera_permission=endpoint.camera_permission,
            backend_connected=endpoint.backend_connected,
            model_loaded=endpoint.model_loaded,
            inference_latency_ms=endpoint.inference_latency_ms,
            last_detection_at=last_detection,
            last_heartbeat_at=last_seen,
            application_version=endpoint.application_version,
        )

    @staticmethod
    def _tenant_get(session: Session, model: type, organization_id: str, record_id: str):
        record = session.get(model, record_id)
        if record is None or getattr(record, "organization_id", None) != organization_id:
            raise TenantAccessError(f"{model.__name__} is not available in organization scope")
        return record

    @staticmethod
    def _validate_zone(
        name: str,
        relative_x: float,
        relative_y: float,
        relative_width: float,
        relative_height: float,
        sensitivity: str,
        protection_action: str,
    ) -> None:
        if not name.strip():
            raise ValueError("zone name must not be empty")
        if sensitivity not in {item.value for item in ZoneSensitivity}:
            raise ValueError("unsupported zone sensitivity")
        if protection_action not in {item.value for item in ProtectionAction}:
            raise ValueError("unsupported protection action")
        if not (0 <= relative_x <= 1 and 0 <= relative_y <= 1):
            raise ValueError("zone origin must be between 0 and 1")
        if relative_width <= 0 or relative_height <= 0:
            raise ValueError("zone width and height must be greater than 0")
        if relative_x + relative_width > 1 or relative_y + relative_height > 1:
            raise ValueError("zone dimensions must stay inside the workspace")

    def _sync_incident_for_heartbeat(
        self,
        session: Session,
        organization_id: str,
        endpoint: EndpointSession,
        heartbeat: HeartbeatInput,
        now: datetime,
    ) -> None:
        state = heartbeat.session_state.upper()
        active = session.scalars(
            select(ThreatIncident).where(
                ThreatIncident.organization_id == organization_id,
                ThreatIncident.session_id == endpoint.id,
                ThreatIncident.ended_at.is_(None),
                ThreatIncident.status.in_([IncidentStatus.OPEN.value, IncidentStatus.INVESTIGATING.value]),
            ).order_by(ThreatIncident.started_at.desc())
        ).first()

        if state not in {"WARNING", "LOCKDOWN"}:
            if active is not None:
                active.ended_at = now
                active.duration_ms = self._duration_ms(active.started_at, now)
                active.current_risk_score = min(100, max(0, heartbeat.latest_risk_score))
                active.status = IncidentStatus.RESOLVED.value
                active.resolution_reason = "Endpoint returned to secure state."
                active.updated_at = now
                active.actions_json = json.dumps(["Recovery started", "Threat cleared"])
                session.add(IncidentEvent(
                    organization_id=organization_id,
                    incident_id=active.id,
                    event_type="threat_cleared",
                    source="heartbeat",
                    message="Endpoint returned to secure state; active threat window closed.",
                    risk_score=active.current_risk_score,
                    metadata_json=json.dumps({"session_state": heartbeat.session_state}),
                    occurred_at=now,
                ))
            return

        risk_score = min(100, max(0, heartbeat.latest_risk_score))
        severity = _severity_for_score(risk_score)
        if active is None:
            incident = ThreatIncident(
                organization_id=organization_id,
                workspace_id=endpoint.workspace_id,
                device_id=endpoint.device_id,
                session_id=endpoint.id,
                state=state,
                threat_type="OPTICAL_THREAT",
                severity=severity,
                peak_risk_score=risk_score,
                current_risk_score=risk_score,
                backend_connected=heartbeat.backend_connected,
                model_loaded=heartbeat.model_loaded,
                started_at=now,
                created_at=now,
                updated_at=now,
                actions_json=json.dumps(["Protected workspace state escalated" if state == "LOCKDOWN" else "Protected zones blurred"]),
            )
            session.add(incident)
            session.flush()
            fingerprint = watermark_fingerprint(organization_id, endpoint.workspace_id, endpoint.device_id, endpoint.id, incident.id, now)
            session.add(IncidentEvent(
                organization_id=organization_id,
                incident_id=incident.id,
                event_type="incident_opened",
                source="heartbeat",
                message=f"Endpoint reported {state}; incident opened from confirmed pipeline state.",
                risk_score=risk_score,
                metadata_json=json.dumps({
                    "session_state": state,
                    "backend_connected": heartbeat.backend_connected,
                    "model_loaded": heartbeat.model_loaded,
                    "watermark_active": True,
                    "watermark_fingerprint": fingerprint,
                    "watermark_policy": "session_tiled_metadata_only",
                    "watermark_state": state,
                    "watermark_activated_at": now.isoformat(),
                }),
                occurred_at=now,
            ))
            session.add(IncidentEvent(
                organization_id=organization_id,
                incident_id=incident.id,
                event_type="state_changed",
                source="state_coordinator",
                message=f"State changed to {state}.",
                risk_score=risk_score,
                metadata_json=json.dumps({"action": "LOCKDOWN" if state == "LOCKDOWN" else "BLUR", "watermark_fingerprint": fingerprint, "watermark_active": True}),
                occurred_at=now + timedelta(milliseconds=1),
            ))
            return

        previous_state = active.state
        previous_peak = active.peak_risk_score
        active.state = state
        active.current_risk_score = risk_score
        active.peak_risk_score = max(active.peak_risk_score, risk_score)
        active.severity = _severity_for_score(active.peak_risk_score)
        active.backend_connected = heartbeat.backend_connected
        active.model_loaded = heartbeat.model_loaded
        active.updated_at = now
        if state != previous_state:
            fingerprint = watermark_fingerprint(organization_id, endpoint.workspace_id, endpoint.device_id, endpoint.id, active.id, now)
            session.add(IncidentEvent(
                organization_id=organization_id,
                incident_id=active.id,
                event_type="state_changed",
                source="state_coordinator",
                message=f"State changed from {previous_state} to {state}.",
                risk_score=risk_score,
                metadata_json=json.dumps({"previous_state": previous_state, "state": state, "watermark_active": True, "watermark_fingerprint": fingerprint, "watermark_state": state, "watermark_activated_at": now.isoformat()}),
                occurred_at=now,
            ))
        if active.peak_risk_score != previous_peak:
            session.add(IncidentEvent(
                organization_id=organization_id,
                incident_id=active.id,
                event_type="risk_score_changed",
                source="risk_engine",
                message=f"Peak risk score reached {active.peak_risk_score}.",
                risk_score=active.peak_risk_score,
                metadata_json=json.dumps({"current_risk_score": risk_score}),
                occurred_at=now + timedelta(milliseconds=1),
            ))

    @staticmethod
    def _duration_ms(started_at: datetime, ended_at: datetime) -> int:
        if started_at.tzinfo is None:
            started_at = started_at.replace(tzinfo=timezone.utc)
        if ended_at.tzinfo is None:
            ended_at = ended_at.replace(tzinfo=timezone.utc)
        return max(0, int((ended_at - started_at).total_seconds() * 1000))


def _severity_for_score(score: int) -> str:
    if score >= 90:
        return IncidentSeverity.CRITICAL.value
    if score >= 60:
        return IncidentSeverity.HIGH.value
    if score >= 30:
        return IncidentSeverity.MEDIUM.value
    return IncidentSeverity.LOW.value


def policy_preset(name: str) -> dict[str, object]:
    presets: dict[str, dict[str, object]] = {
        "Standard Office": dict(name="Standard Office", warning_threshold=60, lockdown_threshold=82, recovery_seconds=2, monitoring_required=False, watermark_mode="ON_THREAT", warning_default_action="BLUR", lockdown_default_action="HIDE", protect_high_zones_on_warning=True, protect_all_zones_on_lockdown=True, require_reauthentication_after_lockdown=False),
        "Banking Operations": dict(name="Banking Operations", warning_threshold=55, lockdown_threshold=78, recovery_seconds=4, monitoring_required=True, watermark_mode="ALWAYS", warning_default_action="REDACT", lockdown_default_action="HIDE", protect_high_zones_on_warning=True, protect_all_zones_on_lockdown=True, require_reauthentication_after_lockdown=True),
        "Healthcare Records": dict(name="Healthcare Records", warning_threshold=58, lockdown_threshold=80, recovery_seconds=5, monitoring_required=True, watermark_mode="ALWAYS", warning_default_action="BLUR", lockdown_default_action="REDACT", protect_high_zones_on_warning=True, protect_all_zones_on_lockdown=True, require_reauthentication_after_lockdown=True),
        "Source-Code Cleanroom": dict(name="Source-Code Cleanroom", warning_threshold=50, lockdown_threshold=75, recovery_seconds=6, monitoring_required=True, watermark_mode="ALWAYS", warning_default_action="REDACT", lockdown_default_action="HIDE", protect_high_zones_on_warning=True, protect_all_zones_on_lockdown=True, require_reauthentication_after_lockdown=True),
        "Remote Contractor": dict(name="Remote Contractor", warning_threshold=55, lockdown_threshold=78, recovery_seconds=5, monitoring_required=True, watermark_mode="ALWAYS", warning_default_action="BLUR", lockdown_default_action="HIDE", protect_high_zones_on_warning=True, protect_all_zones_on_lockdown=True, require_reauthentication_after_lockdown=True),
        "Critical Restricted Workspace": dict(name="Critical Restricted Workspace", warning_threshold=45, lockdown_threshold=70, recovery_seconds=8, monitoring_required=True, watermark_mode="ALWAYS", warning_default_action="HIDE", lockdown_default_action="HIDE", protect_high_zones_on_warning=True, protect_all_zones_on_lockdown=True, require_reauthentication_after_lockdown=True),
    }
    if name not in presets:
        raise ValueError("unknown policy preset")
    return presets[name]


def audit_repository_action(
    repository: SaaSRepository,
    organization_id: str,
    action: str,
    resource_type: str,
    resource_id: str,
    actor_user_id: str | None = None,
) -> AuditRecord:
    with repository.session_scope() as session:
        record = AuditRecord(
            organization_id=organization_id,
            action=action,
            resource_type=resource_type,
            resource_id=resource_id,
            actor_user_id=actor_user_id,
        )
        session.add(record)
        session.flush()
        return record
