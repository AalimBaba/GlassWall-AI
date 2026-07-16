from __future__ import annotations

from contextlib import contextmanager
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Iterator

from sqlalchemy import Engine, create_engine, select
from sqlalchemy.orm import Session, sessionmaker

from .saas_models import (
    AuditRecord,
    Base,
    Device,
    EndpointHealth,
    EndpointSession,
    IncidentEvent,
    Organization,
    ProtectedZone,
    ThreatIncident,
    Workspace,
)


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
    device_id: str
    state: str
    health: EndpointHealth
    latest_risk_score: int
    last_heartbeat_at: datetime | None
    application_version: str


class SaaSRepository:
    """Tenant-scoped repository boundary for the SaaS control plane."""

    def __init__(self, database_url: str = "sqlite:///./glasswall-dev.db", engine: Engine | None = None) -> None:
        self.engine = engine or create_engine(database_url, connect_args={"check_same_thread": False} if database_url.startswith("sqlite") else {})
        self.SessionLocal = sessionmaker(bind=self.engine, expire_on_commit=False)

    def create_schema(self) -> None:
        Base.metadata.create_all(self.engine)

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
            return self._health_for(endpoint, now)

    def list_endpoint_health(
        self,
        organization_id: str,
        at: datetime | None = None,
        expiry_seconds: int = 60,
    ) -> list[EndpointHealthSnapshot]:
        now = at or datetime.now(timezone.utc)
        with self.session_scope() as session:
            endpoints = session.scalars(
                select(EndpointSession).where(EndpointSession.organization_id == organization_id)
            ).all()
            return [self._health_for(item, now, expiry_seconds) for item in endpoints]

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
                threat_type=threat_type,
                severity=severity,
                peak_risk_score=min(100, max(0, peak_risk_score)),
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
    ) -> IncidentEvent:
        with self.session_scope() as session:
            self._tenant_get(session, ThreatIncident, organization_id, incident_id)
            event = IncidentEvent(
                organization_id=organization_id,
                incident_id=incident_id,
                event_type=event_type,
                message=message,
                risk_score=risk_score,
            )
            session.add(event)
            session.flush()
            return event

    def list_incidents(self, organization_id: str) -> list[ThreatIncident]:
        with self.session_scope() as session:
            return list(session.scalars(select(ThreatIncident).where(ThreatIncident.organization_id == organization_id)).all())

    def add_protected_zone(
        self,
        organization_id: str,
        workspace_id: str,
        name: str,
        x: float,
        y: float,
        width: float,
        height: float,
        sensitivity: str = "standard",
    ) -> ProtectedZone:
        with self.session_scope() as session:
            self._tenant_get(session, Workspace, organization_id, workspace_id)
            zone = ProtectedZone(
                organization_id=organization_id,
                workspace_id=workspace_id,
                name=name,
                x=x,
                y=y,
                width=width,
                height=height,
                sensitivity=sensitivity,
            )
            session.add(zone)
            session.flush()
            return zone

    def admin_overview(self, organization_id: str, at: datetime | None = None) -> dict[str, object]:
        endpoints = self.list_endpoint_health(organization_id, at=at)
        incidents = self.list_incidents(organization_id)
        health_counts = {item.value: 0 for item in EndpointHealth}
        for endpoint in endpoints:
            health_counts[endpoint.health.value] += 1
        open_incidents = sum(1 for item in incidents if item.status in {"OPEN", "INVESTIGATING"})
        return {
            "organization_id": organization_id,
            "endpoint_count": len(endpoints),
            "health_counts": health_counts,
            "incident_count": len(incidents),
            "open_incident_count": open_incidents,
            "sample_data": False,
        }

    @staticmethod
    def _health_for(endpoint: EndpointSession, now: datetime, expiry_seconds: int = 60) -> EndpointHealthSnapshot:
        last_seen = endpoint.last_heartbeat_at
        if last_seen is not None and last_seen.tzinfo is None:
            last_seen = last_seen.replace(tzinfo=timezone.utc)
        if now.tzinfo is None:
            now = now.replace(tzinfo=timezone.utc)
        if last_seen is None or now - last_seen > timedelta(seconds=expiry_seconds):
            health = EndpointHealth.OFFLINE
        elif endpoint.state == "MONITORING_INTERRUPTED" or not endpoint.camera_permission:
            health = EndpointHealth.MONITORING_INTERRUPTED
        elif not endpoint.backend_connected or not endpoint.model_loaded:
            health = EndpointHealth.DEGRADED
        else:
            health = EndpointHealth.ONLINE
        return EndpointHealthSnapshot(
            session_id=endpoint.id,
            workspace_id=endpoint.workspace_id,
            device_id=endpoint.device_id,
            state=endpoint.state,
            health=health,
            latest_risk_score=endpoint.latest_risk_score,
            last_heartbeat_at=endpoint.last_heartbeat_at,
            application_version=endpoint.application_version,
        )

    @staticmethod
    def _tenant_get(session: Session, model: type, organization_id: str, record_id: str):
        record = session.get(model, record_id)
        if record is None or getattr(record, "organization_id", None) != organization_id:
            raise TenantAccessError(f"{model.__name__} is not available in organization scope")
        return record


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
