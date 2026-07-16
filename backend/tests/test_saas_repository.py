from __future__ import annotations

from datetime import datetime, timedelta, timezone

import pytest
from sqlalchemy import create_engine
from sqlalchemy.pool import StaticPool

from backend.app.saas_models import EndpointHealth
from backend.app.saas_repository import HeartbeatInput, SaaSRepository, TenantAccessError


@pytest.fixture()
def repo() -> SaaSRepository:
    engine = create_engine("sqlite://", connect_args={"check_same_thread": False}, poolclass=StaticPool)
    repository = SaaSRepository(engine=engine)
    repository.create_schema()
    return repository


def make_endpoint(repo: SaaSRepository, slug: str = "acme") -> tuple[str, str, str, str]:
    org = repo.create_organization(f"{slug} org", slug)
    workspace = repo.create_workspace(org.id, "Finance Workspace", sensitivity="critical")
    device = repo.create_device(org.id, "Aalim Laptop", f"{slug}-device")
    endpoint = repo.create_endpoint_session(org.id, workspace.id, device.id)
    return org.id, workspace.id, device.id, endpoint.id


def test_repository_enforces_tenant_isolation(repo: SaaSRepository) -> None:
    org_a, workspace_a, device_a, session_a = make_endpoint(repo, "tenant-a")
    org_b, *_ = make_endpoint(repo, "tenant-b")

    assert repo.get_workspace(org_a, workspace_a).id == workspace_a
    with pytest.raises(TenantAccessError):
        repo.get_workspace(org_b, workspace_a)

    with pytest.raises(TenantAccessError):
        repo.create_incident(
            organization_id=org_b,
            workspace_id=workspace_a,
            device_id=device_a,
            session_id=session_a,
            threat_type="PHONE",
            severity="WARNING",
            peak_risk_score=70,
        )


def test_heartbeat_health_and_expiry(repo: SaaSRepository) -> None:
    org, workspace, device, session = make_endpoint(repo)
    now = datetime(2026, 7, 16, tzinfo=timezone.utc)

    online = repo.record_heartbeat(
        org,
        HeartbeatInput(
            session_id=session,
            workspace_id=workspace,
            device_id=device,
            user_id=None,
            session_state="SECURE",
            camera_permission=True,
            backend_connected=True,
            model_loaded=True,
            inference_latency_ms=42,
            latest_risk_score=12,
            last_detection_at=None,
            application_version="1.0.0",
        ),
        at=now,
    )
    assert online.health is EndpointHealth.ONLINE

    expired = repo.list_endpoint_health(org, at=now + timedelta(seconds=61))
    assert expired[0].health is EndpointHealth.OFFLINE


def test_incident_and_timeline_are_tenant_scoped(repo: SaaSRepository) -> None:
    org, workspace, device, session = make_endpoint(repo)
    other_org, *_ = make_endpoint(repo, "other")

    incident = repo.create_incident(org, workspace, device, session, "PHONE", "LOCKDOWN", 88)
    event = repo.add_incident_event(org, incident.id, "risk_score_changed", "Risk score reached Lockdown.", 88)
    assert event.incident_id == incident.id
    assert [item.id for item in repo.list_incidents(org)] == [incident.id]
    assert repo.list_incidents(other_org) == []

    with pytest.raises(TenantAccessError):
        repo.add_incident_event(other_org, incident.id, "bad_read", "Should not cross tenants.")
