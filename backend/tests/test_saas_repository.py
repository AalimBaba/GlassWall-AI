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


def test_heartbeat_update_and_degraded_status(repo: SaaSRepository) -> None:
    org, workspace, device, session = make_endpoint(repo)
    now = datetime(2026, 7, 16, tzinfo=timezone.utc)

    degraded = repo.record_heartbeat(
        org,
        HeartbeatInput(
            session_id=session,
            workspace_id=workspace,
            device_id=device,
            user_id=None,
            session_state="WARNING",
            camera_permission=True,
            backend_connected=False,
            model_loaded=True,
            inference_latency_ms=50,
            latest_risk_score=64,
            last_detection_at=now,
            application_version="1.0.1",
        ),
        at=now,
    )
    assert degraded.health is EndpointHealth.DEGRADED
    assert degraded.state == "WARNING"
    assert degraded.latest_risk_score == 64

    interrupted = repo.record_heartbeat(
        org,
        HeartbeatInput(
            session_id=session,
            workspace_id=workspace,
            device_id=device,
            user_id=None,
            session_state="MONITORING_INTERRUPTED",
            camera_permission=False,
            backend_connected=True,
            model_loaded=True,
            inference_latency_ms=10,
            latest_risk_score=55,
            last_detection_at=None,
            application_version="1.0.2",
        ),
        at=now + timedelta(seconds=5),
    )
    assert interrupted.health is EndpointHealth.MONITORING_INTERRUPTED
    assert interrupted.application_version == "1.0.2"


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


def test_zero_state_overview_and_invalid_org(repo: SaaSRepository) -> None:
    org = repo.create_organization("Empty Tenant", "empty")
    overview = repo.admin_overview(org.id)
    assert overview["endpoint_count"] == 0
    assert overview["open_incident_count"] == 0
    assert overview["state_counts"] == {"SECURE": 0, "WARNING": 0, "LOCKDOWN": 0}

    with pytest.raises(TenantAccessError):
        repo.admin_overview("missing-org")

    with pytest.raises(TenantAccessError):
        repo.list_endpoint_health("missing-org")
