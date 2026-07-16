from __future__ import annotations

from datetime import datetime, timedelta, timezone
import json

import pytest
from sqlalchemy import create_engine
from sqlalchemy.pool import StaticPool

from backend.app.saas_models import EndpointHealth
from backend.app.saas_repository import HeartbeatInput, SaaSRepository, TenantAccessError, policy_preset


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


def test_confirmed_threat_heartbeat_creates_and_dedupes_incident(repo: SaaSRepository) -> None:
    org, workspace, device, session = make_endpoint(repo)
    now = datetime(2026, 7, 16, 12, 0, tzinfo=timezone.utc)
    warning = HeartbeatInput(session, workspace, device, None, "WARNING", True, True, True, 25, 67, now, "test")

    repo.record_heartbeat(org, warning, at=now)
    repo.record_heartbeat(org, warning, at=now + timedelta(seconds=1))

    incidents = repo.list_incidents(org)
    assert len(incidents) == 1
    assert incidents[0].status == "OPEN"
    assert incidents[0].severity == "HIGH"
    assert incidents[0].current_risk_score == 67
    _, events, *_ = repo.get_incident_detail(org, incidents[0].id)
    assert [event.event_type for event in events] == ["incident_opened", "state_changed"]
    metadata = json.loads(events[0].metadata_json)
    assert metadata["watermark_active"] is True
    assert len(metadata["watermark_fingerprint"]) == 64


def test_secure_heartbeat_does_not_create_incident(repo: SaaSRepository) -> None:
    org, workspace, device, session = make_endpoint(repo)
    now = datetime(2026, 7, 16, tzinfo=timezone.utc)
    repo.record_heartbeat(org, HeartbeatInput(session, workspace, device, None, "SECURE", True, True, True, 25, 8, None, "test"), at=now)
    assert repo.list_incidents(org) == []


def test_incident_escalation_and_resolution(repo: SaaSRepository) -> None:
    org, workspace, device, session = make_endpoint(repo)
    now = datetime(2026, 7, 16, 12, 0, tzinfo=timezone.utc)
    repo.record_heartbeat(org, HeartbeatInput(session, workspace, device, None, "WARNING", True, True, True, 25, 67, now, "test"), at=now)
    repo.record_heartbeat(org, HeartbeatInput(session, workspace, device, None, "LOCKDOWN", True, True, True, 30, 91, now, "test"), at=now + timedelta(seconds=2))
    incident = repo.list_incidents(org)[0]
    assert incident.state == "LOCKDOWN"
    assert incident.peak_risk_score == 91
    assert incident.severity == "CRITICAL"

    repo.record_heartbeat(org, HeartbeatInput(session, workspace, device, None, "SECURE", True, True, True, 20, 12, None, "test"), at=now + timedelta(seconds=5))
    closed = repo.list_incidents(org)[0]
    assert closed.ended_at is not None
    assert closed.status == "RESOLVED"
    assert closed.duration_ms == 5000
    _, events, *_ = repo.get_incident_detail(org, closed.id)
    assert [event.event_type for event in events] == ["incident_opened", "state_changed", "state_changed", "risk_score_changed", "threat_cleared"]


def test_incident_status_false_positive_and_notes(repo: SaaSRepository) -> None:
    org, workspace, device, session = make_endpoint(repo)
    incident = repo.create_incident(org, workspace, device, session, "PHONE", "HIGH", 72)
    updated = repo.update_incident_status(org, incident.id, "FALSE_POSITIVE", reason="Analyst reviewed metadata.", analyst_id="analyst-1")
    note = repo.add_analyst_note(org, incident.id, "Bounding box matched a desk phone.", analyst_id="analyst-1")

    assert updated.status == "FALSE_POSITIVE"
    assert updated.resolution_reason == "Analyst reviewed metadata."
    assert note.note == "Bounding box matched a desk phone."
    _, events, _, _, notes = repo.get_incident_detail(org, incident.id)
    assert events[-2].event_type == "status_changed"
    assert events[-1].event_type == "analyst_note_added"
    assert notes[0].analyst_id == "analyst-1"


def test_incident_filters_pagination_and_tenant_isolation(repo: SaaSRepository) -> None:
    org, workspace, device, session = make_endpoint(repo)
    other_org, other_workspace, other_device, other_session = make_endpoint(repo, "other-filter")
    repo.create_incident(org, workspace, device, session, "PHONE", "HIGH", 72)
    repo.create_incident(org, workspace, device, session, "OBSERVER", "LOW", 12)
    other_incident = repo.create_incident(other_org, other_workspace, other_device, other_session, "PHONE", "CRITICAL", 95)

    assert repo.count_incidents(org) == 2
    assert [item.threat_type for item in repo.list_incidents(org, severity="HIGH")] == ["PHONE"]
    assert len(repo.list_incidents(org, limit=1, offset=0)) == 1
    assert all(item.organization_id == org for item in repo.list_incidents(org))

    with pytest.raises(TenantAccessError):
        repo.get_incident_detail(org, other_incident.id)


def test_protected_zone_crud_and_validation(repo: SaaSRepository) -> None:
    org, workspace, *_ = make_endpoint(repo)
    zone = repo.add_protected_zone(
        org,
        workspace,
        name="Salary column",
        description="Sensitive compensation field",
        relative_x=0.1,
        relative_y=0.2,
        relative_width=0.3,
        relative_height=0.25,
        sensitivity="CRITICAL",
        protection_action="REDACT",
    )
    assert zone.relative_x == 0.1
    assert zone.protection_action == "REDACT"
    assert repo.list_protected_zones(org, workspace)[0].name == "Salary column"

    updated = repo.update_protected_zone(org, workspace, zone.id, {"relative_x": 0.2, "enabled": False, "protection_action": "HIDE"})
    assert updated.relative_x == 0.2
    assert updated.enabled is False
    assert updated.protection_action == "HIDE"

    with pytest.raises(ValueError):
        repo.add_protected_zone(org, workspace, "", 0.9, 0.1, 0.2, 0.2)
    with pytest.raises(ValueError):
        repo.update_protected_zone(org, workspace, zone.id, {"relative_width": 0})
    with pytest.raises(ValueError):
        repo.update_protected_zone(org, workspace, zone.id, {"relative_x": 0.9, "relative_width": 0.2})

    repo.delete_protected_zone(org, workspace, zone.id)
    assert repo.list_protected_zones(org, workspace) == []


def test_protected_zone_tenant_and_workspace_isolation(repo: SaaSRepository) -> None:
    org_a, workspace_a, *_ = make_endpoint(repo, "zone-a")
    org_b, workspace_b, *_ = make_endpoint(repo, "zone-b")
    zone = repo.add_protected_zone(org_a, workspace_a, "API key panel", 0.1, 0.1, 0.2, 0.2)

    with pytest.raises(TenantAccessError):
        repo.list_protected_zones(org_b, workspace_a)
    with pytest.raises(TenantAccessError):
        repo.update_protected_zone(org_b, workspace_a, zone.id, {"name": "leak"})
    with pytest.raises(TenantAccessError):
        repo.delete_protected_zone(org_a, workspace_b, zone.id)


def test_policy_presets_creation_update_and_isolation(repo: SaaSRepository) -> None:
    org, workspace, *_ = make_endpoint(repo, "policy-a")
    other_org, *_ = make_endpoint(repo, "policy-b")
    preset = policy_preset("Banking Operations")
    assert preset["monitoring_required"] is True
    policy = repo.create_policy_from_preset(org, workspace, "Banking Operations")
    assert policy.name == "Banking Operations"
    assert policy.workspace_id == workspace
    assert repo.list_policies(org, workspace)[0].id == policy.id

    updated = repo.update_policy(org, policy.id, {"warning_threshold": 50, "lockdown_threshold": 70, "enabled": False})
    assert updated.warning_threshold == 50
    assert updated.lockdown_threshold == 70
    assert updated.enabled is False

    with pytest.raises(ValueError):
        repo.update_policy(org, policy.id, {"warning_threshold": 80, "lockdown_threshold": 70})
    with pytest.raises(TenantAccessError):
        repo.update_policy(other_org, policy.id, {"enabled": True})
    with pytest.raises(ValueError):
        repo.create_policy_from_preset(org, workspace, "Imaginary Policy")
