from __future__ import annotations

from sqlalchemy import create_engine
from sqlalchemy.pool import StaticPool

from backend.app import main
from backend.app.saas_repository import SaaSRepository


def test_heartbeat_api_and_admin_overview_are_real_stored_state() -> None:
    engine = create_engine("sqlite://", connect_args={"check_same_thread": False}, poolclass=StaticPool)
    repo = SaaSRepository(engine=engine)
    repo.create_schema()
    main.saas_repo = repo

    org = repo.create_organization("API Tenant", "api-tenant")
    workspace = repo.create_workspace(org.id, "Cleanroom")
    device = repo.create_device(org.id, "Browser Endpoint", "endpoint-key")
    endpoint = repo.create_endpoint_session(org.id, workspace.id, device.id)

    response = main.app.router.routes  # keep module imported before TestClient binds app
    assert response

    from fastapi.testclient import TestClient

    client = TestClient(main.app)
    heartbeat = client.post(
        f"/api/organizations/{org.id}/heartbeats",
        json={
            "session_id": endpoint.id,
            "workspace_id": workspace.id,
            "device_id": device.id,
            "session_state": "SECURE",
            "camera_permission": True,
            "backend_connected": False,
            "model_loaded": True,
            "inference_latency_ms": 30,
            "latest_risk_score": 18,
            "application_version": "test",
        },
    )
    assert heartbeat.status_code == 200
    assert heartbeat.json()["health"] == "Degraded"

    overview = client.get(f"/api/organizations/{org.id}/admin/overview")
    assert overview.status_code == 200
    body = overview.json()
    assert body["sample_data"] is False
    assert body["endpoint_count"] == 1
    assert body["health_counts"]["Degraded"] == 1
    assert body["state_counts"]["SECURE"] == 1

    devices = client.get(f"/api/organizations/{org.id}/devices")
    assert devices.status_code == 200
    device_rows = devices.json()["devices"]
    assert len(device_rows) == 1
    assert device_rows[0]["device_name"] == "Browser Endpoint"
    assert device_rows[0]["workspace_name"] == "Cleanroom"
    assert device_rows[0]["backend_connected"] is False


def test_invalid_organization_returns_safe_404() -> None:
    from fastapi.testclient import TestClient

    client = TestClient(main.app)
    response = client.get("/api/organizations/not-real/admin/overview")
    assert response.status_code == 404


def test_incident_api_lists_filters_details_status_and_notes() -> None:
    engine = create_engine("sqlite://", connect_args={"check_same_thread": False}, poolclass=StaticPool)
    repo = SaaSRepository(engine=engine)
    repo.create_schema()
    main.saas_repo = repo

    org = repo.create_organization("Incident Tenant", "incident-tenant")
    workspace = repo.create_workspace(org.id, "Trading Desk")
    device = repo.create_device(org.id, "Analyst Workstation", "incident-device")
    endpoint = repo.create_endpoint_session(org.id, workspace.id, device.id)
    incident = repo.create_incident(org.id, workspace.id, device.id, endpoint.id, "PHONE", "HIGH", 77)
    repo.add_incident_event(org.id, incident.id, "phone_persisted", "Phone persisted beyond temporal threshold.", 77)

    from fastapi.testclient import TestClient

    client = TestClient(main.app)
    listed = client.get(f"/api/organizations/{org.id}/incidents", params={"severity": "HIGH", "limit": 10, "offset": 0})
    assert listed.status_code == 200
    assert listed.json()["total"] == 1
    assert listed.json()["incidents"][0]["id"] == incident.id
    assert listed.json()["sample_data"] is False

    detail = client.get(f"/api/organizations/{org.id}/incidents/{incident.id}")
    assert detail.status_code == 200
    assert [event["event_type"] for event in detail.json()["events"]] == ["phone_persisted"]

    status = client.post(
        f"/api/organizations/{org.id}/incidents/{incident.id}/status",
        json={"status": "INVESTIGATING", "reason": "Assigned for review", "analyst_id": "analyst-1"},
    )
    assert status.status_code == 200
    assert status.json()["status"] == "INVESTIGATING"
    assert status.json()["assigned_analyst_id"] == "analyst-1"

    note = client.post(
        f"/api/organizations/{org.id}/incidents/{incident.id}/notes",
        json={"note": "Reviewing metadata only.", "analyst_id": "analyst-1"},
    )
    assert note.status_code == 200
    assert note.json()["analyst_notes"][0]["note"] == "Reviewing metadata only."


def test_incident_api_enforces_tenant_isolation() -> None:
    engine = create_engine("sqlite://", connect_args={"check_same_thread": False}, poolclass=StaticPool)
    repo = SaaSRepository(engine=engine)
    repo.create_schema()
    main.saas_repo = repo

    org_a = repo.create_organization("A", "a")
    workspace_a = repo.create_workspace(org_a.id, "A Workspace")
    device_a = repo.create_device(org_a.id, "A Device", "a-device")
    session_a = repo.create_endpoint_session(org_a.id, workspace_a.id, device_a.id)
    incident = repo.create_incident(org_a.id, workspace_a.id, device_a.id, session_a.id, "PHONE", "HIGH", 72)
    org_b = repo.create_organization("B", "b")

    from fastapi.testclient import TestClient

    client = TestClient(main.app)
    response = client.get(f"/api/organizations/{org_b.id}/incidents/{incident.id}")
    assert response.status_code == 404
