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


def test_protected_zone_api_crud_and_validation() -> None:
    engine = create_engine("sqlite://", connect_args={"check_same_thread": False}, poolclass=StaticPool)
    repo = SaaSRepository(engine=engine)
    repo.create_schema()
    main.saas_repo = repo

    org = repo.create_organization("Zones Tenant", "zones-tenant")
    workspace = repo.create_workspace(org.id, "Executive Dashboard")

    from fastapi.testclient import TestClient

    client = TestClient(main.app)
    created = client.post(
        f"/api/organizations/{org.id}/workspaces/{workspace.id}/zones",
        json={
            "name": "Revenue panel",
            "description": "Confidential revenue values",
            "relative_x": 0.1,
            "relative_y": 0.1,
            "relative_width": 0.3,
            "relative_height": 0.2,
            "sensitivity": "HIGH",
            "protection_action": "BLUR",
            "enabled": True,
        },
    )
    assert created.status_code == 200
    zone_id = created.json()["id"]
    assert created.json()["sample_data"] is False if "sample_data" in created.json() else True

    listed = client.get(f"/api/organizations/{org.id}/workspaces/{workspace.id}/zones")
    assert listed.status_code == 200
    assert listed.json()["zones"][0]["name"] == "Revenue panel"
    assert listed.json()["sample_data"] is False

    patched = client.patch(
        f"/api/organizations/{org.id}/workspaces/{workspace.id}/zones/{zone_id}",
        json={"relative_x": 0.2, "protection_action": "REDACT", "enabled": False},
    )
    assert patched.status_code == 200
    assert patched.json()["relative_x"] == 0.2
    assert patched.json()["protection_action"] == "REDACT"
    assert patched.json()["enabled"] is False

    invalid = client.post(
        f"/api/organizations/{org.id}/workspaces/{workspace.id}/zones",
        json={"name": "Bad", "relative_x": 0.9, "relative_y": 0.1, "relative_width": 0.2, "relative_height": 0.2},
    )
    assert invalid.status_code == 400

    deleted = client.delete(f"/api/organizations/{org.id}/workspaces/{workspace.id}/zones/{zone_id}")
    assert deleted.status_code == 200
    assert client.get(f"/api/organizations/{org.id}/workspaces/{workspace.id}/zones").json()["zones"] == []


def test_protected_zone_api_tenant_isolation() -> None:
    engine = create_engine("sqlite://", connect_args={"check_same_thread": False}, poolclass=StaticPool)
    repo = SaaSRepository(engine=engine)
    repo.create_schema()
    main.saas_repo = repo
    org_a = repo.create_organization("Zone A", "zone-a-api")
    workspace_a = repo.create_workspace(org_a.id, "A")
    org_b = repo.create_organization("Zone B", "zone-b-api")
    zone = repo.add_protected_zone(org_a.id, workspace_a.id, "Token panel", 0.1, 0.1, 0.2, 0.2)

    from fastapi.testclient import TestClient

    client = TestClient(main.app)
    response = client.get(f"/api/organizations/{org_b.id}/workspaces/{workspace_a.id}/zones")
    assert response.status_code == 404
    response = client.patch(f"/api/organizations/{org_b.id}/workspaces/{workspace_a.id}/zones/{zone.id}", json={"name": "bad"})
    assert response.status_code == 404
