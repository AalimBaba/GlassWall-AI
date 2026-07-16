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
