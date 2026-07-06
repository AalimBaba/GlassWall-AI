import base64

import cv2
import numpy as np
from fastapi.testclient import TestClient

from backend.app.main import app, detector
from backend.app.schemas import Detection


client = TestClient(app)


def blank_jpeg() -> str:
    ok, encoded = cv2.imencode(".jpg", np.zeros((240, 320, 3), dtype=np.uint8))
    assert ok
    return base64.b64encode(encoded.tobytes()).decode()


def test_health_is_honest_about_phone_model() -> None:
    response = client.get("/health")
    assert response.status_code == 200
    assert response.json()["phone_model_loaded"] is False


def test_websocket_analyzes_real_image_without_fake_detection() -> None:
    with client.websocket_connect("/ws/analyze") as websocket:
        websocket.send_json({"frame": blank_jpeg(), "timestamp": 1000})
        result = websocket.receive_json()
    assert result["state"] == "SECURE"
    assert result["detections"] == []
    assert result["faces_count"] == 0
    assert result["phone_detected"] is False


def test_websocket_rejects_invalid_frame() -> None:
    with client.websocket_connect("/ws/analyze") as websocket:
        websocket.send_json({"frame": "not-base64", "timestamp": 1000})
        result = websocket.receive_json()
    assert "error" in result


def test_websocket_second_face_warning_and_lockdown(monkeypatch) -> None:
    faces = [
        Detection(type="FACE", confidence=0.91, bbox=(10, 10, 50, 50)),
        Detection(type="FACE", confidence=0.82, bbox=(100, 10, 50, 50)),
    ]
    monkeypatch.setattr(detector, "analyze", lambda _frame: faces)
    with client.websocket_connect("/ws/analyze") as websocket:
        states = []
        for timestamp in (10_000, 11_499, 11_500, 13_000):
            websocket.send_json({"frame": blank_jpeg(), "timestamp": timestamp})
            states.append(websocket.receive_json()["state"])
    assert states == ["SECURE", "SECURE", "WARNING", "LOCKDOWN"]
