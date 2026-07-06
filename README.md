# GlassWall AI

**Real-Time Optical Data Loss Prevention**

[Live frontend](https://aalimbaba.github.io/GlassWall-AI/) · [Repository](https://github.com/AalimBaba/GlassWall-AI)

GlassWall AI protects a sensitive dashboard from physical viewing risks. The local full system captures webcam frames in React, sends compressed JPEGs over a WebSocket, detects real faces with OpenCV, applies persistence thresholds in a FastAPI session, and returns `SECURE`, `WARNING`, or `LOCKDOWN`. The UI only blurs or locks from a real backend result or an explicit manual simulation.

> **GitHub Pages hosts the frontend demo. The real-time detection pipeline runs locally using the FastAPI backend because GitHub Pages cannot host Python inference services.**

## What works

- React + TypeScript + Vite security interface
- Real webcam preview using `getUserMedia`
- JPEG frame capture every 400 ms through a hidden canvas
- FastAPI WebSocket endpoint at `/ws/analyze`
- Real OpenCV Haar frontal-face detection with bounding boxes and detector scores
- One face = normal; a second face must persist 1.5 seconds for Warning and 3 seconds for Lockdown
- Two clear seconds before a threat returns to Secure, preventing state flicker
- Three-second cooldown after Reset
- Partial blur in Warning and full protection overlay in Lockdown
- Active detection list, threat timeline, security event log, backend status, and model status
- Explicit Simulation Mode with manual-only controls
- Static GitHub Pages deployment that truthfully reports an offline local backend

There are no random confidence values, fake startup alerts, automatic simulation timers, or hardcoded real-detection events.

## Detection honesty

### Implemented

- **Face / second-observer detection:** OpenCV's bundled `haarcascade_frontalface_default.xml`, executed by the local Python backend.
- **Temporal policy:** state is based on continuous evidence, not a single frame.
- **Real confidence display:** the UI receives a bounded score derived from OpenCV's actual cascade level weight. This is a detector score, not identity recognition or a calibrated probability.

### Not currently implemented

- **Phone/camera object detection:** no YOLO/COCO model file ships with the backend. The API returns `phone_model_loaded: false`, and the frontend displays **Phone model: not loaded**.
- **Face recognition or identity:** the system counts face regions; it does not identify people.
- **Gaze / side-face inference:** not claimed by the working detector.

Phone detection requires adding a YOLO/COCO model file. Until then, the backend will never fabricate a `PHONE` or `CAMERA` detection.

## Architecture

```text
Browser webcam
  → hidden canvas (480 px JPEG, quality 0.7)
  → WebSocket /ws/analyze every 400 ms
  → FastAPI connection session
  → OpenCV grayscale + Haar face cascade
  → per-session temporal threat engine
  → structured SECURE / WARNING / LOCKDOWN response
  → React blur, overlay, detections, timeline, and event log
```

```text
.
├── src/                         React frontend
│   ├── App.tsx                  webcam, WebSocket, state UI, simulation
│   └── styles.css               responsive enterprise interface
├── backend/
│   ├── app/
│   │   ├── main.py              FastAPI health + WebSocket service
│   │   ├── detector.py          real OpenCV frame decoding and face detection
│   │   ├── threat_engine.py     temporal SECURE/WARNING/LOCKDOWN policy
│   │   └── schemas.py           typed API contract
│   ├── tests/                   API and state-transition tests
│   ├── requirements.txt         runtime dependencies
│   └── requirements-dev.txt     test dependencies
├── geometry.py                  existing spatial reasoning core
├── interval_tree.py             existing augmented AVL interval tree
├── temporal_engine.py           existing signal-correlation engine
├── app/core/state_graph.py      existing general threat state graph
└── .github/workflows/deploy.yml GitHub Pages frontend deployment
```

## Run the full local system

Requirements:

- Node.js 20+
- Python 3.11+
- A webcam

### 1. Install dependencies

```bash
npm install
python -m pip install -r backend/requirements.txt
```

For backend tests, install `backend/requirements-dev.txt` instead.

### 2. Start the detection backend

From the repository root:

```bash
python -m uvicorn backend.app.main:app --host 127.0.0.1 --port 8000 --reload
```

Confirm [http://127.0.0.1:8000/health](http://127.0.0.1:8000/health) reports:

```json
{
  "status": "ok",
  "face_detector": "opencv-haar",
  "phone_model_loaded": false
}
```

### 3. Start the frontend

In a second terminal:

```bash
npm run dev
```

Open the URL printed by Vite, normally `http://localhost:5173`. Real Camera Mode connects to `ws://127.0.0.1:8000/ws/analyze`. Select **Start real camera** and approve webcam access.

To use another backend URL:

```bash
VITE_BACKEND_WS_URL=ws://192.168.1.10:8000/ws/analyze npm run dev
```

On PowerShell:

```powershell
$env:VITE_BACKEND_WS_URL='ws://192.168.1.10:8000/ws/analyze'
npm run dev
```

## State rules

| Evidence | Duration | Result |
| --- | ---: | --- |
| Zero or one face | Any | Secure |
| More than one face | Under 1.5 s | Secure |
| More than one face | 1.5–3.0 s | Warning + partial blur |
| More than one face | At least 3.0 s | Lockdown + full overlay |
| Qualifying evidence disappears | 2.0 s clear | Secure |
| Reset pressed | Immediate | Secure + 3.0 s cooldown |

Phone thresholds are implemented in the temporal engine for a future real detector: 1 second for Warning and 2 seconds for Lockdown. They cannot activate while the model is absent because no phone detections are generated.

## WebSocket contract

Client request:

```json
{
  "frame": "data:image/jpeg;base64,...",
  "timestamp": 1783350000000
}
```

Server response:

```json
{
  "state": "SECURE",
  "detections": [
    { "type": "FACE", "confidence": 0.87, "bbox": [42, 31, 96, 96] }
  ],
  "faces_count": 1,
  "phone_detected": false,
  "threat_reason": null,
  "action": "NONE",
  "timestamp": 1783350000000,
  "phone_model_loaded": false,
  "backend": "opencv-haar"
}
```

Reset the connection's temporal buffers with:

```json
{ "type": "reset", "timestamp": 1783350000000 }
```

## Modes

### Real Camera Mode (default)

- Attempts to connect to the local backend.
- Does not request camera permission until **Start real camera** is pressed.
- When the backend is offline, says: **Backend not connected. Real detection unavailable.**
- Does not fall back to fake or random results.

### Simulation Mode

- Clearly labeled **Simulation Mode — manual triggers only**.
- Does not access the camera or backend for detection.
- Provides Simulate Phone, Simulate Second Face, Simulate Lockdown, and Reset controls.
- Every generated log entry begins with `Simulation:`.

## Testing

```bash
npm run build
python -m pytest -q backend/tests
python -m pytest -q
```

The backend tests verify blank real image decoding produces no fake detections, malformed images are rejected, single faces remain Secure, brief second faces do not accumulate, the 1.5/3.0-second transitions work, and Reset clears temporal buffers.

## GitHub Pages

Pushes to `main` run `.github/workflows/deploy.yml`. It builds and deploys only the static frontend. On the public site, Real Camera Mode correctly reports the local backend as unavailable unless the visitor is deliberately running a compatible service. Simulation Mode remains available as the portfolio fallback.

## CV Project Description

**GlassWall AI — Real-Time Optical DLP Security Platform**

- Built a real-time Optical Data Loss Prevention prototype that streams webcam frames from React to FastAPI over WebSockets and protects sensitive UI from persistent unauthorized observers.
- Implemented real OpenCV face detection and a temporal security state engine with evidence persistence, clear-scene hysteresis, reset cooldown, and auditable Secure/Warning/Lockdown transitions.
- Delivered a responsive GitHub Pages portfolio frontend with honest backend-offline behavior, explicit manual simulation, typed detection contracts, automated deployment, and tested Python inference services.

Short version:

> GlassWall AI — real-time optical DLP prototype using React webcam capture, FastAPI WebSockets, OpenCV face detection, and temporal UI lockdown.

## Data and privacy

The local frontend sends webcam frames only to the configured WebSocket endpoint. The provided backend processes each frame in memory and does not persist images, identities, logs, or biometric templates. Dashboard values and identities are fictional demo data.
