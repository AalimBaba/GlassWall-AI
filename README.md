# GlassWall AI

**Real-Time Optical Data Loss Prevention**

[Live app](https://aalimbaba.github.io/GlassWall-AI/) · [Repository](https://github.com/AalimBaba/GlassWall-AI)

GlassWall AI protects sensitive dashboard content when an actual webcam frame contains a persistent smartphone or when a second face remains visible. It combines browser-side TensorFlow.js COCO-SSD phone detection with an optional local FastAPI/OpenCV face-counting backend. Warning, Lockdown, Recovery, and audit events are driven by real model output or clearly labeled manual simulation—never random values or hardcoded camera events.

## Deployment reality

- **GitHub Pages:** runs the full React UI, webcam preview, real browser-side phone inference, phone bounding boxes, temporal phone validation, DLP blur/lockdown, recovery, audit log, and manual simulation.
- **Hosted or local FastAPI backend:** adds WebSocket frame processing, OpenCV second-face detection, endpoint heartbeats, device inventory, and admin overview APIs.
- GitHub Pages cannot host Python. On the live site, phone protection works independently while face protection and Admin Console data are labeled offline/degraded unless a compatible HTTPS/WSS backend is configured.

## Real detection models

### Phone detection

- Model: TensorFlow.js COCO-SSD 2.2.3 with the MobileNet-v2 base.
- Inference: browser-side on actual `HTMLVideoElement` frames.
- Accepted classes: `cell phone`, `smartphone`, `mobile phone`, or `phone` (COCO emits `cell phone`).
- Threshold: 0.45, configurable in `src/phoneThreatTracker.ts`.
- Output: real model confidence and bounding box rendered over the mirrored camera preview.
- Model states: MODEL LOADING, MODEL READY, and MODEL ERROR. Camera start is disabled until the model is ready.

### Face detection

- Model: OpenCV's bundled `haarcascade_frontalface_default.xml`.
- Inference: local Python backend on JPEG frames received over `/ws/analyze`.
- Purpose: count face regions only. There is no identity recognition or biometric enrollment.
- Score: a bounded value derived from the cascade's real level weight; it is not a calibrated identity probability.

## Real-time inference pipeline

The Endpoint Protection client now uses a staged latest-frame pipeline rather than letting webcam capture, phone inference, backend frame encoding, and UI state updates all compete inside one callback.

```mermaid
flowchart LR
  Capture["Frame Capture<br/>10 FPS target"] --> Queue["Bounded Latest-Frame Queue<br/>capacity 1-2"]
  Queue --> Phone["Browser Phone Inference<br/>COCO-SSD single-flight"]
  Queue --> Face["Backend Face Inference<br/>FastAPI/OpenCV single-flight"]
  Phone --> Fusion["Detection Fusion<br/>stale result guard"]
  Face --> Fusion
  Fusion --> Temporal["Temporal Analysis<br/>phone/observer persistence"]
  Temporal --> Risk["Risk + State Coordinator"]
  Risk --> UI["UI Protection<br/>Observe/Warning/Lockdown/Recovery"]
  Risk --> Report["Heartbeat + Incident Reporting"]
```

Pipeline behavior:

- capture is capped at roughly 10 FPS;
- phone inference and backend face inference consume independent bounded queues;
- queue overflow uses latest-frame-wins and records dropped frames;
- COCO-SSD runs single-flight, so slow model calls cannot pile up;
- backend face analysis runs single-flight from the browser and CPU-bound OpenCV work is moved off the FastAPI event loop with `asyncio.to_thread()`;
- backend inference is bounded by a semaphore and reports dropped/busy frames instead of creating an unlimited backlog;
- stale backend results with older frame IDs are discarded;
- stopping monitoring aborts worker loops, clears queues, and resets metrics;
- browser-side phone detection continues when the backend is unavailable.

The live diagnostics panel reports real counters only:

- Capture FPS
- Phone Inference FPS
- Backend Inference FPS
- Average Phone Latency
- Average Face Latency
- Queue Depth
- Dropped Frames
- Stale Results Discarded
- Latest Processed Frame ID

The current WebSocket payload remains JSON/base64 for compatibility. A binary Blob/WebSocket transport would reduce encoding overhead and is documented as a future optimization, not claimed as implemented.

## Threat policy

The phone tracker requires three consecutive qualifying frames before starting its duration clock.

| Evidence | Duration | State / response |
| --- | ---: | --- |
| No confirmed threat | — | Secure |
| Phone ≥45%, fewer than 3 frames | — | Secure |
| Phone ≥45%, 3 frames confirmed | Under 1.5 s | Suspicious; no blur yet |
| Confirmed phone | 1.5–3.0 s | Warning; partial dashboard blur |
| Confirmed phone | At least 3.0 s | Lockdown; sensitive dashboard covered |
| Phone removed after protection | Under 2.0 s clear | Recovery; protection remains active |
| Phone removed | At least 2.0 s clear | Secure |
| More than one face | 1.5–3.0 s | Warning |
| More than one face | At least 3.0 s | Lockdown |
| Reset | Immediate | Secure; temporal buffers cleared |

The UI records metadata-only events with timestamp, transition, threat type, actual confidence, duration/state context, and response. Frames are not stored.

## Operational truth states

- MODEL LOADING
- PROTECTION ACTIVE
- DEGRADED PROTECTION
- MODEL ERROR
- CAMERA OFFLINE
- BACKEND OFFLINE (shown in runtime status)

The threat state (`SECURE`, `WARNING`, `LOCKDOWN`) is displayed separately from operational readiness. For example, camera-offline cannot masquerade as fully protected merely because no threat has been observed.

## Architecture

```text
Webcam video
  ├─→ COCO-SSD MobileNet-v2 in browser
  │     → real phone boxes/confidence
  │     → consecutive-frame + duration tracker
  │     → Warning / Lockdown / Recovery
  │
  └─→ hidden canvas JPEG every 400 ms (local full system)
        → FastAPI WebSocket /ws/analyze
        → OpenCV Haar face count
        → backend temporal policy
        → Warning / Lockdown

Combined strongest state
  → partial blur / full protection overlay
  → runtime detections + metadata audit log
```

```mermaid
flowchart LR
  Browser["Endpoint Protection Client<br/>React + webcam + COCO-SSD"] -->|optional WSS frames| FastAPI["FastAPI Backend<br/>OpenCV faces + SaaS APIs"]
  Browser -->|heartbeat metadata| Heartbeat["Endpoint Heartbeat API"]
  FastAPI --> Risk["Adaptive Risk Scoring"]
  Heartbeat --> Repo["Tenant-Scoped Repository<br/>SQLite local dev"]
  Risk --> Incidents["Threat Incidents + Timeline"]
  Repo --> Admin["Security Admin Console Data"]
```

```mermaid
flowchart TD
  Signal["Detection signal<br/>phone / observer / interruption"] --> Score["Risk scorer<br/>weighted + deterministic"]
  Score --> Guard["Temporal guard<br/>no single-frame lockdown"]
  Guard --> State{"Risk level"}
  State -->|0-29| Secure["SECURE"]
  State -->|30-59| Observe["OBSERVE"]
  State -->|60-79| Warning["WARNING<br/>blur protected zones"]
  State -->|80-100| Lockdown["LOCKDOWN<br/>obscure sensitive workspace"]
  Warning --> Ledger["Incident event metadata"]
  Lockdown --> Ledger
```

## SaaS control-plane slice

The backend now includes the first multi-tenant SaaS foundation:

- tenant-aware domain records for organizations, workspaces, users, roles, devices, endpoint sessions, policies, protected zones, detection signals, incidents, incident events, remediation actions, audit records, plans, usage records, and integrations;
- a SQLite/SQLAlchemy repository boundary that can be replaced later by PostgreSQL or Cosmos-backed repositories without moving business rules into route handlers;
- explicit tenant-scope checks for workspaces, devices, endpoint sessions, incidents, and incident events;
- endpoint heartbeat storage with health states: Online, Degraded, Monitoring Interrupted, and Offline;
- heartbeat expiry so endpoints do not stay online forever;
- admin overview data derived from stored endpoint and incident records, with `sample_data: false` unless explicitly seeded in a future demo workspace;
- deterministic adaptive risk scoring with explainable factor contributions, configurable weights, decay, hysteresis, and a guard against single-frame Lockdown.

## Admin Console

The React frontend now has separate product surfaces for **Overview**, **Endpoint Protection**, and **Devices**. The Admin Console is data-driven:

- Overview cards show total devices, online/degraded/offline devices, secure/warning/lockdown sessions, and open incidents from `GET /api/organizations/{organization_id}/admin/overview`.
- Devices shows endpoint inventory from `GET /api/organizations/{organization_id}/devices`.
- Device details show the stored organization, workspace, endpoint/session IDs, health, risk score, component status, inference latency, heartbeat time, and latest detection time.
- Incidents shows tenant-scoped incident counts, filters, persisted incident rows, and a metadata-only investigation drawer backed by `GET /api/organizations/{organization_id}/incidents`.
- Empty-state and backend-unconfigured screens are shown when there is no real control-plane data.
- Policies, Analytics, and Settings are intentionally labeled as not yet configured; no fake live activity is generated.

Endpoint Protection sends heartbeats only when a control-plane backend and endpoint identity are configured. Heartbeats include real browser/client values: session state, camera permission, phone-model readiness, backend connectivity, latest risk score, latest detection timestamp, inference latency, and application version. Heartbeat failures never stop browser-side phone detection.

Real incident persistence:

- WARNING or LOCKDOWN endpoint state opens a single active incident for the current threat window.
- Repeated heartbeats update the same active incident rather than creating one incident per frame or per heartbeat.
- LOCKDOWN escalation updates state, severity, current risk, peak risk, and timeline events.
- Returning to SECURE closes the active incident as resolved with a system recovery reason.
- Analyst actions can move incidents to INVESTIGATING, RESOLVED, FALSE_POSITIVE, or DISMISSED.
- Analyst notes are stored separately from timeline events.
- Evidence remains metadata-only by default; raw webcam frames are not persisted.

Incident APIs:

```text
GET  /api/organizations/{organization_id}/incidents
GET  /api/organizations/{organization_id}/incidents/{incident_id}
POST /api/organizations/{organization_id}/incidents/{incident_id}/status
POST /api/organizations/{organization_id}/incidents/{incident_id}/notes
```

```text
Endpoint Protection Client
  → Heartbeat API
  → Tenant Repository
  → Admin Overview API / Devices API
  → Admin Console
```

## CI/CD pipeline

GitHub Actions now separates validation from deployment:

```text
Frontend Install
  → Frontend Tests
  → TypeScript/Vite Build
  → Python Install
  → Python Tests
  → GitHub Pages Build
  → Deploy
```

The Pages deployment job depends on the test job, so the public frontend is not deployed unless both frontend and backend tests pass. Dependency caching is enabled for Node and Python package installs.

Environment variables:

```text
VITE_API_BASE_URL=https://your-fastapi-backend.example.com
VITE_WS_BASE_URL=wss://your-fastapi-backend.example.com
VITE_GLASSWALL_ORG_ID=<organization id>
VITE_GLASSWALL_WORKSPACE_ID=<workspace id>
VITE_GLASSWALL_DEVICE_ID=<device id>
VITE_GLASSWALL_SESSION_ID=<endpoint session id>
VITE_HEARTBEAT_INTERVAL_MS=15000
VITE_ADMIN_POLL_INTERVAL_MS=15000
```

`VITE_BACKEND_WS_URL` remains supported as a legacy exact-path override, but `VITE_WS_BASE_URL` is preferred because the client derives `/ws/analyze` consistently and can switch from `ws://` in development to `wss://` in production.

For local development, copy `.env.example` to `.env` and create matching development records through the repository layer or a future explicit seed command. The public GitHub Pages build intentionally does not include a localhost control-plane URL; without `VITE_API_BASE_URL`, the Admin Console reports that the backend is not configured while browser-side phone detection continues to work.

## Hosted FastAPI backend deployment

The repository includes a production Dockerfile at `backend/Dockerfile` and a Render blueprint at `render.yaml`. The default blueprint uses a small persistent disk mounted at `/data` and SQLite at `sqlite:////data/glasswall.db`, which is suitable for a low-cost prototype. For production scale, replace `DATABASE_URL` with managed PostgreSQL without changing the route layer.

Required backend environment variables:

```text
DATABASE_URL=sqlite:////data/glasswall.db
ALLOWED_ORIGINS=https://aalimbaba.github.io
JWT_SECRET=<generated secret>
ENVIRONMENT=production
LOG_LEVEL=INFO
MAX_FRAME_BYTES=2000000
HEARTBEAT_EXPIRY_SECONDS=60
```

Render setup:

1. Create a new Render Blueprint from this repository or create a Web Service using `backend/Dockerfile`.
2. Keep `healthCheckPath` set to `/ready`; `/health` is a lightweight runtime status endpoint, while `/ready` verifies database reachability.
3. Set `ALLOWED_ORIGINS` to the public Pages origin and any explicit preview origins you trust.
4. After Render provides an HTTPS URL, configure GitHub repository variables:

```text
VITE_API_BASE_URL=https://<render-service>.onrender.com
VITE_WS_BASE_URL=wss://<render-service>.onrender.com
VITE_GLASSWALL_ORG_ID=<organization id>
VITE_GLASSWALL_WORKSPACE_ID=<workspace id>
VITE_GLASSWALL_DEVICE_ID=<device id>
VITE_GLASSWALL_SESSION_ID=<endpoint session id>
```

The GitHub Pages workflow passes these repository variables into the production Vite build. If they are not set, the public frontend remains usable for browser-side phone detection and shows honest backend-unavailable states for Admin Console and face detection.

```mermaid
flowchart TB
  Org["Organization"] --> Workspace["Workspace"]
  Org --> User["User + Role"]
  Org --> Device["Device"]
  Workspace --> Session["EndpointSession"]
  Device --> Session
  Session --> Signal["DetectionSignal"]
  Session --> Incident["ThreatIncident"]
  Incident --> Event["IncidentEvent"]
  Incident --> Action["RemediationAction"]
  Org --> Audit["AuditRecord"]
  Org --> Usage["UsageRecord"]
  Org --> Integration["Integration"]
```

```mermaid
stateDiagram-v2
  [*] --> OPEN
  OPEN --> INVESTIGATING
  INVESTIGATING --> RESOLVED
  INVESTIGATING --> FALSE_POSITIVE
  OPEN --> DISMISSED
  RESOLVED --> [*]
  FALSE_POSITIVE --> [*]
  DISMISSED --> [*]
```

Relevant files:

```text
src/App.tsx                         Webcam, COCO inference, WebSocket, UI response
src/phoneThreatTracker.ts          Configurable phone temporal state machine
src/phoneThreatTracker.test.ts     One-frame, escalation, recovery, reset tests
backend/app/main.py                FastAPI health and WebSocket API
backend/app/detector.py            Real OpenCV image decoding and face detection
backend/app/threat_engine.py       Face/phone backend temporal policy
backend/app/schemas.py             Typed response contract
backend/app/risk_engine.py         Deterministic adaptive risk scoring
backend/app/saas_models.py         Tenant-aware SaaS domain model
backend/app/saas_repository.py     SQLite/SQLAlchemy tenant repository
backend/tests/                     API and backend state tests
.github/workflows/deploy.yml       GitHub Pages deployment
```

## Run the live/browser system

Requirements: Node.js 20+ and a webcam.

```bash
npm install
npm run dev
```

Open the Vite URL, wait for **MODEL READY**, choose Real Camera Mode, press **Start real camera**, and grant camera permission. Phone detection works without Python.

## Run the full local system

Requirements: Python 3.11+.

```bash
python -m pip install -r backend/requirements.txt
python -m uvicorn backend.app.main:app --host 127.0.0.1 --port 8000 --reload
```

In a second terminal:

```bash
npm run dev
```

In development, the frontend derives `ws://127.0.0.1:8000/ws/analyze` from `VITE_WS_BASE_URL` or its safe dev fallback. In production, no insecure localhost WebSocket is bundled. Set `VITE_WS_BASE_URL=wss://<hosted-backend>` when a hosted backend exists. Without that variable, the Pages app reports the face backend as unavailable while browser-side phone protection continues working.

Health endpoint: [http://127.0.0.1:8000/health](http://127.0.0.1:8000/health).
Readiness endpoint: [http://127.0.0.1:8000/ready](http://127.0.0.1:8000/ready).

Initial SaaS APIs:

- `POST /api/organizations/{organization_id}/heartbeats`
- `GET /api/organizations/{organization_id}/admin/overview`

These APIs require pre-existing organization/workspace/device/session records in the repository. Development seeding will be added as an explicit command in a later slice; the backend does not silently create fake tenants or fake endpoint activity.

## Modes

### Real Camera Mode

- Runs actual COCO-SSD phone inference.
- Uses the face backend when connected.
- Never replaces failed inference with simulation.
- Shows model errors and degraded/offline components explicitly.

### Simulation Mode

- Labeled **Simulation Mode — manual triggers only**.
- Manual buttons are disabled outside Simulation Mode.
- Every event begins with `Simulation:` and cannot contaminate real inference state.

## Test commands

```bash
npm run build
npx vitest run
python -m pytest -q backend/tests
python -m pytest -q
```

Automated coverage includes:

- one-frame phone evidence does not alert;
- confidence below 0.45 does not alert;
- three frames begin suspicious tracking;
- 1.5 seconds reaches Warning;
- 3 seconds reaches Lockdown;
- phone removal enters Recovery and requires 2 seconds clear;
- reset clears accumulated phone evidence;
- blank real images produce no fabricated backend detections;
- malformed frames are rejected;
- one face stays Secure;
- second-face Warning and Lockdown transitions work through the WebSocket contract.
- tenant isolation prevents cross-organization workspace, incident, and timeline access;
- endpoint heartbeat health expires to Offline;
- admin overview counts come from stored endpoint and incident records;
- risk scoring is deterministic, explainable, decays over time, uses hysteresis, and blocks single-frame Lockdown.
- latest-frame queues drop old frames instead of growing without bound;
- phone inference is single-flight;
- stale fused/backend results are rejected;
- diagnostics are derived from real counters;
- backend OpenCV inference runs off the async event loop and exposes frame-processing metrics.

## Mandatory real-camera test matrix

| Test | Expected |
| --- | --- |
| One person, no phone | One face locally; no phone; Secure |
| One person holding a prominent smartphone | Real phone box → Suspicious → Warning → Lockdown |
| Phone removed | Recovery for 2 seconds → Secure |
| Two people, no phone | Warning after 1.5 seconds; Lockdown after 3 seconds |
| Empty room | No fabricated phone or face detections |
| Random objects | No phone alert unless COCO-SSD returns a qualifying `cell phone` |
| Camera disabled | CAMERA OFFLINE |
| Phone model download fails | MODEL ERROR; camera start disabled |
| Face backend absent | DEGRADED PROTECTION; browser phone protection remains available |

## Known limitations

- COCO-SSD accuracy depends on lighting, camera quality, phone size, occlusion, and pose. It is not guaranteed to recognize every device.
- A 0.45 threshold favors recall for a prominently held phone but can still produce false positives; temporal confirmation reduces—not eliminates—them.
- Haar cascades can miss profiles, partially covered faces, or poor lighting.
- The live Pages app has no deployed Python face backend. Deploying FastAPI behind HTTPS/WSS is a separate infrastructure step.
- This is a portfolio prototype, not a certified or production-ready DLP control.

## Privacy

COCO-SSD processes video frames in the browser. When the optional local backend is connected, downscaled JPEGs are sent only to the configured WebSocket. The provided backend processes them in memory and stores no images, biometric templates, or identities. Audit events contain metadata only.

## CV Project Description

**GlassWall AI — Real-Time Optical DLP Security Prototype**

- Built a real-time optical DLP prototype using browser-side COCO-SSD smartphone detection, actual bounding boxes, confidence thresholds, and temporal Warning/Lockdown/Recovery controls.
- Integrated React webcam capture with a FastAPI WebSocket and OpenCV face-counting pipeline for persistent second-observer protection without face recognition.
- Implemented operational health states, metadata-only security audits, responsive UI protection, automated tests, and GitHub Pages deployment with honest degraded-mode reporting.

Short version:

> GlassWall AI — real-time optical DLP prototype using COCO-SSD phone detection, OpenCV face counting, temporal validation, and automatic sensitive-UI protection.
