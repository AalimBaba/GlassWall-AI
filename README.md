# GlassWall AI

**Zero-Trust Optical Data Loss Prevention for secure workspaces**

[Live demo](https://yourusername.github.io/glasswall-ai/) · [Repository](https://github.com/yourusername/glasswall-ai)

> Replace `yourusername` in the links above and in `src/App.tsx` before sharing the project.

GlassWall AI is a portfolio-grade security prototype focused on the analog gap in conventional DLP: sensitive information can still be photographed or viewed after it reaches a screen. The interactive frontend demonstrates how a confidential interface can react to a detected phone, unauthorized observer, or shoulder-surfing risk with immediate blur, warning, lockdown, confidence scoring, and local event logging.

The public GitHub Pages experience is deliberately a safe, deterministic simulation. It does not claim to run camera inference in the browser. The repository also contains real, unit-tested Python reasoning modules intended to sit behind future YOLO, MediaPipe, WebRTC, FastAPI, and Azure adapters.

## Live demo capabilities

- Responsive confidential enterprise dashboard with synthetic financial, access, customer-risk, alert, and compliance data
- Phone-camera, second-observer, and shoulder-surfing threat simulations
- Secure, Warning, and Lockdown states with immediate privacy blur
- Threat reason, confidence, timestamp, remediation, timeline, and reset flow
- Architecture, technology-status, feature, about, and CV portfolio sections
- Static build with no backend, camera, credentials, or Azure dependency

## Repository architecture

```text
.
├── src/                         React + TypeScript static demo
│   ├── App.tsx                  UI, simulator, dashboard, content
│   └── styles.css               Responsive visual system
├── app/core/
│   ├── state_graph.py           Dynamic threat state graph
│   └── *.py                     Compatibility exports for core modules
├── geometry.py                  Immutable 3D geometry primitives
├── spatial_engine.py            Gaze-to-screen intersection engine
├── interval_tree.py             Generic augmented AVL interval tree
├── temporal_engine.py           Multi-signal temporal correlation
├── models.py                    Threat domain models
├── test_*.py                    Python unit suite
├── glasswall-ai/                Preserved early FastAPI/Docker scaffold
└── .github/workflows/deploy.yml GitHub Pages deployment
```

### Implemented engineering modules

- **Spatial Threat Engine** — hand-built immutable vectors, rays, planes, and rectangles; evaluates whether a gaze ray intersects a protected screen region in O(1) per observer.
- **Temporal Interval Tree Analyzer** — thread-safe augmented AVL tree with O(log N) insertion and O(log N + K) overlap queries; correlates distinct signals without treating a single-frame detection as confirmed evidence.
- **Dynamic Threat State Machine** — validated and auditable transitions through secure, detection, warning, lockdown, recovery, and restored states.
- **Frontend threat simulator** — a dependency-free static runtime using React state to demonstrate response behavior safely.

Command-based remediation, stream strategies, actual CV workers, a production FastAPI service, and the Azure threat ledger are architecture-ready or planned integrations—not represented as implemented production systems.

## Technology status

| Area | Implemented | Architecture ready / planned |
| --- | --- | --- |
| Frontend | React, TypeScript, Vite, responsive CSS, static Pages export | WebRTC camera capture |
| Core | Python, 3D ray-casting, augmented AVL interval tree, state graph, thread-safe analysis | Command and strategy patterns, LRU inference cache |
| AI / API | — | OpenCV, MediaPipe Face Mesh, YOLO, FastAPI, WebSockets |
| Cloud | GitHub Pages workflow | Azure Container Apps, Event Grid, Functions, Cosmos DB |

The `glasswall-ai/` directory is an earlier backend scaffold preserved for reference. Several entries are extensionless placeholders and it is not required by the live demo. The tested reasoning core at the repository root is the authoritative current Python implementation.

## Run locally

Requirements: Node.js 20+ and npm.

```bash
npm install
npm run dev
```

Open the local URL printed by Vite. For a production-equivalent check:

```bash
npm run build
npm run preview
```

The optimized static output is generated in `dist/`.

## Run Python tests

Requirements: Python 3.11+.

```bash
python -m pip install -r requirements.txt
python -m pytest -v
```

The core runtime itself intentionally has no third-party dependency; the root requirements file contains test tooling only.

## Deploy to GitHub Pages

1. Create a GitHub repository and push this project with the default branch named `main`.
2. In **Settings → Pages**, select **GitHub Actions** as the source.
3. Replace the placeholder profile/repository URLs in `src/App.tsx` and this README.
4. Push to `main`, or run **Deploy to GitHub Pages** manually from the Actions tab.

The workflow installs from `package-lock.json`, runs the strict TypeScript production build, uploads `dist`, and deploys it with GitHub's official Pages actions. Vite uses relative asset paths, so both project Pages URLs and custom domains work without a repository-name edit.

## Detection pipeline

```text
Webcam / CCTV feed
  → local CV processing
  → YOLO device detection
  → MediaPipe face and gaze tracking
  → spatial ray-casting
  → temporal interval analysis
  → threat state machine
  → UI blur / lockdown
  → Azure threat logging
```

Only the reasoning core and frontend response simulator are currently implemented. The remaining stages show the intended integration boundary.

## CV Project Description

**GlassWall AI — Zero-Trust Optical DLP Security Platform**

- Built a full-stack zero-trust Optical Data Loss Prevention prototype that protects confidential dashboards from physical screen exfiltration risks such as smartphone photography and shoulder surfing.
- Designed a low-latency threat evaluation architecture using spatial ray-casting, temporal interval analysis, state-machine driven remediation, and modular computer-vision pipelines.
- Developed a recruiter-ready live web demo with simulated AI threat detection, real-time UI blur/lockdown, security event logging, and cloud-ready Azure threat ledger architecture.

Short version:

> GlassWall AI — AI-powered Optical DLP platform that detects physical screen-exfiltration threats and instantly blurs/locks sensitive enterprise dashboards.

## Security and data note

All dashboard identities, values, and events are fictional. The static demo requests no camera permission, stores no personal data, sends no telemetry, includes no secrets, and does not require cloud services.
