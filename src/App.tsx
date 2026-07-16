import { useEffect, useRef, useState } from 'react'
import {
  Activity, ArrowRight, Blocks, BrainCircuit, Camera, Check, ChevronRight, CircleDollarSign,
  Cloud, Code2, Database, Eye, Fingerprint, Globe2, KeyRound, LockKeyhole, Menu,
  Network, Radio, RefreshCw, ScanFace, Shield, ShieldAlert, ShieldCheck, Smartphone,
  Terminal, TriangleAlert, UserRoundX, Users, Workflow, X, Zap
} from 'lucide-react'
import type { DetectedObject, ObjectDetection } from '@tensorflow-models/coco-ssd'
import { PHONE_POLICY, PhoneThreatTracker, type PhoneTrackerSnapshot } from './phoneThreatTracker'

type Threat = { mode: 'Warning' | 'Lockdown'; reason: string; detail: string; confidence: number; action: string; icon: typeof Smartphone }
type Event = { id: number; title: string; time: string; confidence?: number; action: string; mode: string }
type DetectionMode = 'real' | 'simulation'
type CameraState = 'off' | 'requesting' | 'scanning' | 'error'
type BackendState = 'connecting' | 'connected' | 'offline'
type ModelState = 'loading' | 'ready' | 'error'
type BackendDetection = { type: 'FACE' | 'PHONE' | 'CAMERA'; confidence: number; bbox: [number, number, number, number] }
type AnalysisResult = { state: 'SECURE' | 'WARNING' | 'LOCKDOWN'; detections: BackendDetection[]; faces_count: number; phone_detected: boolean; threat_reason: string | null; action: 'NONE' | 'BLUR' | 'LOCKDOWN'; timestamp: number; phone_model_loaded: boolean; error?: string }

const LINKS = {
  github: 'https://github.com/AalimBaba/GlassWall-AI',
  portfolio: 'https://yourportfolio.example.com',
}

const threats: Record<string, Threat> = {
  phone: { mode: 'Warning', reason: 'Simulated phone threat', detail: 'User manually triggered a phone-camera scenario.', confidence: 90, action: 'Privacy blur enabled', icon: Smartphone },
  observer: { mode: 'Warning', reason: 'Simulated second face', detail: 'User manually triggered a second-observer scenario.', confidence: 90, action: 'Privacy blur enabled', icon: UserRoundX },
  shoulder: { mode: 'Lockdown', reason: 'Simulated lockdown', detail: 'User manually triggered a full-lockdown scenario.', confidence: 95, action: 'Sensitive data obscured', icon: LockKeyhole },
}

const features = [
  ['Physical DLP concept', 'Closes the analog gap that traditional file monitoring cannot see.', Eye],
  ['Instant UI protection', 'Blurs protected content at the moment a risk crosses policy thresholds.', ShieldAlert],
  ['Multi-signal evaluation', 'Correlates device, face, gaze, spatial, and temporal evidence.', BrainCircuit],
  ['Auditable threat states', 'Makes every transition from secure to lockdown explicit and traceable.', Workflow],
  ['Modular inference design', 'Separates capture, detection, reasoning, remediation, and logging.', Blocks],
  ['Cloud-ready pipeline', 'Designed for event-driven Azure ingestion without coupling the demo.', Cloud],
]

const modules = [
  ['01', 'Spatial Threat Engine', 'Projects an observer’s gaze ray into a sensitive screen plane and evaluates intersection geometry.', 'Implemented · Python'],
  ['02', 'Temporal Interval Analyzer', 'Uses an augmented AVL interval tree to correlate independent signals across time windows.', 'Implemented · Python'],
  ['03', 'Dynamic Threat State Machine', 'Controls validated movement through secure, warning, lockdown, and recovery states.', 'Implemented · Python'],
  ['04', 'FastAPI Frame Service', 'Receives compressed JPEG frames over WebSocket and returns a structured detection contract.', 'Implemented · Python'],
  ['05', 'OpenCV Face Detector', 'Runs the bundled frontal-face cascade and reports actual face boxes and detector scores.', 'Implemented · Python'],
  ['06', 'Browser Phone Detector', 'Runs MobileNet-v2 COCO-SSD on live webcam frames and validates the cell phone class over time.', 'Implemented · TensorFlow.js'],
]

function now() { return new Date().toLocaleTimeString([], { hour: '2-digit', minute: '2-digit', second: '2-digit' }) }

let phoneModelPromise: Promise<ObjectDetection> | null = null
function getPhoneModel() {
  phoneModelPromise ??= Promise.all([import('@tensorflow/tfjs'), import('@tensorflow-models/coco-ssd')]).then(async ([tf, cocoSsd]) => {
    await tf.ready()
    return cocoSsd.load({ base: 'mobilenet_v2' })
  })
  return phoneModelPromise
}

export default function App() {
  const [active, setActive] = useState<Threat | null>(null)
  const [events, setEvents] = useState<Event[]>([{ id: 1, title: 'Session initialized', time: now(), action: 'Secure — no active threat', mode: 'Secure' }])
  const [menu, setMenu] = useState(false)
  const [detectionMode, setDetectionMode] = useState<DetectionMode>('real')
  const [backendState, setBackendState] = useState<BackendState>('connecting')
  const [cameraState, setCameraState] = useState<CameraState>('off')
  const [cameraMessage, setCameraMessage] = useState('Camera inactive — no threat detected')
  const [detections, setDetections] = useState<BackendDetection[]>([])
  const [phoneModelState, setPhoneModelState] = useState<ModelState>('loading')
  const [phoneModelError, setPhoneModelError] = useState('')
  const [phoneDetections, setPhoneDetections] = useState<DetectedObject[]>([])
  const [phoneSnapshot, setPhoneSnapshot] = useState<PhoneTrackerSnapshot>({ state: 'SECURE', durationMs: 0, confidence: 0, confirmed: false })
  const [backendAnalysis, setBackendAnalysis] = useState<AnalysisResult | null>(null)
  const [inferenceFps, setInferenceFps] = useState(0)
  const videoRef = useRef<HTMLVideoElement>(null)
  const canvasRef = useRef<HTMLCanvasElement>(null)
  const streamRef = useRef<MediaStream | null>(null)
  const socketRef = useRef<WebSocket | null>(null)
  const phoneModelRef = useRef<ObjectDetection | null>(null)
  const phoneTrackerRef = useRef(new PhoneThreatTracker())
  const phoneInferenceBusyRef = useRef(false)
  const phoneLastFrameAtRef = useRef(0)
  const phoneLastStateRef = useRef<PhoneTrackerSnapshot['state']>('SECURE')
  const phoneProtectionRef = useRef<'Warning' | 'Lockdown' | null>(null)
  const phoneLastConfidenceRef = useRef(0)
  const frameTimerRef = useRef<number | null>(null)
  const awaitingResultRef = useRef(false)
  const lastBackendStateRef = useRef<'SECURE' | 'WARNING' | 'LOCKDOWN'>('SECURE')
  const backendUrl = import.meta.env.VITE_BACKEND_WS_URL || (import.meta.env.DEV ? 'ws://127.0.0.1:8000/ws/analyze' : '')

  const simulate = (key: keyof typeof threats) => {
    if (detectionMode !== 'simulation') return
    const threat = threats[key]
    setActive(threat)
    setEvents(old => [{ id: Date.now(), title: `Simulation: ${key} threat triggered by user`, time: now(), confidence: threat.confidence, action: threat.action, mode: threat.mode }, ...old].slice(0, 6))
    document.getElementById('demo')?.scrollIntoView({ behavior: 'smooth', block: 'start' })
  }
  const reset = () => {
    setActive(null)
    setDetections([])
    setPhoneDetections([])
    setPhoneSnapshot(phoneTrackerRef.current.reset())
    phoneLastStateRef.current = 'SECURE'
    phoneProtectionRef.current = null
    lastBackendStateRef.current = 'SECURE'
    if (socketRef.current?.readyState === WebSocket.OPEN) socketRef.current.send(JSON.stringify({ type: 'reset', timestamp: Date.now() }))
    setEvents(old => [{ id: Date.now(), title: 'Session reset', time: now(), action: 'Returned to secure state; 3s cooldown active', mode: 'Secure' }, ...old].slice(0, 6))
    if (cameraState === 'scanning') setCameraMessage('Camera active — no threat detected')
  }

  const stopCamera = () => {
    if (frameTimerRef.current) window.clearInterval(frameTimerRef.current)
    frameTimerRef.current = null
    streamRef.current?.getTracks().forEach(track => track.stop())
    streamRef.current = null
    awaitingResultRef.current = false
    setCameraState('off')
    setCameraMessage('Camera not analyzed yet')
    setDetections([])
    setPhoneDetections([])
    setPhoneSnapshot(phoneTrackerRef.current.reset())
    phoneProtectionRef.current = null
  }

  const runPhoneDetection = async () => {
    const video = videoRef.current
    const model = phoneModelRef.current
    if (!video || !model || video.readyState < 2 || phoneInferenceBusyRef.current) return
    phoneInferenceBusyRef.current = true
    const startedAt = performance.now()
    try {
      const predictions = await model.detect(video, 20, PHONE_POLICY.confidenceThreshold)
      const phones = predictions.filter(item => /cell phone|smartphone|mobile phone|phone/i.test(item.class))
      setPhoneDetections(phones)
      const highest = Math.max(0, ...phones.map(item => item.score))
      if (highest > 0) phoneLastConfidenceRef.current = highest
      const timestamp = Date.now()
      const snapshot = phoneTrackerRef.current.update(phones.length > 0, highest, timestamp)
      setPhoneSnapshot(snapshot)
      const elapsed = performance.now() - startedAt
      const sinceLast = phoneLastFrameAtRef.current ? startedAt - phoneLastFrameAtRef.current : elapsed
      phoneLastFrameAtRef.current = startedAt
      setInferenceFps(Math.round(10000 / Math.max(elapsed, sinceLast)) / 10)

      if (snapshot.state === 'WARNING') phoneProtectionRef.current = 'Warning'
      if (snapshot.state === 'LOCKDOWN') phoneProtectionRef.current = 'Lockdown'
      if (snapshot.state === 'SECURE') phoneProtectionRef.current = null
      if (snapshot.state !== phoneLastStateRef.current && ['WARNING', 'LOCKDOWN', 'RECOVERY', 'SECURE'].includes(snapshot.state)) {
        const transition = `${phoneLastStateRef.current} → ${snapshot.state}`
        setEvents(old => [{ id: timestamp, title: `Real detection: phone ${transition}`, time: now(), confidence: highest ? Math.round(highest * 100) : undefined, action: snapshot.state === 'LOCKDOWN' ? 'Sensitive data obscured' : snapshot.state === 'WARNING' ? 'Privacy blur enabled' : snapshot.state === 'RECOVERY' ? 'Protection held during recovery' : 'Returned to secure', mode: snapshot.state === 'LOCKDOWN' ? 'Lockdown' : snapshot.state === 'WARNING' || snapshot.state === 'RECOVERY' ? 'Warning' : 'Secure' }, ...old].slice(0, 10))
      }
      phoneLastStateRef.current = snapshot.state
    } catch (error) {
      setPhoneModelState('error')
      setPhoneModelError(error instanceof Error ? error.message : 'Phone inference failed')
    } finally {
      phoneInferenceBusyRef.current = false
    }
  }

  const sendFrame = () => {
    const video = videoRef.current
    const canvas = canvasRef.current
    const socket = socketRef.current
    if (!video || !canvas || video.readyState < 2) return
    void runPhoneDetection()
    if (!socket || socket.readyState !== WebSocket.OPEN || awaitingResultRef.current) return
    canvas.width = 480
    canvas.height = Math.round(480 * video.videoHeight / video.videoWidth) || 360
    const context = canvas.getContext('2d')
    if (!context) return
    context.drawImage(video, 0, 0, canvas.width, canvas.height)
    awaitingResultRef.current = true
    socket.send(JSON.stringify({ frame: canvas.toDataURL('image/jpeg', .7), timestamp: Date.now() }))
  }

  const startCamera = async () => {
    stopCamera()
    setDetectionMode('real')
    if (phoneModelState !== 'ready') { setCameraState('error'); setCameraMessage(phoneModelState === 'loading' ? 'Phone model is still loading.' : 'Phone model failed to load. Real phone detection unavailable.'); return }
    setCameraState('requesting')
    setCameraMessage('Waiting for webcam permission…')
    try {
      const stream = await navigator.mediaDevices.getUserMedia({ video: { facingMode: 'user', width: { ideal: 640 }, height: { ideal: 480 } }, audio: false })
      streamRef.current = stream
      if (videoRef.current) { videoRef.current.srcObject = stream; await videoRef.current.play() }
      setCameraState('scanning')
      setCameraMessage('Camera active — no threat detected')
      frameTimerRef.current = window.setInterval(sendFrame, 400)
    } catch (error) {
      stopCamera(); setDetectionMode('real'); setCameraState('error')
      setCameraMessage(error instanceof Error && error.name === 'NotAllowedError' ? 'Camera permission denied — no analysis is running' : 'Camera unavailable — no analysis is running')
    }
  }

  const chooseSimulation = () => { stopCamera(); setDetectionMode('simulation'); setActive(null) }
  const chooseReal = () => { setDetectionMode('real'); setActive(null); setCameraMessage(backendState === 'connected' ? 'Camera inactive — no threat detected' : 'Face backend unavailable. Browser phone detection remains available.') }

  const connectBackend = () => {
    socketRef.current?.close()
    if (!backendUrl) {
      setBackendState('offline')
      awaitingResultRef.current = false
      setCameraMessage('No hosted face backend configured. Browser phone detection remains available.')
      return
    }
    setBackendState('connecting')
    const socket = new WebSocket(backendUrl)
    socketRef.current = socket
    socket.onopen = () => { setBackendState('connected'); setCameraMessage('Backend connected — start camera for real detection') }
    socket.onmessage = event => {
      awaitingResultRef.current = false
      let result: AnalysisResult
      try { result = JSON.parse(event.data) as AnalysisResult } catch { return }
      if (result.error) { setCameraMessage(`Backend rejected frame: ${result.error}`); return }
      setDetections(result.detections)
      setBackendAnalysis(result)
      const faceText = `${result.faces_count} face${result.faces_count === 1 ? '' : 's'} visible`
      if (result.state === 'SECURE') {
        setCameraMessage(`Camera active — ${faceText}; phone detector ${phoneModelState}`)
      } else {
        const confidence = Math.round(Math.max(0, ...result.detections.map(item => item.confidence)) * 100)
        setCameraMessage(`${result.state}: ${result.threat_reason}`)
        if (lastBackendStateRef.current !== result.state) setEvents(old => [{ id: result.timestamp, title: `Real detection: ${result.threat_reason}`, time: now(), confidence, action: result.action === 'LOCKDOWN' ? 'Sensitive data obscured' : 'Privacy blur enabled', mode: result.state === 'LOCKDOWN' ? 'Lockdown' : 'Warning' }, ...old].slice(0, 10))
      }
      lastBackendStateRef.current = result.state
    }
    socket.onerror = () => { setBackendState('offline'); setCameraMessage('Backend not connected. Real detection unavailable.') }
    socket.onclose = () => { setBackendState('offline'); awaitingResultRef.current = false; setCameraMessage('Backend not connected. Real detection unavailable.') }
  }

  const loadPhoneModel = async () => {
    setPhoneModelState('loading')
    setPhoneModelError('')
    try {
      phoneModelRef.current = await getPhoneModel()
      setPhoneModelState('ready')
      setCameraMessage(backendState === 'connected' ? 'Protection models ready — start camera' : 'Phone model ready — face backend offline')
    } catch (error) {
      phoneModelPromise = null
      setPhoneModelState('error')
      setPhoneModelError(error instanceof Error ? error.message : 'Unable to download COCO-SSD model assets')
      setCameraMessage('Phone model error — real phone protection unavailable')
    }
  }

  useEffect(() => {
    const close = () => setMenu(false)
    window.addEventListener('resize', close)
    connectBackend()
    void loadPhoneModel()
    return () => { window.removeEventListener('resize', close); if (frameTimerRef.current) window.clearInterval(frameTimerRef.current); streamRef.current?.getTracks().forEach(track => track.stop()); socketRef.current?.close() }
  }, [])

  useEffect(() => {
    if (detectionMode === 'simulation') return
    const backendRank = backendAnalysis?.state === 'LOCKDOWN' ? 2 : backendAnalysis?.state === 'WARNING' ? 1 : 0
    const phoneProtection = phoneSnapshot.state === 'LOCKDOWN' ? 'Lockdown' : phoneSnapshot.state === 'WARNING' ? 'Warning' : phoneSnapshot.state === 'RECOVERY' ? phoneProtectionRef.current : null
    const phoneRank = phoneProtection === 'Lockdown' ? 2 : phoneProtection === 'Warning' ? 1 : 0
    if (phoneRank === 0 && backendRank === 0) { setActive(null); return }

    if (phoneRank >= backendRank) {
      const recovering = phoneSnapshot.state === 'RECOVERY'
      const confidence = Math.round(phoneLastConfidenceRef.current * 100)
      setActive({
        mode: phoneProtection || 'Warning',
        reason: recovering ? 'Phone removed — recovery validation active' : 'Real cell phone detected',
        detail: recovering ? `Sensitive content remains protected for ${(PHONE_POLICY.recoveryMs / 1000).toFixed(1)} seconds of clear frames.` : `COCO-SSD confirmed a phone for ${(phoneSnapshot.durationMs / 1000).toFixed(1)} seconds from actual webcam frames.`,
        confidence,
        action: phoneProtection === 'Lockdown' ? 'Sensitive content protected — optical exfiltration threat detected.' : 'Privacy blur enabled',
        icon: Smartphone,
      })
      return
    }

    const confidence = Math.round(Math.max(0, ...(backendAnalysis?.detections || []).map(item => item.confidence)) * 100)
    setActive({ mode: backendAnalysis?.state === 'LOCKDOWN' ? 'Lockdown' : 'Warning', reason: backendAnalysis?.threat_reason || 'Persistent second-person threat', detail: `${backendAnalysis?.faces_count || 0} faces visible. State returned by the local OpenCV temporal engine.`, confidence, action: backendAnalysis?.state === 'LOCKDOWN' ? 'Sensitive content protected — optical exfiltration threat detected.' : 'Privacy blur enabled', icon: UserRoundX })
  }, [backendAnalysis, detectionMode, phoneSnapshot])

  const operationalState = phoneModelState === 'loading' ? 'MODEL LOADING' : phoneModelState === 'error' ? 'MODEL ERROR' : cameraState !== 'scanning' ? 'CAMERA OFFLINE' : backendState !== 'connected' ? 'DEGRADED PROTECTION' : 'PROTECTION ACTIVE'
  const faceCount = backendAnalysis?.faces_count || 0
  const highestPhoneConfidence = Math.max(0, ...phoneDetections.map(item => item.score))

  return <div className="app">
    <header className="nav-wrap">
      <nav className="nav shell">
        <a className="brand" href="#top" aria-label="GlassWall AI home"><span className="brand-mark"><Shield size={19}/></span><span>GLASSWALL <b>AI</b></span></a>
        <div className={menu ? 'nav-links open' : 'nav-links'}>
          {['Demo', 'About', 'Architecture', 'Technology'].map(x => <a key={x} href={`#${x.toLowerCase()}`} onClick={() => setMenu(false)}>{x}</a>)}
        </div>
        <a className="nav-cta desktop" href={LINKS.github} target="_blank" rel="noreferrer"><Code2 size={15}/> View source</a>
        <button className="menu" onClick={() => setMenu(!menu)} aria-label="Toggle navigation">{menu ? <X/> : <Menu/>}</button>
      </nav>
    </header>

    <main id="top">
      <section className="hero shell">
        <div className="hero-grid" aria-hidden="true"/><div className="orb orb-a"/><div className="orb orb-b"/>
        <div className="hero-copy reveal">
          <div className="eyebrow"><span className="live-dot"/> Zero-trust optical security prototype</div>
          <h1>The last line of defense is <em>what’s on screen.</em></h1>
          <p>GlassWall AI streams webcam frames to a local FastAPI + OpenCV pipeline, verifies persistent second-observer risk, and protects sensitive interfaces in real time.</p>
          <div className="hero-actions">
            <a className="button primary" href="#demo"><Zap size={17}/> Launch live demo</a>
            <a className="button secondary" href="#architecture">View architecture <ArrowRight size={17}/></a>
          </div>
          <div className="hero-proof">
            <span><Check/> Real OpenCV faces</span><span><Check/> Temporal state engine</span><span><Check/> Honest simulation fallback</span>
          </div>
        </div>
        <div className="hero-visual">
          <div className="radar">
            <div className="radar-ring r1"/><div className="radar-ring r2"/><div className="radar-ring r3"/>
            <div className="scan-line"/><div className="radar-core"><Fingerprint size={42}/><b>PROTECTED</b><small>OPTICAL PERIMETER</small></div>
            <div className="signal s1"><Smartphone/><span>Phone model</span><b>COCO-SSD</b></div>
            <div className="signal s2"><ScanFace/><span>Face detection</span><b>Implemented</b></div>
            <div className="signal s3"><Activity/><span>Temporal policy</span><b>Active</b></div>
          </div>
        </div>
      </section>

      <section className="trust-strip"><div className="shell"><span>ENGINEERED FOR</span><b>FINANCIAL SERVICES</b><i/><b>HEALTHCARE</b><i/><b>DEFENSE</b><i/><b>SECURE REMOTE WORK</b></div></section>

      <section className="section shell" id="demo">
        <SectionHead kicker="INTERACTIVE PROTOTYPE" title="Put the dashboard under pressure." text="Choose an explicit simulation or opt in to experimental, browser-side object detection. Nothing triggers automatically at startup." />
        <div className="mode-panel">
          <div><span>DETECTION MODE</span><b>{detectionMode === 'simulation' ? 'Simulation Mode — manual triggers only' : 'Real Camera Mode'}</b><small>{detectionMode === 'simulation' ? 'No camera or automatic analysis.' : `${operationalState}. Browser phone detector ${phoneModelState}; face backend ${backendState}.`}</small></div>
          <div className="mode-switch"><button className={detectionMode === 'real' ? 'selected' : ''} onClick={chooseReal}><Camera/> Real Camera Mode</button><button className={detectionMode === 'simulation' ? 'selected' : ''} onClick={chooseSimulation}><Zap/> Simulation Mode</button></div>
        </div>
        <div className={`camera-panel ${detectionMode === 'simulation' ? 'camera-hidden' : ''}`}>
          <div className="camera-view">
            <video ref={videoRef} muted playsInline/><canvas ref={canvasRef} hidden/><div className="camera-corners"/>
            {phoneDetections.map((item, index) => { const width = videoRef.current?.videoWidth || 640; const height = videoRef.current?.videoHeight || 480; return <div className="phone-box" key={`${item.class}-${index}`} style={{ left: `${100 - ((item.bbox[0] + item.bbox[2]) / width * 100)}%`, top: `${item.bbox[1] / height * 100}%`, width: `${item.bbox[2] / width * 100}%`, height: `${item.bbox[3] / height * 100}%` }}><span>PHONE {Math.round(item.score * 100)}%</span></div> })}
            <span className={`camera-live ${cameraState}`}><i/>{cameraState === 'scanning' ? 'REAL FRAME ANALYSIS ACTIVE' : cameraState.toUpperCase()}</span>
          </div>
          <div className="camera-info">
            <div className="kicker">REAL-TIME OPTICAL DLP</div><h3>COCO-SSD phone + OpenCV face detection</h3><div className={`operational-status ${operationalState.toLowerCase().replaceAll(' ', '-')}`}>{operationalState}</div><p>{cameraMessage}</p>
            <div className="backend-badges"><span className={backendState}><i/>Face backend: {backendState}</span><span className={phoneModelState === 'ready' ? 'connected' : phoneModelState === 'error' ? 'offline' : 'connecting'}><i/>Phone model: {phoneModelState === 'ready' ? 'MODEL READY' : phoneModelState === 'error' ? 'MODEL ERROR' : 'MODEL LOADING'}</span></div>
            {phoneModelError && <div className="model-error">{phoneModelError}</div>}
            <div className="runtime-grid"><span><b>{inferenceFps}</b> inference FPS</span><span><b>{faceCount}</b> faces</span><span><b>{phoneDetections.length}</b> phones</span><span><b>{Math.round(highestPhoneConfidence * 100)}%</b> phone confidence</span></div>
            <div className="camera-rules"><span><Check/> Phone ≥{Math.round(PHONE_POLICY.confidenceThreshold * 100)}% + {PHONE_POLICY.consecutiveFrames} frames</span><span><Check/> 1.5s Warning · 3.0s Lockdown</span><span><Check/> 2.0s clear → Recovery → Secure</span></div>
            {(detections.length > 0 || phoneDetections.length > 0) && <div className="active-detections">{phoneDetections.map((item, index) => <span key={`phone-${index}`}>PHONE · {Math.round(item.score * 100)}% · [{item.bbox.map(Math.round).join(', ')}]</span>)}{detections.map((item, index) => <span key={`${item.type}-${index}`}>{item.type} · {Math.round(item.confidence * 100)}% · [{item.bbox.join(', ')}]</span>)}</div>}
            <div className="camera-actions">{cameraState !== 'scanning' ? <button onClick={startCamera} disabled={phoneModelState !== 'ready'}><Camera/> Start real camera</button> : <button onClick={stopCamera}><X/> Stop camera</button>}{phoneModelState === 'error' && <button onClick={loadPhoneModel}><RefreshCw/> Retry phone model</button>}{backendState !== 'connected' && <button onClick={connectBackend}><RefreshCw/> Retry face backend</button>}</div>
          </div>
        </div>
        <div className={`demo-shell ${active ? active.mode.toLowerCase() : 'secure'} ${detectionMode === 'real' && operationalState !== 'PROTECTION ACTIVE' ? 'degraded' : ''}`}>
          <div className="demo-topbar">
            <div><span className="mini-logo"><Shield size={15}/></span><b>MERIDIAN</b><span className="classified">INTERNAL · CONFIDENTIAL</span></div>
            <div className="status-cluster"><span className="pulse"/><span>THREAT STATE</span><b>{active?.mode.toUpperCase() || 'SECURE'}</b></div>
          </div>
          {!active && <div className="secure-banner"><ShieldCheck/><div><b>No confirmed threat</b><span>{detectionMode === 'real' ? `${operationalState} · ${cameraMessage}` : 'Camera inactive — manual simulation only'}</span></div><strong>{detectionMode === 'simulation' ? 'SIMULATION MODE' : operationalState}</strong></div>}
          {active && <div className="threat-banner">
            <div className="threat-icon"><active.icon/></div><div><b>{active.reason}</b><span>{active.detail}</span></div>
            <div className="confidence"><span>CONFIDENCE</span><b>{active.confidence}%</b></div><div className="banner-meta"><span>{now()}</span><b>{active.action}</b></div>
          </div>}
          <div className="demo-body">
            <aside className="side-rail"><div className="rail-icon active"><Blocks/></div><div className="rail-icon"><Activity/></div><div className="rail-icon"><Users/></div><div className="rail-icon"><Database/></div><div className="rail-icon"><Shield/></div></aside>
            <div className="dashboard-wrap">
              <div className={`dashboard ${active ? 'obscured' : ''}`}>
                <div className="dash-heading"><div><small>FICTIONAL INTERNAL DATASET</small><h3>Placeholder Project Metrics</h3></div><span>SAFE DEMO DATA</span></div>
                <div className="fiction-label">All dashboard data is fictional demo data.</div>
                <div className="metric-grid">
                  <Metric label="DEMO REVENUE INDEX" value="IDX 72" trend="Synthetic value" icon={CircleDollarSign}/>
                  <Metric label="SYNTHETIC RISK SCORE" value="18 / 100" trend="Sample only" icon={ShieldAlert}/>
                  <Metric label="SAMPLE COMPLIANCE" value="6 / 6" trend="Mock controls" icon={ShieldCheck}/>
                  <Metric label="PLACEHOLDER SESSIONS" value="24" trend="Fictional users" icon={Users}/>
                </div>
                <div className="dash-grid">
                  <div className="dash-card chart-card"><CardTitle title="Demo activity index" tag="SYNTHETIC"/><div className="chart"><div className="chart-fill"/><svg viewBox="0 0 600 160" preserveAspectRatio="none"><path d="M0,140 C60,128 80,105 130,113 S210,88 250,95 S330,60 370,69 S430,28 480,45 S550,15 600,20"/></svg><div className="chart-labels"><span>S1</span><span>S2</span><span>S3</span><span>S4</span><span>S5</span><span>S6</span></div></div></div>
                  <div className="dash-card compliance"><CardTitle title="Sample compliance status" tag="MOCK"/><div className="score-ring"><div><b>96</b><span>/100</span></div></div><div className="control-row"><span><i className="ok"/>Demo Control A</span><b>PASS</b></div><div className="control-row"><span><i className="ok"/>Demo Control B</span><b>PASS</b></div></div>
                  <div className="dash-card access"><CardTitle title="Mock access events" tag="FICTIONAL"/><table><thead><tr><th>IDENTITY</th><th>RESOURCE</th><th>RISK</th><th>TIME</th></tr></thead><tbody>
                    <tr><td><i className="avatar">U1</i>Demo User 01</td><td>Sample Dataset A</td><td><span className="risk low">LOW</span></td><td>10:42</td></tr>
                    <tr><td><i className="avatar blue">U2</i>Demo User 02</td><td>Placeholder Vault</td><td><span className="risk medium">MED</span></td><td>10:18</td></tr>
                    <tr><td><i className="avatar purple">U3</i>Demo User 03</td><td>Mock Project File</td><td><span className="risk low">LOW</span></td><td>09:56</td></tr>
                  </tbody></table></div>
                  <div className="dash-card alerts"><CardTitle title="Detection status" tag={active ? active.mode.toUpperCase() : 'NO ACTIVE ALERTS'}/><div className="alert-row safe"><ShieldCheck/><div><b>{active ? active.reason : 'No active threat detected'}</b><span>{active ? active.detail : 'Waiting for a manual simulation or verified backend result'}</span></div><strong>{active ? active.mode.toUpperCase() : 'SAFE'}</strong></div><div className="alert-row minor"><Camera/><div><b>{detectionMode === 'real' ? cameraMessage : 'Camera inactive'}</b><span>{detectionMode === 'real' ? `Backend ${backendState} · OpenCV face analysis` : 'Simulation mode does not access the camera'}</span></div><strong>INFO</strong></div></div>
                </div>
              </div>
              {active && <div className="lock-overlay"><div className="lock-symbol"><LockKeyhole/></div><span>ZERO-TRUST PROTECTION ACTIVE</span><h3>Sensitive data secured</h3><p>{active.action}. Clear the detected risk before resuming this session.</p><button onClick={reset}><RefreshCw/> Reset secure session</button></div>}
            </div>
          </div>
        </div>
        <div className="simulation-panel">
          <div className="sim-copy"><span>MANUAL SIMULATOR</span><h3>Test a threat scenario</h3><p>{detectionMode === 'simulation' ? 'These controls create explicit user-triggered demo events. They are never presented as camera detections.' : 'Switch to Simulation Demo above to use manual triggers.'}</p></div>
          <div className="sim-buttons"><button disabled={detectionMode !== 'simulation'} onClick={() => simulate('phone')}><Smartphone/><span><b>Simulate Phone</b><small>User-triggered Warning</small></span></button><button disabled={detectionMode !== 'simulation'} onClick={() => simulate('observer')}><UserRoundX/><span><b>Simulate Second Face</b><small>User-triggered Warning</small></span></button><button disabled={detectionMode !== 'simulation'} onClick={() => simulate('shoulder')}><LockKeyhole/><span><b>Simulate Lockdown</b><small>User-triggered Lockdown</small></span></button><button className="reset" onClick={reset}><RefreshCw/><span><b>Reset</b><small>Clear active threats</small></span></button></div>
        </div>
        <div className="event-log">
          <div className="log-head"><div><Radio/><span><b>Security event stream</b><small>SESSION LEDGER · LOCAL</small></span></div><span className="connected"><i/> MONITORING</span></div>
          {events.length === 0 ? <div className="empty-log"><ShieldCheck/><div><b>No threats in this session</b><span>Use the simulator or camera assist to generate a verified event.</span></div></div> : <div className="log-rows">{events.map(e => <div className="log-row" key={e.id}><span className={`event-severity ${e.mode.toLowerCase()}`}>{e.mode}</span><div><b>{e.title}</b><span>{e.action}</span></div><span>{e.confidence ? `${e.confidence}% confidence` : 'No detection'}</span><time>{e.time}</time></div>)}</div>}
        </div>
      </section>

      <section className="section about-section" id="about"><div className="shell about-grid">
        <div className="about-visual"><div className="glass-layers"><div className="layer l1"/><div className="layer l2"/><div className="layer l3"><Shield size={60}/></div></div><div className="stat-card top"><b>&lt;40ms</b><span>target response latency</span></div><div className="stat-card bottom"><b>3</b><span>implemented reasoning engines</span></div></div>
        <div><div className="kicker">THE ANALOG GAP</div><h2>Security shouldn’t stop at the edge of the screen.</h2><p className="lead">GlassWall AI combines browser-side COCO-SSD phone detection with local FastAPI/OpenCV face counting and temporal threat evaluation.</p><p>Traditional DLP watches files, networks, and endpoints. GlassWall focuses on what happens after sensitive data is rendered: unauthorized observers and physical capture risks.</p><div className="honesty"><ShieldCheck/><div><b>Real inference, explicit limitations</b><span>GitHub Pages runs real phone detection locally in the browser. The optional FastAPI service adds OpenCV second-face detection when run on the same machine. Simulation remains isolated and manual.</span></div></div></div>
      </div></section>

      <section className="section shell" id="architecture"><SectionHead kicker="SYSTEM ARCHITECTURE" title="Working modules, clearly separated." text="The local system streams compressed webcam frames to FastAPI, runs real OpenCV face analysis, applies temporal policy, and returns an auditable UI state." />
        <div className="module-grid">{modules.map(([num, title, text, status]) => <article className="module-card" key={num}><div className="module-num">{num}</div><div><h3>{title}</h3><p>{text}</p><span className={status.startsWith('Implemented') ? 'tag implemented' : 'tag planned'}>{status}</span></div></article>)}</div>
      </section>

      <section className="section dark-section"><div className="shell"><SectionHead kicker="CAPABILITIES" title="Security engineering you can interact with." text="The portfolio demo makes a complex threat model legible without pretending simulation is production inference." /><div className="feature-grid">{features.map((item) => { const title = item[0] as string; const text = item[1] as string; const Icon = item[2] as typeof Shield; return <article className="feature-card" key={title}><div className="feature-icon"><Icon/></div><h3>{title}</h3><p>{text}</p><ArrowRight/></article> })}</div></div></section>

      <section className="section shell" id="technology"><SectionHead kicker="TOOLS & TECHNOLOGIES" title="What’s built—and what comes next." text="Every capability is labeled honestly: implemented in this repository, designed at the architecture layer, or planned for integration." />
        <div className="tech-grid">
          <Tech title="Frontend + phone AI" icon={Code2} status="IMPLEMENTED" items={['React + TypeScript', 'COCO-SSD MobileNet-v2', 'Real phone bounding boxes', 'Temporal phone tracker', 'GitHub Pages workflow']}/>
          <Tech title="Reasoning core" icon={BrainCircuit} status="IMPLEMENTED" items={['Python threat models', '3D spatial ray-casting', 'Augmented AVL interval tree', 'Threat state graph', 'Thread-safe evaluation']}/>
          <Tech title="Local detection service" icon={Terminal} status="IMPLEMENTED" items={['FastAPI + WebSockets', 'OpenCV Haar faces', 'Temporal state engine', 'Per-session reset cooldown', 'Structured detection API']}/>
          <Tech title="Cloud pipeline" icon={Cloud} status="ARCHITECTURE READY" items={['Azure Container Apps', 'Event Grid + Functions', 'Cosmos DB threat ledger', 'Static Web Apps option', 'GitHub Pages live demo']}/>
        </div>
      </section>

      <section className="cta-section"><div className="cta-grid"/><div className="shell cta-inner"><div className="cta-icon"><Shield/></div><div className="kicker">PORTFOLIO PROJECT</div><h2>Built for the security problems that happen in plain sight.</h2><p>A security-focused AI engineering project demonstrating full-stack development, edge AI architecture, advanced data structures, and cloud-ready system design.</p><div className="hero-actions"><a className="button primary" href={LINKS.github} target="_blank" rel="noreferrer"><Code2/> Explore the code</a><a className="button secondary" href="#demo"><Zap/> Run live demo</a><a className="button secondary" href={LINKS.portfolio} target="_blank" rel="noreferrer"><Globe2/> Portfolio</a></div></div></section>
    </main>
    <footer><div className="shell footer-inner"><a className="brand" href="#top"><span className="brand-mark"><Shield size={18}/></span><span>GLASSWALL <b>AI</b></span></a><p>Zero-Trust Optical Data Loss Prevention · Portfolio prototype</p><div><a href="#about">About</a><a href="#architecture">Architecture</a><a href={LINKS.github}>GitHub</a></div></div></footer>
  </div>
}

function SectionHead({ kicker, title, text }: { kicker: string; title: string; text: string }) { return <div className="section-head"><div className="kicker">{kicker}</div><h2>{title}</h2><p>{text}</p></div> }
function CardTitle({ title, tag }: { title: string; tag: string }) { return <div className="card-title"><b>{title}</b><span>{tag}</span></div> }
function Metric({ label, value, trend, icon: Icon }: { label: string; value: string; trend: string; icon: typeof Shield }) { return <div className="metric"><div><span>{label}</span><b>{value}</b><small>{trend}</small></div><Icon/></div> }
function Tech({ title, icon: Icon, status, items }: { title: string; icon: typeof Shield; status: string; items: string[] }) { return <article className="tech-card"><div className="tech-top"><div><Icon/><h3>{title}</h3></div><span className={status === 'IMPLEMENTED' ? 'implemented' : ''}>{status}</span></div><ul>{items.map(x => <li key={x}><Check/>{x}</li>)}</ul></article> }
