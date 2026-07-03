import { useEffect, useRef, useState } from 'react'
import {
  Activity, ArrowRight, Blocks, BrainCircuit, Camera, Check, ChevronRight, CircleDollarSign,
  Cloud, Code2, Database, Eye, Fingerprint, Globe2, KeyRound, LockKeyhole, Menu,
  Network, Radio, RefreshCw, ScanFace, Shield, ShieldAlert, ShieldCheck, Smartphone,
  Terminal, TriangleAlert, UserRoundX, Users, Workflow, X, Zap
} from 'lucide-react'

type Threat = { mode: 'Warning' | 'Lockdown'; reason: string; detail: string; confidence: number; action: string; icon: typeof Smartphone }
type Event = { id: number; title: string; time: string; confidence?: number; action: string; mode: string }
type DetectionMode = 'simulation' | 'camera'
type CameraState = 'off' | 'requesting' | 'loading' | 'scanning' | 'error'

const LINKS = {
  github: 'https://github.com/AalimBaba/GlassWall-AI',
  portfolio: 'https://yourportfolio.example.com',
}

const threats: Record<string, Threat> = {
  phone: { mode: 'Warning', reason: 'Simulated phone threat', detail: 'User manually triggered a phone-camera scenario.', confidence: 90, action: 'Privacy blur enabled', icon: Smartphone },
  observer: { mode: 'Warning', reason: 'Simulated unauthorized observer', detail: 'User manually triggered a second-observer scenario.', confidence: 90, action: 'Privacy blur enabled', icon: UserRoundX },
  shoulder: { mode: 'Lockdown', reason: 'Simulated shoulder surfing', detail: 'User manually triggered a high-risk gaze-overlap scenario.', confidence: 95, action: 'Sensitive data obscured', icon: Eye },
}

const pipeline = [
  ['Webcam / CCTV', Camera], ['Local CV', BrainCircuit], ['YOLO detection', Smartphone],
  ['Face & gaze', ScanFace], ['Spatial ray-cast', Network], ['Interval analysis', Activity],
  ['Threat state', Workflow], ['Blur / lockdown', LockKeyhole], ['Azure ledger', Cloud],
] as const

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
  ['04', 'Command-Based Remediation', 'Decouples blur, lock, warn, revoke, and audit actions for reversible response.', 'Architecture ready'],
  ['05', 'Stream Strategy Layer', 'Selects webcam, CCTV, or prerecorded inference streams behind a stable interface.', 'Planned integration'],
  ['06', 'Azure Threat Ledger', 'Persists immutable threat evidence through an event-driven cloud pipeline.', 'Architecture ready'],
]

function now() { return new Date().toLocaleTimeString([], { hour: '2-digit', minute: '2-digit', second: '2-digit' }) }

export default function App() {
  const [active, setActive] = useState<Threat | null>(null)
  const [events, setEvents] = useState<Event[]>([{ id: 1, title: 'Session initialized', time: now(), action: 'Secure — no active threat', mode: 'Secure' }])
  const [menu, setMenu] = useState(false)
  const [detectionMode, setDetectionMode] = useState<DetectionMode>('simulation')
  const [cameraState, setCameraState] = useState<CameraState>('off')
  const [cameraMessage, setCameraMessage] = useState('Camera not analyzed yet')
  const videoRef = useRef<HTMLVideoElement>(null)
  const streamRef = useRef<MediaStream | null>(null)
  const modelRef = useRef<{ detect: (input: HTMLVideoElement) => Promise<Array<{ class: string; score: number; bbox: number[] }>> } | null>(null)
  const scanTimerRef = useRef<number | null>(null)
  const phoneSinceRef = useRef<number | null>(null)
  const overlapSinceRef = useRef<number | null>(null)
  const lastCameraThreatRef = useRef<'phone' | 'overlap' | null>(null)
  const cooldownUntilRef = useRef(0)
  const cameraSessionRef = useRef(0)
  const inferenceBusyRef = useRef(false)

  const simulate = (key: keyof typeof threats) => {
    if (detectionMode !== 'simulation') return
    const threat = threats[key]
    setActive(threat)
    setEvents(old => [{ id: Date.now(), title: `Simulation: ${key} threat triggered by user`, time: now(), confidence: threat.confidence, action: threat.action, mode: threat.mode }, ...old].slice(0, 6))
    document.getElementById('demo')?.scrollIntoView({ behavior: 'smooth', block: 'start' })
  }
  const reset = () => {
    setActive(null)
    phoneSinceRef.current = null
    overlapSinceRef.current = null
    lastCameraThreatRef.current = null
    cooldownUntilRef.current = Date.now() + 3000
    setEvents(old => [{ id: Date.now(), title: 'Session reset', time: now(), action: 'Returned to secure state; 3s cooldown active', mode: 'Secure' }, ...old].slice(0, 6))
    if (cameraState === 'scanning') setCameraMessage('Camera active — no threat detected')
  }

  const stopCamera = () => {
    cameraSessionRef.current += 1
    if (scanTimerRef.current) window.clearInterval(scanTimerRef.current)
    scanTimerRef.current = null
    streamRef.current?.getTracks().forEach(track => track.stop())
    streamRef.current = null
    modelRef.current = null
    setCameraState('off')
    setCameraMessage('Camera not analyzed yet')
    phoneSinceRef.current = null
    overlapSinceRef.current = null
    lastCameraThreatRef.current = null
  }

  const runDetection = async () => {
    const video = videoRef.current
    const model = modelRef.current
    if (!video || !model || video.readyState < 2 || Date.now() < cooldownUntilRef.current || inferenceBusyRef.current) return
    inferenceBusyRef.current = true
    try {
      const predictions = await model.detect(video)
      const phone = predictions.filter(p => /cell phone|phone/i.test(p.class) && p.score >= .55).sort((a, b) => b.score - a.score)[0]
      const persons = predictions.filter(p => p.class === 'person' && p.score >= .65)
      const timestamp = Date.now()
      phoneSinceRef.current = phone ? (phoneSinceRef.current ?? timestamp) : null
      overlapSinceRef.current = phone && persons.length > 1 ? (overlapSinceRef.current ?? timestamp) : null
      const phoneDuration = phoneSinceRef.current ? timestamp - phoneSinceRef.current : 0
      const overlapDuration = overlapSinceRef.current ? timestamp - overlapSinceRef.current : 0

      if (phone && persons.length > 1 && overlapDuration >= 1500) {
        setCameraMessage(`Persistent phone + ${persons.length} people detected`)
        if (lastCameraThreatRef.current !== 'overlap') {
          const confidence = Math.round(Math.min(phone.score, ...persons.map(p => p.score)) * 100)
          const threat: Threat = { mode: 'Lockdown', reason: 'Camera-assisted overlap detected', detail: `A phone and ${persons.length} people persisted together for ${(overlapDuration / 1000).toFixed(1)}s.`, confidence, action: 'Sensitive data obscured', icon: ShieldAlert }
          setActive(threat); lastCameraThreatRef.current = 'overlap'
          setEvents(old => [{ id: timestamp, title: `Camera: phone + multiple people detected for ${(overlapDuration / 1000).toFixed(1)}s`, time: now(), confidence, action: threat.action, mode: threat.mode }, ...old].slice(0, 6))
        }
      } else if (phone && phoneDuration >= 1000) {
        setCameraMessage(`Cell phone persisted for ${(phoneDuration / 1000).toFixed(1)}s at ${Math.round(phone.score * 100)}%`)
        if (lastCameraThreatRef.current !== 'phone') {
          const confidence = Math.round(phone.score * 100)
          const threat: Threat = { mode: 'Warning', reason: 'Camera-assisted phone detection', detail: `COCO-SSD classified a cell phone for ${(phoneDuration / 1000).toFixed(1)}s.`, confidence, action: 'Privacy blur enabled', icon: Smartphone }
          setActive(threat); lastCameraThreatRef.current = 'phone'
          setEvents(old => [{ id: timestamp, title: `Camera: cell phone detected for ${(phoneDuration / 1000).toFixed(1)}s`, time: now(), confidence, action: threat.action, mode: threat.mode }, ...old].slice(0, 6))
        }
      } else {
        setCameraMessage(persons.length ? `Camera active — ${persons.length} person${persons.length > 1 ? 's' : ''} visible, no threat detected` : 'Camera active — no threat detected')
        if (!phone) lastCameraThreatRef.current = null
      }
    } catch {
      setCameraMessage('Camera frame could not be analyzed; no threat triggered')
    } finally {
      inferenceBusyRef.current = false
    }
  }

  const startCamera = async () => {
    stopCamera()
    const sessionId = cameraSessionRef.current
    setDetectionMode('camera')
    setCameraState('requesting')
    setCameraMessage('Waiting for webcam permission…')
    try {
      const stream = await navigator.mediaDevices.getUserMedia({ video: { facingMode: 'user', width: { ideal: 640 }, height: { ideal: 480 } }, audio: false })
      if (sessionId !== cameraSessionRef.current) { stream.getTracks().forEach(track => track.stop()); return }
      streamRef.current = stream
      if (videoRef.current) { videoRef.current.srcObject = stream; await videoRef.current.play() }
      setCameraState('loading'); setCameraMessage('Camera active — loading COCO-SSD model…')
      await import('@tensorflow/tfjs')
      const cocoSsd = await import('@tensorflow-models/coco-ssd')
      const model = await cocoSsd.load({ base: 'lite_mobilenet_v2' })
      if (sessionId !== cameraSessionRef.current || !streamRef.current) return
      modelRef.current = model
      setCameraState('scanning'); setCameraMessage('Camera active — no threat detected')
      scanTimerRef.current = window.setInterval(runDetection, 350)
    } catch (error) {
      stopCamera(); setDetectionMode('camera'); setCameraState('error')
      setCameraMessage(error instanceof Error && error.name === 'NotAllowedError' ? 'Camera permission denied — no analysis is running' : 'Camera or detection model unavailable — no analysis is running')
    }
  }

  const chooseSimulation = () => { stopCamera(); setDetectionMode('simulation'); setActive(null) }

  useEffect(() => {
    const close = () => setMenu(false)
    window.addEventListener('resize', close)
    return () => { window.removeEventListener('resize', close); if (scanTimerRef.current) window.clearInterval(scanTimerRef.current); streamRef.current?.getTracks().forEach(track => track.stop()) }
  }, [])

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
          <p>GlassWall AI detects physical screen-exfiltration risks—phone photography, shoulder surfing, and unauthorized observers—then instantly protects sensitive interfaces.</p>
          <div className="hero-actions">
            <a className="button primary" href="#demo"><Zap size={17}/> Launch live demo</a>
            <a className="button secondary" href="#architecture">View architecture <ArrowRight size={17}/></a>
          </div>
          <div className="hero-proof">
            <span><Check/> Browser-safe simulation</span><span><Check/> No backend required</span><span><Check/> Open architecture</span>
          </div>
        </div>
        <div className="hero-visual">
          <div className="radar">
            <div className="radar-ring r1"/><div className="radar-ring r2"/><div className="radar-ring r3"/>
            <div className="scan-line"/><div className="radar-core"><Fingerprint size={42}/><b>PROTECTED</b><small>OPTICAL PERIMETER</small></div>
            <div className="signal s1"><Smartphone/><span>Device detection</span><b>Opt-in</b></div>
            <div className="signal s2"><ScanFace/><span>Observer logic</span><b>Simulated</b></div>
            <div className="signal s3"><Eye/><span>Gaze tracking</span><b>Architecture</b></div>
          </div>
        </div>
      </section>

      <section className="trust-strip"><div className="shell"><span>ENGINEERED FOR</span><b>FINANCIAL SERVICES</b><i/><b>HEALTHCARE</b><i/><b>DEFENSE</b><i/><b>SECURE REMOTE WORK</b></div></section>

      <section className="section shell" id="demo">
        <SectionHead kicker="INTERACTIVE PROTOTYPE" title="Put the dashboard under pressure." text="Choose an explicit simulation or opt in to experimental, browser-side object detection. Nothing triggers automatically at startup." />
        <div className="mode-panel">
          <div><span>DETECTION MODE</span><b>{detectionMode === 'simulation' ? 'Mode: Simulation Demo' : 'Mode: Camera Assist Experimental'}</b><small>{detectionMode === 'simulation' ? 'Manual scenarios only — no camera or automatic analysis.' : 'Local COCO-SSD assistance — experimental and not production security.'}</small></div>
          <div className="mode-switch"><button className={detectionMode === 'simulation' ? 'selected' : ''} onClick={chooseSimulation}><Zap/> Simulation Demo</button><button className={detectionMode === 'camera' ? 'selected' : ''} onClick={startCamera}><Camera/> Camera Assist / Experimental</button></div>
        </div>
        <div className={`camera-panel ${detectionMode === 'simulation' ? 'camera-hidden' : ''}`}>
          <div className="camera-view"><video ref={videoRef} muted playsInline/><div className="camera-corners"/><span className={`camera-live ${cameraState}`}><i/>{cameraState === 'scanning' ? 'LOCAL ANALYSIS ACTIVE' : cameraState.toUpperCase()}</span></div>
          <div className="camera-info"><div className="kicker">OPTIONAL CAMERA ASSIST</div><h3>Experimental local object detection</h3><p>{cameraMessage}</p><div className="camera-rules"><span><Check/> Phone ≥55% for 1.0s → Warning</span><span><Check/> Phone + 2 people for 1.5s → Lockdown</span><span><Check/> No frame or model → no threat</span></div><button onClick={stopCamera}><X/> Stop camera</button></div>
        </div>
        <div className={`demo-shell ${active ? active.mode.toLowerCase() : 'secure'}`}>
          <div className="demo-topbar">
            <div><span className="mini-logo"><Shield size={15}/></span><b>MERIDIAN</b><span className="classified">INTERNAL · CONFIDENTIAL</span></div>
            <div className="status-cluster"><span className="pulse"/><span>SECURITY MODE</span><b>{active?.mode.toUpperCase() || 'SECURE'}</b></div>
          </div>
          {!active && <div className="secure-banner"><ShieldCheck/><div><b>No active threat detected</b><span>{detectionMode === 'camera' ? cameraMessage : 'Camera not analyzed yet'}</span></div><strong>{detectionMode === 'simulation' ? 'SIMULATION MODE' : 'CAMERA ASSIST · EXPERIMENTAL'}</strong></div>}
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
                  <div className="dash-card alerts"><CardTitle title="Detection status" tag="NO ACTIVE ALERTS"/><div className="alert-row safe"><ShieldCheck/><div><b>No active threat detected</b><span>Waiting for a user simulation or verified camera signal</span></div><strong>SAFE</strong></div><div className="alert-row minor"><Camera/><div><b>{detectionMode === 'camera' ? cameraMessage : 'Camera not analyzed yet'}</b><span>{detectionMode === 'camera' ? 'Experimental browser assistance' : 'Simulation mode does not access the camera'}</span></div><strong>INFO</strong></div></div>
                </div>
              </div>
              {active && <div className="lock-overlay"><div className="lock-symbol"><LockKeyhole/></div><span>ZERO-TRUST PROTECTION ACTIVE</span><h3>Sensitive data secured</h3><p>{active.action}. Clear the detected risk before resuming this session.</p><button onClick={reset}><RefreshCw/> Reset secure session</button></div>}
            </div>
          </div>
        </div>
        <div className="simulation-panel">
          <div className="sim-copy"><span>MANUAL SIMULATOR</span><h3>Test a threat scenario</h3><p>{detectionMode === 'simulation' ? 'These controls create explicit user-triggered demo events. They are never presented as camera detections.' : 'Switch to Simulation Demo above to use manual triggers.'}</p></div>
          <div className="sim-buttons"><button disabled={detectionMode !== 'simulation'} onClick={() => simulate('phone')}><Smartphone/><span><b>Simulate Phone</b><small>User-triggered Warning</small></span></button><button disabled={detectionMode !== 'simulation'} onClick={() => simulate('observer')}><UserRoundX/><span><b>Simulate Observer</b><small>User-triggered Warning</small></span></button><button disabled={detectionMode !== 'simulation'} onClick={() => simulate('shoulder')}><Eye/><span><b>Simulate Shoulder Surfing</b><small>User-triggered Lockdown</small></span></button><button className="reset" onClick={reset}><RefreshCw/><span><b>Reset Session</b><small>Clear active threats</small></span></button></div>
        </div>
        <div className="event-log">
          <div className="log-head"><div><Radio/><span><b>Security event stream</b><small>SESSION LEDGER · LOCAL</small></span></div><span className="connected"><i/> MONITORING</span></div>
          {events.length === 0 ? <div className="empty-log"><ShieldCheck/><div><b>No threats in this session</b><span>Use the simulator or camera assist to generate a verified event.</span></div></div> : <div className="log-rows">{events.map(e => <div className="log-row" key={e.id}><span className={`event-severity ${e.mode.toLowerCase()}`}>{e.mode}</span><div><b>{e.title}</b><span>{e.action}</span></div><span>{e.confidence ? `${e.confidence}% confidence` : 'No detection'}</span><time>{e.time}</time></div>)}</div>}
        </div>
      </section>

      <section className="section about-section" id="about"><div className="shell about-grid">
        <div className="about-visual"><div className="glass-layers"><div className="layer l1"/><div className="layer l2"/><div className="layer l3"><Shield size={60}/></div></div><div className="stat-card top"><b>&lt;40ms</b><span>target response latency</span></div><div className="stat-card bottom"><b>3</b><span>implemented reasoning engines</span></div></div>
        <div><div className="kicker">THE ANALOG GAP</div><h2>Security shouldn’t stop at the edge of the screen.</h2><p className="lead">GlassWall AI is a real-time security prototype exploring how computer vision and zero-trust UI protection can reduce physical data leakage in high-security environments.</p><p>Traditional DLP watches files, networks, and endpoints. GlassWall focuses on what happens after sensitive data is rendered: people capturing it with phones, cameras, or unauthorized viewing.</p><div className="honesty"><ShieldCheck/><div><b>Built to demonstrate, designed to integrate</b><span>The live site uses simulated detections for a safe browser demo. Its architecture is prepared for WebRTC, MediaPipe, YOLO, FastAPI, and Azure—not presented as already deployed AI.</span></div></div></div>
      </div></section>

      <section className="section shell" id="architecture"><SectionHead kicker="SYSTEM ARCHITECTURE" title="From visual signal to verified response." text="A low-latency pipeline separates perception, reasoning, remediation, and audit—so every layer can evolve independently." />
        <div className="pipeline">{pipeline.map((item, i) => { const name = item[0] as string; const Icon = item[1] as typeof Shield; return <div className="pipe-wrap" key={name}><div className="pipe-card"><span>{String(i + 1).padStart(2, '0')}</span><Icon/><b>{name}</b></div>{i < pipeline.length - 1 && <ChevronRight className="pipe-arrow"/>}</div> })}</div>
        <div className="module-grid">{modules.map(([num, title, text, status]) => <article className="module-card" key={num}><div className="module-num">{num}</div><div><h3>{title}</h3><p>{text}</p><span className={status.startsWith('Implemented') ? 'tag implemented' : 'tag planned'}>{status}</span></div></article>)}</div>
      </section>

      <section className="section dark-section"><div className="shell"><SectionHead kicker="CAPABILITIES" title="Security engineering you can interact with." text="The portfolio demo makes a complex threat model legible without pretending simulation is production inference." /><div className="feature-grid">{features.map((item) => { const title = item[0] as string; const text = item[1] as string; const Icon = item[2] as typeof Shield; return <article className="feature-card" key={title}><div className="feature-icon"><Icon/></div><h3>{title}</h3><p>{text}</p><ArrowRight/></article> })}</div></div></section>

      <section className="section shell" id="technology"><SectionHead kicker="TOOLS & TECHNOLOGIES" title="What’s built—and what comes next." text="Every capability is labeled honestly: implemented in this repository, designed at the architecture layer, or planned for integration." />
        <div className="tech-grid">
          <Tech title="Frontend + browser AI" icon={Code2} status="IMPLEMENTED" items={['React + TypeScript', 'TensorFlow.js COCO-SSD', 'Optional webcam preview', 'Temporal detection smoothing', 'GitHub Pages workflow']}/>
          <Tech title="Reasoning core" icon={BrainCircuit} status="IMPLEMENTED" items={['Python threat models', '3D spatial ray-casting', 'Augmented AVL interval tree', 'Threat state graph', 'Thread-safe evaluation']}/>
          <Tech title="AI & service layer" icon={Terminal} status="PLANNED INTEGRATION" items={['FastAPI + WebSockets', 'OpenCV + MediaPipe', 'YOLO object detection', 'WebRTC capture strategy', 'Command remediation']}/>
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
