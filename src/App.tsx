import { useEffect, useState } from 'react'
import {
  Activity, ArrowRight, Blocks, BrainCircuit, Camera, Check, ChevronRight, CircleDollarSign,
  Cloud, Code2, Database, Eye, Fingerprint, Globe2, KeyRound, LockKeyhole, Menu,
  Network, Radio, RefreshCw, ScanFace, Shield, ShieldAlert, ShieldCheck, Smartphone,
  Terminal, TriangleAlert, UserRoundX, Users, Workflow, X, Zap
} from 'lucide-react'

type Threat = { mode: 'Warning' | 'Lockdown'; reason: string; detail: string; confidence: number; action: string; icon: typeof Smartphone }
type Event = { id: number; title: string; time: string; confidence: number; action: string; mode: string }

const LINKS = {
  github: 'https://github.com/AalimBaba/GlassWall-AI',
  portfolio: 'https://yourportfolio.example.com',
}

const threats: Record<string, Threat> = {
  phone: { mode: 'Lockdown', reason: 'Phone camera detected', detail: 'Optical capture device identified inside the protected display zone.', confidence: 97, action: 'Sensitive data obscured', icon: Smartphone },
  observer: { mode: 'Lockdown', reason: 'Unauthorized observer', detail: 'A second face entered the secure viewing perimeter.', confidence: 94, action: 'Session locked', icon: UserRoundX },
  shoulder: { mode: 'Warning', reason: 'Shoulder surfing risk', detail: 'Suspicious gaze intersects the confidential screen region.', confidence: 89, action: 'Privacy blur enabled', icon: Eye },
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
  const [events, setEvents] = useState<Event[]>([])
  const [menu, setMenu] = useState(false)

  const simulate = (key: keyof typeof threats) => {
    const threat = threats[key]
    setActive(threat)
    setEvents(old => [{ id: Date.now(), title: threat.reason, time: now(), confidence: threat.confidence, action: threat.action, mode: threat.mode }, ...old].slice(0, 4))
    document.getElementById('demo')?.scrollIntoView({ behavior: 'smooth', block: 'start' })
  }
  const reset = () => setActive(null)

  useEffect(() => {
    const close = () => setMenu(false)
    window.addEventListener('resize', close)
    return () => window.removeEventListener('resize', close)
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
            <div className="signal s1"><Smartphone/><span>Device scan</span><b>Clear</b></div>
            <div className="signal s2"><ScanFace/><span>Identity</span><b>Verified</b></div>
            <div className="signal s3"><Eye/><span>Gaze field</span><b>Aligned</b></div>
          </div>
        </div>
      </section>

      <section className="trust-strip"><div className="shell"><span>ENGINEERED FOR</span><b>FINANCIAL SERVICES</b><i/><b>HEALTHCARE</b><i/><b>DEFENSE</b><i/><b>SECURE REMOTE WORK</b></div></section>

      <section className="section shell" id="demo">
        <SectionHead kicker="INTERACTIVE PROTOTYPE" title="Put the dashboard under pressure." text="Trigger a simulated optical threat and watch the zero-trust interface respond in real time." />
        <div className={`demo-shell ${active ? active.mode.toLowerCase() : 'secure'}`}>
          <div className="demo-topbar">
            <div><span className="mini-logo"><Shield size={15}/></span><b>MERIDIAN</b><span className="classified">INTERNAL · CONFIDENTIAL</span></div>
            <div className="status-cluster"><span className="pulse"/><span>SECURITY MODE</span><b>{active?.mode.toUpperCase() || 'SECURE'}</b></div>
          </div>
          {active && <div className="threat-banner">
            <div className="threat-icon"><active.icon/></div><div><b>{active.reason}</b><span>{active.detail}</span></div>
            <div className="confidence"><span>CONFIDENCE</span><b>{active.confidence}%</b></div><div className="banner-meta"><span>{now()}</span><b>{active.action}</b></div>
          </div>}
          <div className="demo-body">
            <aside className="side-rail"><div className="rail-icon active"><Blocks/></div><div className="rail-icon"><Activity/></div><div className="rail-icon"><Users/></div><div className="rail-icon"><Database/></div><div className="rail-icon"><Shield/></div></aside>
            <div className="dashboard-wrap">
              <div className={`dashboard ${active ? 'obscured' : ''}`}>
                <div className="dash-heading"><div><small>EXECUTIVE OVERVIEW</small><h3>Risk & Revenue Intelligence</h3></div><span>FY 2026 · Q3</span></div>
                <div className="metric-grid">
                  <Metric label="NET REVENUE" value="$48.26M" trend="+8.2%" icon={CircleDollarSign}/>
                  <Metric label="RISK EXPOSURE" value="$1.84M" trend="−12.4%" icon={ShieldAlert}/>
                  <Metric label="SECURITY SCORE" value="94.8" trend="+2.1 pts" icon={ShieldCheck}/>
                  <Metric label="ACTIVE SESSIONS" value="1,284" trend="Verified" icon={Users}/>
                </div>
                <div className="dash-grid">
                  <div className="dash-card chart-card"><CardTitle title="Revenue trajectory" tag="LIVE"/><div className="chart"><div className="chart-fill"/><svg viewBox="0 0 600 160" preserveAspectRatio="none"><path d="M0,140 C60,128 80,105 130,113 S210,88 250,95 S330,60 370,69 S430,28 480,45 S550,15 600,20"/></svg><div className="chart-labels"><span>APR</span><span>MAY</span><span>JUN</span><span>JUL</span><span>AUG</span><span>SEP</span></div></div></div>
                  <div className="dash-card compliance"><CardTitle title="Compliance posture" tag="6 CONTROLS"/><div className="score-ring"><div><b>96</b><span>/100</span></div></div><div className="control-row"><span><i className="ok"/>SOC 2 Type II</span><b>PASS</b></div><div className="control-row"><span><i className="ok"/>ISO 27001</span><b>PASS</b></div></div>
                  <div className="dash-card access"><CardTitle title="Privileged access log" tag="TODAY"/><table><thead><tr><th>IDENTITY</th><th>RESOURCE</th><th>RISK</th><th>TIME</th></tr></thead><tbody>
                    <tr><td><i className="avatar">AK</i>A. Kapoor</td><td>Revenue Vault</td><td><span className="risk low">LOW</span></td><td>10:42</td></tr>
                    <tr><td><i className="avatar blue">MN</i>M. Novak</td><td>Client Ledger</td><td><span className="risk medium">MED</span></td><td>10:18</td></tr>
                    <tr><td><i className="avatar purple">RL</i>R. Liu</td><td>Forecast Model</td><td><span className="risk low">LOW</span></td><td>09:56</td></tr>
                  </tbody></table></div>
                  <div className="dash-card alerts"><CardTitle title="Security alerts" tag="2 OPEN"/><div className="alert-row"><TriangleAlert/><div><b>Impossible travel blocked</b><span>Policy engine · 8 min ago</span></div><strong>HIGH</strong></div><div className="alert-row minor"><KeyRound/><div><b>Key rotation completed</b><span>Secrets vault · 34 min ago</span></div><strong>INFO</strong></div></div>
                </div>
              </div>
              {active && <div className="lock-overlay"><div className="lock-symbol"><LockKeyhole/></div><span>ZERO-TRUST PROTECTION ACTIVE</span><h3>Sensitive data secured</h3><p>{active.action}. Clear the detected risk before resuming this session.</p><button onClick={reset}><RefreshCw/> Reset secure session</button></div>}
            </div>
          </div>
        </div>
        <div className="simulation-panel">
          <div className="sim-copy"><span>DETECTION SIMULATOR</span><h3>Test a threat scenario</h3><p>This static demo uses safe, deterministic events. No camera or personal data is captured.</p></div>
          <div className="sim-buttons"><button onClick={() => simulate('phone')}><Smartphone/><span><b>Phone detected</b><small>Simulate camera capture</small></span></button><button onClick={() => simulate('observer')}><UserRoundX/><span><b>Unauthorized observer</b><small>Simulate second face</small></span></button><button onClick={() => simulate('shoulder')}><Eye/><span><b>Shoulder surfing</b><small>Simulate gaze overlap</small></span></button><button className="reset" onClick={reset}><RefreshCw/><span><b>Reset session</b><small>Return to secure</small></span></button></div>
        </div>
        <div className="event-log">
          <div className="log-head"><div><Radio/><span><b>Security event stream</b><small>SESSION LEDGER · LOCAL</small></span></div><span className="connected"><i/> MONITORING</span></div>
          {events.length === 0 ? <div className="empty-log"><ShieldCheck/><div><b>No threats in this session</b><span>Use the simulator above to generate an auditable security event.</span></div></div> : <div className="log-rows">{events.map(e => <div className="log-row" key={e.id}><span className={`event-severity ${e.mode.toLowerCase()}`}>{e.mode}</span><div><b>{e.title}</b><span>{e.action}</span></div><span>{e.confidence}% confidence</span><time>{e.time}</time></div>)}</div>}
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
          <Tech title="Frontend demo" icon={Code2} status="IMPLEMENTED" items={['React + TypeScript', 'Vite static export', 'Responsive CSS system', 'Interactive threat simulator', 'GitHub Pages workflow']}/>
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
