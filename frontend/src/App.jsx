import { useEffect, useMemo, useRef, useState } from 'react'
import { analyzeTraffic, checkHealth } from './services/api'

const THREATS = [
  ['PortScan', 'PortScan'],
  ['DDoS', 'DDoS'],
  ['C2_Beaconing', 'C2 Beaconing'],
  ['DGA_DNS_Tunneling', 'DGA / DNS Tunneling'],
  ['Encrypted_Malware', 'Encrypted Malware'],
  ['Data_Exfiltration', 'Data Exfiltration'],
]

function App() {
  const inputRef = useRef(null)
  const abortRef = useRef(null)
  const [backend, setBackend] = useState('checking')
  const [file, setFile] = useState(null)
  const [phase, setPhase] = useState('idle')
  const [result, setResult] = useState(null)
  const [error, setError] = useState('')
  const [filter, setFilter] = useState('ALL')
  const [selectedId, setSelectedId] = useState('')
  const [notifications, setNotifications] = useState([])
  const [dragActive, setDragActive] = useState(false)

  const health = async () => {
    try {
      await checkHealth()
      setBackend('online')
    } catch {
      setBackend('offline')
    }
  }

  useEffect(() => {
    health()
    const timer = setInterval(health, 15000)
    return () => {
      clearInterval(timer)
      abortRef.current?.abort()
    }
  }, [])

  const alerts = result?.alerts ?? []
  const summary = result?.summary ?? {}

  const filtered = useMemo(
    () => filter === 'ALL' ? alerts : alerts.filter(a => a.threat_class === filter),
    [alerts, filter],
  )

  const selected = alerts.find(a => a.alert_id === selectedId) ?? filtered[0] ?? null

  const counts = useMemo(() => {
    const value = Object.fromEntries(THREATS.map(([key]) => [key, 0]))
    alerts.forEach(a => {
      if (value[a.threat_class] !== undefined) value[a.threat_class] += 1
    })
    return value
  }, [alerts])

  function choose(fileValue) {
    setError('')
    if (!fileValue) return
    const ext = fileValue.name.toLowerCase().split('.').pop()
    if (!['pcap', 'pcapng', 'csv'].includes(ext)) {
      setError('Use a PCAP, PCAPNG, or NetraX-compatible flow CSV.')
      setPhase('error')
      return
    }
    if (fileValue.size > 100 * 1024 * 1024) {
      setError('The maximum upload size is 100 MB.')
      setPhase('error')
      return
    }
    setFile(fileValue)
    setPhase('ready')
    setResult(null)
    setSelectedId('')
    setFilter('ALL')
  }

  async function analyze() {
    if (!file || backend !== 'online') return
    abortRef.current?.abort()
    abortRef.current = new AbortController()
    setPhase('analyzing')
    setError('')
    setResult(null)
    try {
      const data = await analyzeTraffic(file, abortRef.current.signal)
      setResult(data)
      setPhase(data.status === 'complete' ? 'complete' : 'error')
      setSelectedId(data.alerts?.[0]?.alert_id ?? '')

      // Notifications are derived only from actual DETECTED findings
      // returned by the NetraX API. Group by threat class so a large
      // finding set does not create hundreds of identical popups.
      const detected = (data.alerts ?? []).filter(
        (alert) => alert.status === 'DETECTED',
      )

      const grouped = Object.values(
        detected.reduce((groups, alert) => {
          const key = alert.threat_class || 'Unknown threat'

          if (!groups[key]) {
            groups[key] = {
              threat_class: key,
              count: 0,
              confidence: Number(alert.confidence ?? 0),
              alert_id: alert.alert_id ?? '',
            }
          }

          groups[key].count += 1
          groups[key].confidence = Math.max(
            groups[key].confidence,
            Number(alert.confidence ?? 0),
          )

          return groups
        }, {}),
      )

      setNotifications(grouped)
    } catch (cause) {
      if (cause?.name === 'AbortError') return
      setPhase('error')
      setError(cause?.message || 'Traffic analysis failed.')
    }
  }

  function handleDragEnter(event) {
    event.preventDefault()
    event.stopPropagation()
    setDragActive(true)
  }

  function handleDragOver(event) {
    event.preventDefault()
    event.stopPropagation()
    setDragActive(true)
  }

  function handleDragLeave(event) {
    event.preventDefault()
    event.stopPropagation()

    if (event.currentTarget === event.target) {
      setDragActive(false)
    }
  }

  function handleDrop(event) {
    event.preventDefault()
    event.stopPropagation()
    setDragActive(false)

    const droppedFile = event.dataTransfer?.files?.[0]
    if (droppedFile) choose(droppedFile)
  }

  function reset() {
    abortRef.current?.abort()
    setFile(null)
    setPhase('idle')
    setResult(null)
    setError('')
    setFilter('ALL')
    setSelectedId('')
    if (inputRef.current) inputRef.current.value = ''
  }

  return (
    <div className="app">
      <ToastStack
        notifications={notifications}
        alerts={alerts}
        onClose={(threatClass) =>
          setNotifications((current) =>
            current.filter(
              (item) => item.threat_class !== threatClass,
            ),
          )
        }
        onView={(alertId) => {
          if (alertId) setSelectedId(alertId)
          setNotifications([])
        }}
      />

      <header className="topbar">
        <div className="brand">
          <img src="/netrax-mark.svg" alt="" />
          <div>
            <div className="brand-name">NETRAX</div>
            <div className="brand-subtitle">AI-BASED DETECTION OF CYBER THREATS IN UNIDIRECTIONAL IP TRAFFIC</div>
          </div>
        </div>
        <div className="service-box">
          <span className={`dot ${backend}`} />
          <span>{backend === 'online' ? 'ANALYSIS SERVICE READY' : backend === 'offline' ? 'BACKEND OFFLINE' : 'CHECKING SERVICE'}</span>
          <button onClick={health}>Refresh</button>
        </div>
      </header>

      <main className="container">
        <section className="hero">
          <div>
            <div className="eyebrow">NETRAX SECURITY CONSOLE</div>
            <h1>Passive visibility for<br />one-way network traffic.</h1>
            <p>Capture first. Analyze second. Decide only from the evidence that is actually observable.</p>
          </div>
          <div className="mode-card">
            <span>OBSERVATION MODE</span>
            <strong>READ-ONLY</strong>
            <small>No probes · No return traffic · No mitigation command</small>
          </div>
        </section>

        <section className="panel upload-panel">
          <div className="section-head">
            <div><div className="eyebrow">TRAFFIC INPUT</div><h2>Captured traffic</h2></div>
            <span>PCAP · PCAPNG · NETRAX FLOW CSV</span>
          </div>
          <input
            ref={inputRef}
            hidden
            type="file"
            accept=".pcap,.pcapng,.csv"
            onChange={e => choose(e.target.files?.[0])}
          />
          <div
            className={`dropzone ${file ? 'selected' : ''} ${dragActive ? 'drag-active' : ''}`}
            role="button"
            tabIndex={0}
            onClick={() => inputRef.current?.click()}
            onKeyDown={e => {
              if (e.key === 'Enter' || e.key === ' ') {
                e.preventDefault()
                inputRef.current?.click()
              }
            }}
            onDragEnter={handleDragEnter}
            onDragOver={handleDragOver}
            onDragLeave={handleDragLeave}
            onDrop={handleDrop}
          >
            <div className="upload-symbol">{dragActive ? '↓' : '↑'}</div>
            <strong>
              {file ? file.name : dragActive ? 'Drop the capture here' : 'Drop a traffic capture here'}
            </strong>
            <span>
              {file
                ? `${(file.size / 1024 / 1024).toFixed(2)} MB · Click to replace`
                : 'Drag & drop or click to browse · PCAP · PCAPNG · NetraX flow CSV'}
            </span>
            <small>Maximum upload size: 100 MB</small>
          </div>
          <div className="upload-foot">
            <span style={{fontSize: '9px', color: '#60788c'}}>DEBUG BACKEND: {backend}</span>
            <span className="ready-state"><i className={file ? 'on' : ''} />{file ? 'Capture ready' : 'No capture selected'}</span>
            <div className="actions">
              <button className="secondary" onClick={reset}>Reset</button>
              <button className="primary" disabled={!file || backend !== 'online' || phase === 'analyzing'} onClick={analyze}>{phase === 'analyzing' ? 'Running analysis…' : 'Analyze traffic'}</button>
            </div>
          </div>
          {error && <div className="error">! <span>{error}</span></div>}
        </section>

        <section className="panel live-monitor-panel">
          <div className="section-head">
            <div>
              <div className="eyebrow">LIVE MONITORING</div>
              <h2>Continuous passive observation</h2>
            </div>
            <span className="live-badge"><i /> DEPLOYMENT MODE</span>
          </div>
          <div className="live-monitor-grid">
            <div className="live-state">
              <span className="status-ring" />
              <div>
                <strong>Live capture agent required</strong>
                <p>
                  24/7 monitoring needs a passive capture agent on the network
                  (SPAN/TAP or data diode). The browser dashboard is the viewer;
                  it does not sniff the network by itself.
                </p>
              </div>
            </div>
            <div className="live-specs">
              <span>INGEST</span>
              <strong>PCAP / flow stream</strong>
              <span>PROCESSING</span>
              <strong>Rolling flow windows</strong>
              <span>ALERTS</span>
              <strong>Real-time detector events</strong>
            </div>
          </div>
        </section>

        <section className="panel pipeline-panel">
          <div className="section-head"><div><div className="eyebrow">ANALYSIS PIPELINE</div><h2>Processing state</h2></div><strong className="phase">{phase.toUpperCase()}</strong></div>
          <div className="pipeline">
            {['Traffic input','Flow extraction','Feature extraction','Threat detection','Evidence analysis','Alert generation'].map((label, i) => (
              <div className="pipeline-cell" key={label}>
                <div className={`stage ${i === 0 || phase === 'complete' || (phase === 'analyzing' && i < 3) ? 'active' : ''}`}>
                  <span>0{i + 1}</span><b>{label}</b>
                </div>
                {i < 5 && <div className="line" />}
              </div>
            ))}
          </div>
        </section>

        <TrafficFlowVisualization phase={phase} file={file} alert={selected} />

        <section className="metrics">
          <Metric title="Flows analyzed" value={result?.flows_processed ?? '—'} note="Observed flow records" />
          <Metric title="Threat findings" value={result?.alerts_generated ?? '—'} note="Detected or review-worthy" danger={Number(result?.alerts_generated ?? 0) > 0} />
          <Metric title="Needs review" value={result ? summary.ambiguous ?? 0 : '—'} note="Ambiguous observations" />
          <Metric title="Insufficient evidence" value={result ? summary.insufficient ?? 0 : '—'} note="Not enough evidence for a finding" />
        </section>

        <section className="split">
          <div className="panel panel-body">
            <div className="section-head"><div><div className="eyebrow">THREAT ACTIVITY</div><h2>Findings by detector</h2></div><span>Returned findings</span></div>
            <div className="chart">
              {THREATS.map(([key, label]) => {
                const value = counts[key] || 0
                const max = Math.max(1, ...Object.values(counts))
                return <div className="bar-col" key={key}><em>{value}</em><div className="bar-track"><div className={`bar ${value ? 'fill' : ''}`} style={{height: `${value ? Math.max(8, value / max * 100) : 4}%`}} /></div><small>{label}</small></div>
              })}
            </div>
          </div>
          <div className="panel panel-body">
            <div className="section-head"><div><div className="eyebrow">ANALYSIS STATE</div><h2>Decision context</h2></div></div>
            <div className="decision"><div className="decision-icon">✓</div><div><b>{result ? decision(summary) : 'AWAITING CAPTURE'}</b><p>{result ? 'Decision reflects the evidence returned by the active detector pipeline.' : 'No results are shown until an analysis has completed.'}</p></div></div>
            <div className="state-list">
              <Row label="Analysis ID" value={result?.analysis_id || 'Not assigned'} mono />
              <Row label="Input" value={result?.filename || 'No file'} />
              <Row label="Type" value={result?.file_type || '—'} />
              <Row label="Alerts returned" value={result?.alerts_returned ?? '—'} />
            </div>
          </div>
        </section>

        <section className="split feed">
          <div className="panel panel-body">
            <div className="section-head"><div><div className="eyebrow">ALERT FEED</div><h2>Observed findings</h2></div><select value={filter} onChange={e => setFilter(e.target.value)}><option value="ALL">All threats</option>{THREATS.map(([key,label]) => <option value={key} key={key}>{label}</option>)}</select></div>
            {filtered.length === 0 ? <Empty text={result ? 'No findings returned by this analysis.' : 'Run an analysis to populate this feed with real detector results.'} /> : <div className="alerts">{filtered.map(alert => <button key={alert.alert_id || `${alert.threat_class}-${alert.flow_id}`} className={`alert ${selected?.alert_id === alert.alert_id ? 'selected' : ''}`} onClick={() => setSelectedId(alert.alert_id)}><span><b>{alert.threat_class}</b><small>{alert.flow_id}</small></span><Badge status={alert.status} /><strong>{Number(alert.confidence ?? 0).toFixed(2)}</strong><i>›</i></button>)}</div>}
          </div>
          <Details alert={selected} />
        </section>

        <footer><b>NETRAX</b><span>Passive observation · evidence-aware decisions</span>{result?.alerts_truncated && <span className="warn">Alert feed truncated</span>}</footer>
      </main>
    </div>
  )
}

function ToastStack({ notifications, alerts, onClose, onView }) {
  if (!notifications.length) return null

  return (
    <div className="toast-stack" aria-live="polite">
      {notifications.map((notification) => (
        <ThreatToast
          key={notification.threat_class}
          notification={notification}
          alerts={alerts}
          onClose={() => onClose(notification.threat_class)}
          onView={() => {
            const alert = alerts.find(
              (item) => item.alert_id === notification.alert_id,
            )
            onView(alert?.alert_id || '')
          }}
        />
      ))}
    </div>
  )
}

function ThreatToast({ notification, onClose, onView }) {
  return (
    <div className="threat-toast" role="status">
      <div className="toast-icon">!</div>

      <div className="toast-content">
        <div className="toast-title">THREAT DETECTED</div>
        <strong>{notification.threat_class}</strong>
        <span>
          {notification.count} finding
          {notification.count === 1 ? '' : 's'}
          {' · '}
          {Math.round(notification.confidence * 100)}% confidence
        </span>

        <div className="toast-actions">
          <button
            className="toast-view"
            type="button"
            onClick={onView}
          >
            View finding
          </button>

          <button
            className="toast-ack"
            type="button"
            onClick={onClose}
          >
            Acknowledge
          </button>
        </div>
      </div>

      <button
        className="toast-close"
        type="button"
        onClick={onClose}
        aria-label={`Close ${notification.threat_class} notification`}
      >
        ×
      </button>
    </div>
  )
}

function TrafficFlowVisualization({ phase, file, alert }) {
  const analyzing = phase === 'analyzing'
  const complete = phase === 'complete'
  const ready = Boolean(file)

  const source = alert?.source || 'Observed source'
  const destination = alert?.destination || 'Observed destination'

  const status = complete
    ? 'THREAT DECISION GENERATED'
    : analyzing
      ? 'ANALYZING OBSERVED COPY'
      : ready
        ? 'CAPTURE READY'
        : 'WAITING FOR TRAFFIC'

  const statusClass = complete ? 'complete' : analyzing ? 'analyzing' : ready ? 'ready' : ''

  return (
    <section className="panel traffic-flow">
      <div className="traffic-flow-head">
        <div>
          <div className="eyebrow">TRAFFIC FLOW VISUALIZATION</div>
          <h2>How NetraX observes one-way traffic</h2>
          <p>
            The original path remains untouched. A passive copy is observed at the
            network tap and sent to NetraX for analysis.
          </p>
        </div>

        <div className="flow-state">
          <span className={`status-led ${statusClass}`} />
          <div>
            <b>{file ? 'CAPTURE REPLAY' : 'PASSIVE OBSERVATION'}</b>
            <small>{status}</small>
          </div>
        </div>
      </div>

      <div className="flow-diagram">
        <div className="endpoint-card source-card">
          <div className="endpoint-topline">
            <span className="endpoint-tag">SOURCE</span>
            <span className="endpoint-role">CLIENT / HOST</span>
          </div>
          <div className="endpoint-icon laptop-icon" aria-hidden="true">
            <span />
          </div>
          <strong>{source}</strong>
          <small>Observed sender</small>
        </div>

        <div className="network-stage">
          <div className="traffic-caption">
            <b>ONE-WAY NETWORK TRAFFIC</b>
            <span>Packets continue from source to destination</span>
          </div>

          <div className="main-path">
            <div className="path-glow" />
            <div className="path-line" />
            <div className="packet-track">
              {Array.from({ length: 22 }, (_, i) => (
                <span
                  className={`packet-dot packet-dot-${i % 5}`}
                  key={i}
                />
              ))}
            </div>
            <div className="path-arrow">›</div>
          </div>

          <div className="tap-marker">
            <div className="tap-stem" />
            <div className="tap-card">
              <div className="tap-symbol">↔</div>
              <div>
                <b>NETWORK TAP / SPAN</b>
                <small>Passive observation point</small>
              </div>
            </div>
          </div>

          <div className="passive-branch">
            <span className="branch-dash" />
            <div>
              <b>MIRRORED COPY</b>
              <small>No probes · no return traffic</small>
            </div>
          </div>

          <div className={`netrax-card ${statusClass}`}>
            <div className="netrax-emblem">N</div>
            <div className="netrax-copy">
              <div className="netrax-title-row">
                <b>NETRAX</b>
                <span>AI ANALYSIS ENGINE</span>
              </div>
              <div className="netrax-state">
                <i />
                {status}
              </div>
            </div>
            <div className="netrax-stage-list">
              <span>FLOW</span>
              <span>FEATURES</span>
              <span>DETECTION</span>
              <span>EVIDENCE</span>
            </div>
          </div>
        </div>

        <div className="endpoint-card destination-card">
          <div className="endpoint-topline">
            <span className="endpoint-tag">DESTINATION</span>
            <span className="endpoint-role">SERVER / SERVICE</span>
          </div>
          <div className="endpoint-icon server-icon" aria-hidden="true">
            <span /><span /><span />
          </div>
          <strong>{destination}</strong>
          <small>Observed receiver</small>
        </div>
      </div>

      <div className="flow-footer">
        <div className="flow-legend">
          <span><i className="legend-traffic" />Original traffic path</span>
          <span><i className="legend-copy" />Passive observed copy</span>
          <span><i className="legend-engine" />NetraX analysis</span>
        </div>
        <div className="flow-rules">
          <span>READ-ONLY</span>
          <span>NO PROBES</span>
          <span>NO RETURN TRAFFIC</span>
          <span>NO MITIGATION COMMAND</span>
        </div>
      </div>
    </section>
  )
}

function Metric({ title, value, note, danger }) { return <div className="panel metric"><span>{title}</span><strong className={danger ? 'danger' : ''}>{value}</strong><small>{note}</small></div> }
function Row({ label, value, mono }) { return <div className="state-row"><span>{label}</span><strong className={mono ? 'mono' : ''}>{value}</strong></div> }
function Badge({ status }) { return <span className={`badge ${String(status || '').toLowerCase()}`}>{status || 'UNKNOWN'}</span> }
function Empty({ text }) { return <div className="empty"><div>—</div><b>No findings to display</b><span>{text}</span></div> }
function decision(summary) { if (Number(summary.detected || 0) > 0) return 'THREATS DETECTED'; if (Number(summary.ambiguous || 0) > 0) return 'NEEDS REVIEW'; return 'NO CURRENT FINDING' }

function Details({ alert }) {
  if (!alert) return <div className="panel panel-body details"><div className="eyebrow">FINDING DETAILS</div><div className="empty details-empty"><div>○</div><b>Select a finding</b><span>Evidence, observation limits, and flow context will appear here.</span></div></div>
  return <div className="panel panel-body details"><div className="eyebrow">FINDING DETAILS</div><div className="details-head"><div><h2>{alert.threat_class}</h2><span className="mono">{alert.flow_id}</span></div><Badge status={alert.status} /></div><div className="detail-grid"><Mini l="Confidence" v={Number(alert.confidence ?? 0).toFixed(2)} /><Mini l="Observability" v={alert.observability || '—'} /><Mini l="Separability" v={alert.observability_status || '—'} /><Mini l="Evidence coverage" v={alert.evidence_coverage == null ? '—' : `${Math.round(Number(alert.evidence_coverage) * 100)}%`} /></div><Evidence title="Observed evidence" items={alert.evidence} /><Evidence title="Available evidence" items={alert.available_evidence} /><Evidence title="Missing evidence" items={alert.missing_evidence} warning /><div className="endpoints"><div><span>Source</span><b>{alert.source || 'Not supplied'}</b></div><div><span>Destination</span><b>{alert.destination || 'Not supplied'}</b></div></div></div>
}
function Mini({ l, v }) { return <div><span>{l}</span><b>{v}</b></div> }
function Evidence({ title, items = [], warning }) { const values = Array.isArray(items) ? items : []; return <div className="evidence"><span>{title}</span>{values.length ? values.map((x,i)=><div className={warning ? 'warning' : ''} key={`${x}-${i}`}><b>{warning ? '!' : '✓'}</b>{x}</div>) : <small>None reported</small>}</div> }

export default App
