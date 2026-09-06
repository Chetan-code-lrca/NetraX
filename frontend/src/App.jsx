import { useEffect, useRef, useState } from 'react'
import './App.css'
import AnalysisProgress from './components/AnalysisProgress'
import AlertDetails from './components/AlertDetails'
import Header from './components/Header'
import NetworkPath from './components/NetworkPath'
import RecentAlerts from './components/RecentAlerts'
import SecuritySummary from './components/SecuritySummary'
import TrafficAnalysisView from './components/TrafficAnalysisView'
import TrafficInput from './components/TrafficInput'
import ThreatActivity from './components/ThreatActivity'
import ThreatModelGrid from './components/ThreatModelGrid'
import { threatModels } from './data/threatModels'
import { normalizeAnalysisResponse } from './models/analysis'
import { analyzeTraffic } from './services/api'

const ANALYSIS_STATES = {
  NO_FILE: 'no_file',
  READY: 'ready',
  ANALYZING: 'analyzing',
  COMPLETE: 'complete',
  ERROR: 'error',
  BACKEND_OFFLINE: 'backend_offline',
}

function App() {
  const [trafficFile, setTrafficFile] = useState(null)
  const [recordCount, setRecordCount] = useState(null)
  const [analysisStatus, setAnalysisStatus] = useState(ANALYSIS_STATES.NO_FILE)
  const [analysis, setAnalysis] = useState(null)
  const [error, setError] = useState('')
  const [selectedAlertId, setSelectedAlertId] = useState(null)
  const abortRef = useRef(null)
  const selectedFileRef = useRef(null)

  useEffect(() => () => abortRef.current?.abort(), [])

  const alerts = analysisStatus === ANALYSIS_STATES.COMPLETE ? analysis?.alerts ?? [] : []
  const selectedAlert = alerts.find((alert) => alert.alert_id === selectedAlertId)

  const handleFile = async (file) => {
    abortRef.current?.abort()
    selectedFileRef.current = file
    setTrafficFile(file)
    setRecordCount(null)
    setAnalysis(null)
    setError('')
    setSelectedAlertId(null)
    setAnalysisStatus(file ? ANALYSIS_STATES.READY : ANALYSIS_STATES.NO_FILE)
    if (file?.name.toLowerCase().endsWith('.csv')) {
      const contents = await file.text()
      if (selectedFileRef.current === file) {
        setRecordCount(Math.max(contents.trim().split(/\r?\n/).length - 1, 0))
      }
    }
  }

  const startAnalysis = async () => {
    if (!trafficFile) return
    setError('')
    setAnalysisStatus(ANALYSIS_STATES.ANALYZING)
    abortRef.current = new AbortController()
    try {
      const response = await analyzeTraffic(trafficFile, abortRef.current.signal)
      const normalized = normalizeAnalysisResponse(response, trafficFile)
      setAnalysis(normalized)
      setAnalysisStatus(normalized.status)
      if (normalized.status === ANALYSIS_STATES.COMPLETE) {
        setSelectedAlertId(normalized.alerts[0]?.alert_id ?? null)
      } else if (normalized.status === ANALYSIS_STATES.ERROR) {
        setError(response.message ?? 'Analysis request failed.')
      }
    } catch (requestError) {
      if (requestError.name === 'AbortError') { setAnalysisStatus(selectedFileRef.current ? ANALYSIS_STATES.READY : ANALYSIS_STATES.NO_FILE); return }
      setError(requestError.message)
      setAnalysisStatus(requestError.backendOffline ? ANALYSIS_STATES.BACKEND_OFFLINE : ANALYSIS_STATES.ERROR)
    }
  }

  const stopAnalysis = () => abortRef.current?.abort()
  const resetAnalysis = () => { abortRef.current?.abort(); selectedFileRef.current = null; setTrafficFile(null); setRecordCount(null); setAnalysisStatus(ANALYSIS_STATES.NO_FILE); setAnalysis(null); setError(''); setSelectedAlertId(null) }
  const headerStatus = analysisStatus === ANALYSIS_STATES.BACKEND_OFFLINE ? 'BACKEND OFFLINE' : analysisStatus === ANALYSIS_STATES.COMPLETE ? 'ANALYSIS COMPLETE' : 'ANALYSIS SERVICE READY'

  return (
    <div className="app-shell">
      <Header systemStatus={headerStatus} />
      <main className="dashboard">
        <TrafficInput file={trafficFile} recordCount={recordCount} status={analysisStatus} error={error} onFile={handleFile} onStart={startAnalysis} onStop={stopAnalysis} onReset={resetAnalysis} />
        <NetworkPath alert={selectedAlert} />
        <AnalysisProgress status={analysisStatus} analysis={analysis} />
        <SecuritySummary summary={analysis?.summary} totalFlows={analysis?.flows_processed ?? null} isComplete={analysisStatus === ANALYSIS_STATES.COMPLETE} />
        <ThreatActivity alerts={alerts} models={threatModels} />
        <section className="event-workflow" aria-label="Security event workflow">
          <RecentAlerts alerts={alerts} selectedAlertId={selectedAlertId} onSelectAlert={setSelectedAlertId} />
          <AlertDetails alert={selectedAlert} />
          <TrafficAnalysisView alert={selectedAlert} />
        </section>
        <ThreatModelGrid models={threatModels} alerts={alerts} analysisStatus={analysisStatus} />
        <footer className="footer">NetraX · Passive one-way detection · Evidence-aware results for unidirectional traffic</footer>
      </main>
    </div>
  )
}

export default App
