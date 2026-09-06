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

function App() {
  const [trafficFile, setTrafficFile] = useState(null)
  const [recordCount, setRecordCount] = useState(null)
  const [analysisStatus, setAnalysisStatus] = useState('idle')
  const [analysis, setAnalysis] = useState(null)
  const [error, setError] = useState('')
  const [selectedAlertId, setSelectedAlertId] = useState(null)
  const abortRef = useRef(null)

  useEffect(() => () => abortRef.current?.abort(), [])

  const alerts = analysisStatus === 'complete' ? analysis?.alerts ?? [] : []
  const selectedAlert = alerts.find((alert) => alert.flow_id === selectedAlertId)

  const handleFile = async (file) => {
    abortRef.current?.abort()
    setTrafficFile(file)
    setRecordCount(null)
    setAnalysis(null)
    setError('')
    setSelectedAlertId(null)
    setAnalysisStatus(file ? 'ready' : 'idle')
    if (file?.name.toLowerCase().endsWith('.csv')) {
      const contents = await file.text()
      setRecordCount(Math.max(contents.trim().split(/\r?\n/).length - 1, 0))
    }
  }

  const startAnalysis = async () => {
    if (!trafficFile) return
    setError('')
    setAnalysisStatus('uploading')
    abortRef.current = new AbortController()
    try {
      setAnalysisStatus('analyzing')
      const response = await analyzeTraffic(trafficFile, abortRef.current.signal)
      const normalized = normalizeAnalysisResponse(response, trafficFile)
      setAnalysis(normalized)
      if (normalized.status === 'complete') {
        setAnalysisStatus('complete')
        setSelectedAlertId(normalized.alerts[0]?.flow_id ?? null)
      }
    } catch (requestError) {
      if (requestError.name === 'AbortError') { setAnalysisStatus('ready'); return }
      setError(requestError.message)
      setAnalysisStatus(requestError.backendOffline ? 'backend_offline' : 'error')
    }
  }

  const stopAnalysis = () => abortRef.current?.abort()
  const resetAnalysis = () => { abortRef.current?.abort(); setTrafficFile(null); setRecordCount(null); setAnalysisStatus('idle'); setAnalysis(null); setError(''); setSelectedAlertId(null) }
  const headerStatus = analysisStatus === 'backend_offline' ? 'BACKEND OFFLINE' : analysisStatus === 'complete' ? 'ANALYSIS COMPLETE' : 'ANALYSIS SERVICE READY'

  return (
    <div className="app-shell">
      <Header systemStatus={headerStatus} />
      <main className="dashboard">
        <TrafficInput file={trafficFile} recordCount={recordCount} status={analysisStatus} error={error} onFile={handleFile} onStart={startAnalysis} onStop={stopAnalysis} onReset={resetAnalysis} />
        <NetworkPath alert={selectedAlert} />
        <AnalysisProgress status={analysisStatus} analysis={analysis} />
        <SecuritySummary alerts={alerts} totalFlows={analysis?.flows_processed ?? null} isComplete={analysisStatus === 'complete'} />
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
