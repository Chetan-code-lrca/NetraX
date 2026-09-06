import { useRef } from 'react'

function TrafficInput({ file, recordCount, status, error, onFile, onStart, onStop, onReset }) {
  const inputRef = useRef(null)
  const ready = status === 'ready'
  const type = file ? file.name.split('.').pop().toUpperCase() : '—'
  const statusLabel = { no_file: 'NO FILE', ready: 'READY', analyzing: 'ANALYZING', complete: 'COMPLETE', error: 'ERROR', backend_offline: 'BACKEND OFFLINE' }[status]
  return <section className="traffic-input section" aria-labelledby="traffic-title"><div className="section-heading"><div><p className="detail-eyebrow">Traffic input</p><h2 id="traffic-title">Captured traffic replay</h2><p>Upload a captured traffic file for passive replay and analysis. Uploading a PCAP does not transmit traffic.</p></div><span className="replay-status">{statusLabel}</span></div><div className="input-grid"><div className={`drop-zone ${file ? 'loaded' : ''}`}><input ref={inputRef} type="file" accept=".pcap,.pcapng,.csv" onChange={(event) => onFile(event.target.files?.[0] ?? null)} hidden /><strong>{file ? file.name : 'No traffic loaded'}</strong><span>{file ? `${type} · ${(file.size / 1024).toFixed(1)} KB${recordCount !== null ? ` · ${recordCount} CSV records` : ' · flow count supplied after analysis'}` : 'Supported: PCAP / PCAPNG / CSV'}</span>{error && <em className="input-error">{error}</em>}</div><div className="traffic-controls"><button type="button" onClick={() => inputRef.current?.click()}>Choose file</button><button type="button" className="primary" disabled={!ready} onClick={onStart}>Start analysis</button><button type="button" disabled={status !== 'analyzing'} onClick={onStop}>Stop</button><button type="button" onClick={onReset}>Reset</button></div></div></section>
}
export default TrafficInput
