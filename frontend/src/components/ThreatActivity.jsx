import StatusBadge from './StatusBadge'

function ThreatActivity({ alerts, models }) {
  const countsFor = (name) => alerts.filter((alert) => alert.threat_class === name).length
  const maxCount = Math.max(...models.map((model) => countsFor(model.name)), 1)
  const detected = alerts.filter((alert) => alert.status === 'DETECTED').length
  const review = alerts.filter((alert) => alert.status === 'AMBIGUOUS').length
  const distribution = [['DETECTED', 'DETECTED', detected], ['AMBIGUOUS', 'NEEDS REVIEW', review]]

  return <section className="activity-grid" aria-label="Live threat activity"><article className="section activity-panel"><div className="section-heading"><div><h2>Threat activity</h2><p>Observed positive finding volume by threat class.</p></div><span className="section-note">Real analysis results</span></div><div className="vertical-chart" role="img" aria-label="Threat activity counts by threat class">{models.map((model) => { const count = countsFor(model.name); return <div className="chart-column" key={model.name}><strong>{count || ''}</strong><div className="bar-zone"><i style={{ height: `${(count / maxCount) * 100}%` }} /></div><span>{model.name}</span></div> })}</div></article><article className="section distribution-panel"><div className="section-heading"><div><h2>Alert decisions</h2><p>Status counts derived only from returned alerts.</p></div></div><div className="distribution-list">{distribution.map(([status, label, count]) => <div className="distribution-row" key={status}><StatusBadge status={status} /><strong>{count}</strong><span><b>{label}</b>{status === 'DETECTED' ? 'Evidence supports a threat decision.' : 'Suspicious but incomplete one-way evidence.'}</span></div>)}</div></article></section>
}
export default ThreatActivity
