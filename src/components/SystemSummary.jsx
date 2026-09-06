function SystemSummary({ alerts, totalFlows }) {
  const detected = alerts.filter((alert) => alert.status === 'DETECTED').length
  const review = alerts.filter((alert) => alert.status === 'AMBIGUOUS').length
  const insufficient = alerts.filter((alert) => alert.status === 'INSUFFICIENT').length
  const cards = [['No Threat', insufficient, 'No sufficient evidence for a threat decision', 'no-threat'], ['Threats Detected', detected, 'Evidence supports a threat decision', 'detected'], ['Needs Review', review, 'Suspicious, but ambiguous from one-way observation', 'review'], ['Total Flows', totalFlows, 'Observed in the current demo workspace', 'flows']]
  return <section className="summary-grid" aria-label="System summary">{cards.map(([label, value, detail, className]) => <article className={`summary-card ${className}`} key={label}><p className="label">{label}</p><strong>{value}</strong><small>{detail}</small></article>)}</section>
}
export default SystemSummary
