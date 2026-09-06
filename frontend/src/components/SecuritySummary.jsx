function SecuritySummary({ alerts, totalFlows, isComplete }) {
  const detected = alerts.filter((alert) => alert.status === 'DETECTED').length
  const review = alerts.filter((alert) => alert.status === 'AMBIGUOUS').length
  const insufficient = alerts.filter((alert) => alert.status === 'INSUFFICIENT').length
  const value = (number) => isComplete ? number ?? 'Not supplied' : '—'
  const cards = [['Threats Detected', value(detected), 'Evidence supports a threat decision', 'detected'], ['Needs Review', value(review), 'Suspicious with incomplete one-way evidence', 'review'], ['No Sufficient Evidence', value(insufficient), 'Not a confirmed-safe finding', 'no-threat'], ['Total Flows', value(totalFlows), 'Supplied by the analysis service', 'flows']]
  return <section className="security-summary" aria-label="Security summary"><div className="console-heading"><div><p className="eyebrow">Security monitoring console</p><h2>Network security state</h2></div><p>Passive, evidence-aware analysis of observed one-way traffic.</p></div><div className="summary-grid">{cards.map(([label, value, detail, className]) => <article className={`summary-card ${className}`} key={label}><p className="label">{label}</p><strong>{value}</strong><small>{detail}</small></article>)}</div></section>
}
export default SecuritySummary
