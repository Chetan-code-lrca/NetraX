function SecuritySummary({ summary, totalFlows, isComplete }) {
  const value = (number) => isComplete ? number ?? 'Not supplied' : '—'
  const cards = [['Threats Detected', value(summary?.detected), 'Evidence supports a threat decision', 'detected'], ['No Sufficient Evidence', value(summary?.insufficient), 'Returned by the analysis summary, not by alert count', 'no-threat'], ['Total Flows', value(totalFlows), 'Supplied by the analysis service', 'flows']]
  return <section className="security-summary" aria-label="Security summary"><div className="console-heading"><div><p className="eyebrow">Security monitoring console</p><h2>Network security state</h2></div><p>Passive, evidence-aware analysis of observed one-way traffic.</p></div><div className="summary-grid">{cards.map(([label, value, detail, className]) => <article className={`summary-card ${className}`} key={label}><p className="label">{label}</p><strong>{value}</strong><small>{detail}</small></article>)}</div></section>
}
export default SecuritySummary
