function TrafficAnalysisView({ alert }) {
  if (!alert) return <section className="flow-analysis section"><h2>Current flow</h2><p>No analyzed flow selected.</p></section>
  return <section className="flow-analysis section" aria-labelledby="flow-title"><div className="section-heading"><div><h2 id="flow-title">Current flow analysis</h2><p>Forward traffic metadata will be shown when supplied by the analysis service.</p></div><span className="section-note">No reverse traffic assumed</span></div><div className="flow-facts"><span>Source<b>{alert.source ?? 'Unavailable from input'}</b></span><span>Destination<b>{alert.destination ?? 'Unavailable from input'}</b></span><span>Protocol<b>Not supplied</b></span><span>Destination port<b>Not supplied</b></span><span>Packet count<b>Not supplied</b></span><span>Flow duration<b>Not supplied</b></span><span>Forward bytes<b>Not supplied</b></span><span>Forward packet rate<b>Not supplied</b></span></div></section>
}
export default TrafficAnalysisView
