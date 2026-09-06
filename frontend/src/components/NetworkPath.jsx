function NetworkPath({ alert }) {
  const source = alert?.source ?? 'Captured source'
  const destination = alert?.destination ?? 'Captured destination'
  return <section className="network-path section" aria-labelledby="path-title"><div className="section-heading"><div><h2 id="path-title">One-way observation path</h2><p>Traffic continues to its destination. NetraX observes a passive copy only.</p></div><span className="read-only">Read-only observation</span></div><div className="path-diagram"><div className="endpoint"><small>Source</small><strong>{source}</strong></div><div className="path-line"><span>ONE-WAY TRAFFIC →</span><i /></div><div className="observer"><strong>NETRAX</strong><span>Passive observer</span><small>NO PROBES · NO RETURN TRAFFIC · NO MITIGATION COMMAND</small></div><div className="path-line"><span>TRAFFIC CONTINUES →</span><i /></div><div className="endpoint"><small>Destination</small><strong>{destination}</strong></div></div></section>
}
export default NetworkPath
