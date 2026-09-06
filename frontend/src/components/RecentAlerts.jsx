import { useState } from 'react'
import StatusBadge from './StatusBadge'
import { formatConfidence } from '../models/analysis'

const ALL_FILTER = 'ALL'
const inputValue = (value) => value ?? 'Unavailable from input'

function RecentAlerts({ alerts, selectedAlertId, onSelectAlert }) {
  const [filter, setFilter] = useState(ALL_FILTER)
  const filters = [ALL_FILTER, ...new Set(alerts.map((alert) => alert.threat_class).filter(Boolean))]
  const activeFilter = filters.includes(filter) ? filter : ALL_FILTER
  const filteredAlerts = activeFilter === ALL_FILTER ? alerts : alerts.filter((alert) => alert.threat_class === activeFilter)

  return <section className="section recent-alerts" aria-labelledby="alerts-title"><div className="section-heading"><div><h2 id="alerts-title">Live alert feed</h2><p>Positive findings returned by the analysis service.</p></div><span className="section-note">Selectable events</span></div><div className="alert-filter" aria-label="Filter by threat type">{filters.map((item) => <button className={activeFilter === item ? 'selected' : ''} key={item} type="button" onClick={() => setFilter(item)}>{item}</button>)}</div><div className="table-wrap"><table className="flow-table"><thead><tr><th>Status</th><th>Threat</th><th>Confidence</th><th>Source</th><th>Destination</th><th>Time</th></tr></thead><tbody>{filteredAlerts.length ? filteredAlerts.map((alert) => <tr className={selectedAlertId === alert.flow_id ? 'selected' : ''} key={alert.flow_id}><td><StatusBadge status={alert.status} /></td><td><button className="threat-button" type="button" onClick={() => onSelectAlert(alert.flow_id)}>{alert.threat_class}<small>{alert.flow_id ?? 'No flow ID'}</small></button></td><td className="confidence">{formatConfidence(alert.confidence)}</td><td>{inputValue(alert.source)}</td><td>{inputValue(alert.destination)}</td><td>{alert.timestamp ?? 'Not supplied'}</td></tr>) : <tr className="empty-row"><td colSpan="6">{alerts.length ? `No ${activeFilter} alerts in this analysis.` : 'No analysis results. Upload captured traffic and start backend analysis.'}</td></tr>}</tbody></table></div></section>
}
export default RecentAlerts
