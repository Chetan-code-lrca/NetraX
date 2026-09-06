function Header({ systemStatus }) {
  const isOffline = systemStatus === 'BACKEND OFFLINE'
  return <header className="site-header"><div className="brand"><div className="brand-mark" aria-hidden="true">◈</div><div><h1>NETRAX</h1><p>AI-Based Detection of Cyber Threats in Unidirectional IP Traffic</p></div></div><div className="header-actions"><div className={`monitoring-status ${isOffline ? 'offline' : ''}`}><span className="status-dot" aria-hidden="true" />{systemStatus}</div><span className="last-update">Last update · not connected</span><button className="refresh-button" type="button" onClick={() => window.location.reload()}>Refresh</button></div></header>
}
export default Header
