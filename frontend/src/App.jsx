import React from "react";
import "./App.css";

function App() {
  return (
    <div className="app">
      {/* Header */}
      <header className="header">
        <div className="logo">
          <span className="logo-icon">🛡️</span>
          <div>
            <h1>NetraX</h1>
            <p>Cyber Threat Intelligence</p>
          </div>
        </div>

        <div className="system-status">
          <span className="status-dot"></span>
          System Online
        </div>
      </header>

      {/* Navigation */}
      <nav className="navbar">
        <button className="active">Dashboard</button>
        <button>Threat Map</button>
        <button>Analytics</button>
        <button>Alerts</button>
        <button>Network</button>
      </nav>

      {/* Main Content */}
      <main className="main-content">

        {/* Page heading */}
        <section className="page-heading">
          <div>
            <h2>Cyber Threat Monitoring Dashboard</h2>
            <p>
              AI-based detection and monitoring of cyber threats in
              unidirectional IP networks.
            </p>
          </div>

          <button className="refresh-btn">
            🔄 Refresh Data
          </button>
        </section>

        {/* Statistics */}
        <section className="stats-grid">

          <div className="stat-card">
            <div className="stat-icon">🟢</div>
            <div>
              <p>System Status</p>
              <h3>Operational</h3>
            </div>
          </div>

          <div className="stat-card">
            <div className="stat-icon">⚠️</div>
            <div>
              <p>Active Threats</p>
              <h3>12</h3>
            </div>
          </div>

          <div className="stat-card">
            <div className="stat-icon">🚨</div>
            <div>
              <p>Critical Alerts</p>
              <h3>3</h3>
            </div>
          </div>

          <div className="stat-card">
            <div className="stat-icon">📡</div>
            <div>
              <p>Network Nodes</p>
              <h3>48</h3>
            </div>
          </div>

        </section>

        {/* Dashboard Grid */}
        <section className="dashboard-grid">

          {/* Threat Overview */}
          <div className="dashboard-card large-card">
            <div className="card-header">
              <div>
                <h3>Threat Overview</h3>
                <p>Real-time cyber threat activity</p>
              </div>

              <span className="live-badge">
                ● LIVE
              </span>
            </div>

            <div className="threat-chart">
              <div className="chart-bars">
                <div className="bar" style={{ height: "35%" }}></div>
                <div className="bar" style={{ height: "55%" }}></div>
                <div className="bar" style={{ height: "45%" }}></div>
                <div className="bar" style={{ height: "70%" }}></div>
                <div className="bar" style={{ height: "50%" }}></div>
                <div className="bar" style={{ height: "85%" }}></div>
                <div className="bar" style={{ height: "65%" }}></div>
                <div className="bar" style={{ height: "90%" }}></div>
                <div className="bar" style={{ height: "60%" }}></div>
                <div className="bar" style={{ height: "75%" }}></div>
                <div className="bar" style={{ height: "45%" }}></div>
                <div className="bar" style={{ height: "80%" }}></div>
              </div>
            </div>
          </div>

          {/* Threat Levels */}
          <div className="dashboard-card">
            <div className="card-header">
              <div>
                <h3>Threat Levels</h3>
                <p>Current risk classification</p>
              </div>
            </div>

            <div className="threat-levels">

              <div className="level">
                <div>
                  <span>Critical</span>
                </div>
                <strong>3</strong>
              </div>

              <div className="level">
                <div>
                  <span>High</span>
                </div>
                <strong>5</strong>
              </div>

              <div className="level">
                <div>
                  <span>Medium</span>
                </div>
                <strong>4</strong>
              </div>

              <div className="level">
                <div>
                  <span>Low</span>
                </div>
                <strong>8</strong>
              </div>

            </div>
          </div>

        </section>

        {/* Recent Alerts */}
        <section className="dashboard-card alerts-card">

          <div className="card-header">
            <div>
              <h3>Recent Security Alerts</h3>
              <p>Latest detected activities</p>
            </div>

            <button className="view-all">
              View All
            </button>
          </div>

          <div className="alerts-table">

            <div className="alert-row alert-heading">
              <span>Threat</span>
              <span>Source IP</span>
              <span>Severity</span>
              <span>Status</span>
            </div>

            <div className="alert-row">
              <span>Suspicious Network Activity</span>
              <span>192.168.1.24</span>
              <span className="severity critical">Critical</span>
              <span className="status investigating">
                Investigating
              </span>
            </div>

            <div className="alert-row">
              <span>Port Scanning Detected</span>
              <span>10.0.0.18</span>
              <span className="severity high">High</span>
              <span className="status blocked">
                Blocked
              </span>
            </div>

            <div className="alert-row">
              <span>Unusual Traffic Pattern</span>
              <span>172.16.0.45</span>
              <span className="severity medium">Medium</span>
              <span className="status monitoring">
                Monitoring
              </span>
            </div>

            <div className="alert-row">
              <span>Unauthorized Connection</span>
              <span>192.168.2.31</span>
              <span className="severity high">High</span>
              <span className="status blocked">
                Blocked
              </span>
            </div>

          </div>

        </section>

        {/* Footer */}
        <footer>
          <p>
            NetraX • AI-Based Cyber Threat Detection System
          </p>

          <p>
            Last updated: Just now
          </p>
        </footer>

      </main>
    </div>
  );
}

export default App;