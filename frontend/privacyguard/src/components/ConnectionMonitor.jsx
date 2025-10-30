import React, { useState, useEffect } from "react";

const ConnectionMonitor = ({ network, onBackToScanner }) => {
  const [arpTable, setArpTable] = useState([]);
  const [monitoring, setMonitoring] = useState(false);
  const [threats, setThreats] = useState([]);
  const [connectionStats, setConnectionStats] = useState({
    connected: true,
    duration: "00:00:00",
    dataTransferred: "0 MB",
    packetsAnalyzed: 0,
  });

  // Mock ARP table data - replace with actual API calls
  const mockArpEntries = [
    {
      id: "arp-001",
      ip: "192.168.1.1",
      mac: "00:1B:44:11:3A:B7",
      vendor: "Cisco Systems",
      status: "router",
      lastSeen: new Date(),
      suspicious: false,
    },
    {
      id: "arp-002",
      ip: "192.168.1.100",
      mac: "AA:BB:CC:DD:EE:FF",
      vendor: "Unknown",
      status: "active",
      lastSeen: new Date(),
      suspicious: true,
      threats: ["MAC address spoofing", "Unknown vendor"],
    },
    {
      id: "arp-003",
      ip: "192.168.1.45",
      mac: "11:22:33:44:55:66",
      vendor: "Apple Inc",
      status: "active",
      lastSeen: new Date(),
      suspicious: false,
    },
  ];

  const startMonitoring = async () => {
    setMonitoring(true);

    try {
      // Replace with actual API call to start monitoring
      // const response = await fetch('/api/start-monitoring', {
      //   method: 'POST',
      //   headers: { 'Content-Type': 'application/json' },
      //   body: JSON.stringify({ networkId: network.id })
      // })

      // Simulate initial ARP scan
      await new Promise((resolve) => setTimeout(resolve, 1500));
      setArpTable(mockArpEntries);

      // Start periodic updates
      const interval = setInterval(updateArpTable, 5000);
      return () => clearInterval(interval);
    } catch (err) {
      console.error("Failed to start monitoring:", err);
      setMonitoring(false);
    }
  };

  const updateArpTable = async () => {
    try {
      // Replace with actual API call
      // const response = await fetch('/api/arp-table')
      // const data = await response.json()

      // Simulate occasional new threats
      if (Math.random() > 0.8) {
        const newThreat = {
          id: `threat-${Date.now()}`,
          type: "ARP Spoofing Detected",
          description: "Suspicious MAC address change detected",
          severity: "high",
          timestamp: new Date(),
          affectedDevice: "192.168.1.100",
        };
        setThreats((prev) => [newThreat, ...prev]);
      }

      // Update stats
      setConnectionStats((prev) => ({
        ...prev,
        packetsAnalyzed:
          prev.packetsAnalyzed + Math.floor(Math.random() * 50) + 10,
      }));
    } catch (err) {
      console.error("Failed to update ARP table:", err);
    }
  };

  const stopMonitoring = () => {
    setMonitoring(false);
    // Call API to stop monitoring
  };

  const disconnectNetwork = async () => {
    try {
      // Replace with actual API call
      // await fetch('/api/disconnect', { method: 'POST' })
      onBackToScanner();
    } catch (err) {
      console.error("Failed to disconnect:", err);
    }
  };

  const formatTime = (seconds) => {
    const hours = Math.floor(seconds / 3600);
    const minutes = Math.floor((seconds % 3600) / 60);
    const secs = seconds % 60;
    return `${hours.toString().padStart(2, "0")}:${minutes
      .toString()
      .padStart(2, "0")}:${secs.toString().padStart(2, "0")}`;
  };

  useEffect(() => {
    let timeInterval;
    if (connectionStats.connected) {
      let seconds = 0;
      timeInterval = setInterval(() => {
        seconds++;
        setConnectionStats((prev) => ({
          ...prev,
          duration: formatTime(seconds),
        }));
      }, 1000);
    }
    return () => clearInterval(timeInterval);
  }, [connectionStats.connected]);

  useEffect(() => {
    startMonitoring();
  }, []);

  return (
    <div className="connection-monitor">
      {/* Connection Status Card */}
      <div className="card" style={{ marginBottom: "1.5rem" }}>
        <div className="card-header">
          <div
            style={{
              display: "flex",
              justifyContent: "space-between",
              alignItems: "center",
            }}
          >
            <div>
              <h2 className="card-title">Connected to {network.ssid}</h2>
              <p className="card-subtitle">
                Real-time network monitoring active
              </p>
            </div>
            <div style={{ display: "flex", gap: "0.5rem" }}>
              <button className="btn btn-secondary" onClick={onBackToScanner}>
                ← Back to Scanner
              </button>
              <button className="btn btn-danger" onClick={disconnectNetwork}>
                Disconnect
              </button>
            </div>
          </div>
        </div>

        <div className="card-content">
          <div className="grid grid-cols-4">
            <div className="stat-card">
              <div className="stat-value">{connectionStats.duration}</div>
              <div className="stat-label">Connection Time</div>
            </div>
            <div className="stat-card">
              <div className="stat-value">
                {connectionStats.packetsAnalyzed}
              </div>
              <div className="stat-label">Packets Analyzed</div>
            </div>
            <div className="stat-card">
              <div className="stat-value">{threats.length}</div>
              <div className="stat-label">Threats Detected</div>
            </div>
            <div className="stat-card">
              <div className="stat-value">
                {monitoring ? "🟢 Active" : "🔴 Inactive"}
              </div>
              <div className="stat-label">Monitor Status</div>
            </div>
          </div>
        </div>
      </div>

      {/* Threats Alert Card */}
      {threats.length > 0 && (
        <div
          className="card"
          style={{ marginBottom: "1.5rem", border: "2px solid #ef4444" }}
        >
          <div className="card-header" style={{ background: "#fef2f2" }}>
            <h3 className="card-title" style={{ color: "#dc2626" }}>
              🚨 Security Threats Detected
            </h3>
          </div>
          <div className="card-content">
            {threats.slice(0, 3).map((threat) => (
              <div key={threat.id} className="threat-item">
                <div className="threat-header">
                  <span className="threat-type">{threat.type}</span>
                  <span className="threat-time">
                    {threat.timestamp.toLocaleTimeString()}
                  </span>
                </div>
                <p className="threat-description">{threat.description}</p>
                <p className="threat-device">
                  Affected: {threat.affectedDevice}
                </p>
              </div>
            ))}
          </div>
        </div>
      )}

      {/* ARP Table Card */}
      <div className="card">
        <div className="card-header">
          <div
            style={{
              display: "flex",
              justifyContent: "space-between",
              alignItems: "center",
            }}
          >
            <div>
              <h3 className="card-title">ARP Table Monitor</h3>
              <p className="card-subtitle">
                Monitoring network devices for suspicious activity
              </p>
            </div>
            <button
              className={`btn ${monitoring ? "btn-danger" : "btn-success"}`}
              onClick={monitoring ? stopMonitoring : startMonitoring}
            >
              {monitoring ? <>🛑 Stop Monitoring</> : <>▶️ Start Monitoring</>}
            </button>
          </div>
        </div>

        <div className="card-content">
          {arpTable.length === 0 ? (
            <div
              style={{ textAlign: "center", padding: "2rem", color: "#64748b" }}
            >
              <div className="loading-spinner" style={{ margin: "0 auto" }} />
              <p style={{ marginTop: "1rem" }}>
                {monitoring
                  ? "Scanning network devices..."
                  : "Monitoring stopped"}
              </p>
            </div>
          ) : (
            <div className="arp-table">
              <div className="table-header">
                <div className="table-row">
                  <div className="table-cell header">IP Address</div>
                  <div className="table-cell header">MAC Address</div>
                  <div className="table-cell header">Vendor</div>
                  <div className="table-cell header">Status</div>
                  <div className="table-cell header">Last Seen</div>
                </div>
              </div>
              <div className="table-body">
                {arpTable.map((entry) => (
                  <div
                    key={entry.id}
                    className={`table-row ${
                      entry.suspicious ? "suspicious" : ""
                    }`}
                  >
                    <div className="table-cell">{entry.ip}</div>
                    <div className="table-cell">{entry.mac}</div>
                    <div className="table-cell">{entry.vendor}</div>
                    <div className="table-cell">
                      <span
                        className={`status-badge ${
                          entry.suspicious ? "status-danger" : "status-safe"
                        }`}
                      >
                        {entry.suspicious ? "⚠️ Suspicious" : "✅ Normal"}
                      </span>
                    </div>
                    <div className="table-cell">
                      {entry.lastSeen.toLocaleTimeString()}
                    </div>
                  </div>
                ))}
              </div>
            </div>
          )}
        </div>
      </div>
    </div>
  );
};

export default ConnectionMonitor;
