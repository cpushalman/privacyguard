import React, { useState, useEffect } from "react";
import socketService from "../services/socket";

const Dashboard = () => {
  const [networks, setNetworks] = useState([]);
  const [currentNetwork, setCurrentNetwork] = useState(null);
  const [scanning, setScanning] = useState(false);
  const [connectionStatus, setConnectionStatus] = useState("disconnected");
  const [riskScore, setRiskScore] = useState(0);
  const [threats, setThreats] = useState([]);
  const [protectionActive, setProtectionActive] = useState(false);
  const [scanHistory, setScanHistory] = useState([]);
  const [statistics, setStatistics] = useState({
    totalNetworks: 0,
    highRiskNetworks: 0,
    totalThreats: 0,
    protectionSessions: 0,
    avgRiskScore: 0,
  });

  useEffect(() => {
    initializeConnection();
    fetchStatistics();
  }, []);

  const initializeConnection = async () => {
    try {
      await socketService.connect();
      setConnectionStatus("connected");

      socketService.onNetworkUpdate((data) => {
        console.log("Network update received:", data);
        handleNetworkUpdate(data);
      });

      socketService.onScanStatus((data) => {
        console.log("Scan status:", data);
        setScanning(data.status === "started");
      });

      socketService.onScanError((data) => {
        console.error("Scan error:", data);
      });
    } catch (error) {
      console.error("Connection failed:", error);
      setConnectionStatus("error");
    }
  };

  const handleNetworkUpdate = (data) => {
    if (data.data && data.data.networks) {
      const transformedNetworks = data.data.networks.map((net, idx) => ({
        id: idx,
        ssid: net.ssid,
        bssid: net.bssids?.[0]?.bssid || "Unknown",
        encryption: net.bssids?.[0]?.encryption || "Unknown",
        signal: net.bssids?.[0]?.signal || "Unknown",
        channel: net.bssids?.[0]?.channel || "Unknown",
        riskScore: Math.floor(Math.random() * 100),
        threats: [],
      }));
      setNetworks(transformedNetworks);
    }
  };

  const startScan = () => {
    setScanning(true);
    socketService.requestSingleScan();
  };

  const fetchStatistics = async () => {
    try {
      const response = await fetch("http://localhost:5000/api/stats");
      const data = await response.json();
      setStatistics({
        totalNetworks: data.total_networks_scanned || 0,
        highRiskNetworks: data.high_risk_networks || 0,
        totalThreats: data.total_threats_detected || 0,
        protectionSessions: data.protection_sessions || 0,
        avgRiskScore: data.average_risk_score || 0,
      });
    } catch (error) {
      console.error("Failed to fetch statistics:", error);
    }
  };

  const enableProtection = async () => {
    try {
      const response = await fetch(
        "http://localhost:5000/api/protection/enable",
        {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ method: "wireguard" }),
        }
      );
      const data = await response.json();
      setProtectionActive(true);
      alert(`Protection enabled: ${data.message}`);
    } catch (error) {
      console.error("Failed to enable protection:", error);
    }
  };

  return (
    <div style={{ padding: "2rem" }}>
      {/* Status Bar */}
      <div
        style={{
          background: "linear-gradient(135deg, #667eea 0%, #764ba2 100%)",
          color: "white",
          padding: "2rem",
          borderRadius: "12px",
          marginBottom: "2rem",
        }}
      >
        <h1 style={{ margin: 0, fontSize: "2rem" }}>
          🛡️ Privacy Guard Dashboard
        </h1>
        <p style={{ margin: "0.5rem 0 0 0", opacity: 0.9 }}>
          Connection:{" "}
          <span
            style={{
              color: connectionStatus === "connected" ? "#10b981" : "#ef4444",
            }}
          >
            {connectionStatus === "connected"
              ? "🟢 Connected"
              : "🔴 Disconnected"}
          </span>
        </p>
      </div>

      {/* Statistics Grid */}
      <div
        style={{
          display: "grid",
          gridTemplateColumns: "repeat(auto-fit, minmax(200px, 1fr))",
          gap: "1rem",
          marginBottom: "2rem",
        }}
      >
        <StatCard
          title="Networks Scanned"
          value={statistics.totalNetworks}
          color="#667eea"
        />
        <StatCard
          title="High-Risk Networks"
          value={statistics.highRiskNetworks}
          color="#ef4444"
        />
        <StatCard
          title="Threats Detected"
          value={statistics.totalThreats}
          color="#f59e0b"
        />
        <StatCard
          title="Protection Sessions"
          value={statistics.protectionSessions}
          color="#10b981"
        />
      </div>

      {/* Control Panel */}
      <div
        style={{
          background: "white",
          padding: "1.5rem",
          borderRadius: "12px",
          marginBottom: "2rem",
          boxShadow: "0 4px 6px rgba(0,0,0,0.1)",
        }}
      >
        <h2 style={{ marginTop: 0 }}>🔍 Network Scanner</h2>
        <div style={{ display: "flex", gap: "1rem", flexWrap: "wrap" }}>
          <button
            onClick={startScan}
            disabled={scanning}
            style={{
              padding: "0.75rem 1.5rem",
              background: scanning ? "#ccc" : "#667eea",
              color: "white",
              border: "none",
              borderRadius: "8px",
              cursor: scanning ? "not-allowed" : "pointer",
              fontWeight: 600,
            }}
          >
            {scanning ? "🔄 Scanning..." : "🔍 Start Scan"}
          </button>
          <button
            onClick={enableProtection}
            style={{
              padding: "0.75rem 1.5rem",
              background: protectionActive ? "#10b981" : "#667eea",
              color: "white",
              border: "none",
              borderRadius: "8px",
              cursor: "pointer",
              fontWeight: 600,
            }}
          >
            {protectionActive ? "✓ Protection Active" : "🔐 Enable Protection"}
          </button>
          <button
            onClick={fetchStatistics}
            style={{
              padding: "0.75rem 1.5rem",
              background: "#764ba2",
              color: "white",
              border: "none",
              borderRadius: "8px",
              cursor: "pointer",
              fontWeight: 600,
            }}
          >
            📊 Refresh Stats
          </button>
        </div>
      </div>

      {/* Networks List */}
      <div
        style={{
          background: "white",
          padding: "1.5rem",
          borderRadius: "12px",
          boxShadow: "0 4px 6px rgba(0,0,0,0.1)",
        }}
      >
        <h2 style={{ marginTop: 0 }}>📡 Available Networks</h2>
        {networks.length === 0 ? (
          <p style={{ color: "#999", textAlign: "center", padding: "2rem" }}>
            No networks scanned yet. Click "Start Scan" to begin.
          </p>
        ) : (
          <div style={{ overflowX: "auto" }}>
            <table style={{ width: "100%", borderCollapse: "collapse" }}>
              <thead>
                <tr style={{ borderBottom: "2px solid #e5e7eb" }}>
                  <th
                    style={{
                      textAlign: "left",
                      padding: "1rem",
                      fontWeight: 600,
                    }}
                  >
                    SSID
                  </th>
                  <th
                    style={{
                      textAlign: "left",
                      padding: "1rem",
                      fontWeight: 600,
                    }}
                  >
                    BSSID
                  </th>
                  <th
                    style={{
                      textAlign: "left",
                      padding: "1rem",
                      fontWeight: 600,
                    }}
                  >
                    Encryption
                  </th>
                  <th
                    style={{
                      textAlign: "left",
                      padding: "1rem",
                      fontWeight: 600,
                    }}
                  >
                    Signal
                  </th>
                  <th
                    style={{
                      textAlign: "left",
                      padding: "1rem",
                      fontWeight: 600,
                    }}
                  >
                    Risk
                  </th>
                </tr>
              </thead>
              <tbody>
                {networks.map((net) => (
                  <tr
                    key={net.id}
                    style={{ borderBottom: "1px solid #f0f0f0" }}
                  >
                    <td style={{ padding: "1rem" }}>{net.ssid}</td>
                    <td
                      style={{
                        padding: "1rem",
                        fontSize: "0.85rem",
                        fontFamily: "monospace",
                      }}
                    >
                      {net.bssid}
                    </td>
                    <td style={{ padding: "1rem" }}>{net.encryption}</td>
                    <td style={{ padding: "1rem" }}>{net.signal}</td>
                    <td style={{ padding: "1rem" }}>
                      <RiskBadge score={net.riskScore} />
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </div>
    </div>
  );
};

const StatCard = ({ title, value, color }) => (
  <div
    style={{
      background: "white",
      padding: "1.5rem",
      borderRadius: "12px",
      boxShadow: "0 4px 6px rgba(0,0,0,0.1)",
      borderLeft: `4px solid ${color}`,
    }}
  >
    <div
      style={{ fontSize: "0.875rem", color: "#666", marginBottom: "0.5rem" }}
    >
      {title}
    </div>
    <div style={{ fontSize: "2rem", fontWeight: 700, color: color }}>
      {value}
    </div>
  </div>
);

const RiskBadge = ({ score }) => {
  let color, text;
  if (score >= 70) {
    color = "#ef4444";
    text = "🔴 High";
  } else if (score >= 40) {
    color = "#f59e0b";
    text = "🟡 Medium";
  } else {
    color = "#10b981";
    text = "🟢 Low";
  }

  return (
    <span
      style={{
        background: color + "20",
        color: color,
        padding: "0.25rem 0.75rem",
        borderRadius: "6px",
        fontSize: "0.875rem",
        fontWeight: 500,
      }}
    >
      {text}
    </span>
  );
};

export default Dashboard;
