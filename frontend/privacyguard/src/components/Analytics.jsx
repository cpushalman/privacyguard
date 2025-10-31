import React, { useState, useEffect } from "react";

const Analytics = () => {
  const [threats, setThreats] = useState([]);
  const [networks, setNetworks] = useState([]);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    fetchData();
  }, []);

  const fetchData = async () => {
    try {
      // Fetch threats
      const threatsResponse = await fetch(
        "http://localhost:5000/api/threats?limit=20"
      );
      const threatsData = await threatsResponse.json();
      setThreats(threatsData.threats || []);

      // Fetch network history
      const networksResponse = await fetch(
        "http://localhost:5000/api/networks/history?limit=50"
      );
      const networksData = await networksResponse.json();
      setNetworks(networksData.networks || []);
    } catch (error) {
      console.error("Failed to fetch analytics data:", error);
    } finally {
      setLoading(false);
    }
  };

  const getSeverityColor = (severity) => {
    switch (severity?.toUpperCase()) {
      case "CRITICAL":
        return "#dc2626";
      case "HIGH":
        return "#ea580c";
      case "MEDIUM":
        return "#d97706";
      case "LOW":
        return "#65a30d";
      default:
        return "#6b7280";
    }
  };

  const getRiskColor = (level) => {
    switch (level?.toUpperCase()) {
      case "HIGH":
        return "#ef4444";
      case "MEDIUM":
        return "#f59e0b";
      case "LOW":
        return "#10b981";
      default:
        return "#6b7280";
    }
  };

  if (loading) {
    return (
      <div style={{ padding: "2rem", textAlign: "center" }}>
        <div style={{ fontSize: "1.2rem", color: "#666" }}>
          Loading analytics...
        </div>
      </div>
    );
  }

  return (
    <div style={{ padding: "2rem" }}>
      <div
        style={{
          background: "linear-gradient(135deg, #667eea 0%, #764ba2 100%)",
          color: "white",
          padding: "2rem",
          borderRadius: "12px",
          marginBottom: "2rem",
        }}
      >
        <h1 style={{ margin: 0, fontSize: "2rem" }}>📈 Analytics & Reports</h1>
        <p style={{ margin: "0.5rem 0 0 0", opacity: 0.9 }}>
          View your security history and threat analytics
        </p>
      </div>

      {/* Recent Threats */}
      <div
        style={{
          background: "white",
          padding: "1.5rem",
          borderRadius: "12px",
          marginBottom: "2rem",
          boxShadow: "0 4px 6px rgba(0,0,0,0.1)",
        }}
      >
        <h2 style={{ marginTop: 0, marginBottom: "1rem" }}>
          🚨 Recent Threats
        </h2>
        {threats.length === 0 ? (
          <p style={{ color: "#999", textAlign: "center", padding: "2rem" }}>
            No threats detected yet
          </p>
        ) : (
          <div
            style={{
              maxHeight: "400px",
              overflowY: "auto",
            }}
          >
            {threats.map((threat, idx) => (
              <div
                key={idx}
                style={{
                  background: "#fef2f2",
                  border: `2px solid ${getSeverityColor(threat.severity)}`,
                  padding: "1rem",
                  borderRadius: "8px",
                  marginBottom: "1rem",
                  borderLeft: `4px solid ${getSeverityColor(threat.severity)}`,
                }}
              >
                <div
                  style={{
                    display: "flex",
                    justifyContent: "space-between",
                    marginBottom: "0.5rem",
                  }}
                >
                  <div style={{ fontWeight: 600, color: "#1f2937" }}>
                    {threat.type}
                  </div>
                  <span
                    style={{
                      background: getSeverityColor(threat.severity) + "20",
                      color: getSeverityColor(threat.severity),
                      padding: "0.25rem 0.75rem",
                      borderRadius: "4px",
                      fontSize: "0.75rem",
                      fontWeight: 600,
                    }}
                  >
                    {threat.severity?.toUpperCase()}
                  </span>
                </div>
                <div
                  style={{
                    fontSize: "0.875rem",
                    color: "#666",
                    marginBottom: "0.5rem",
                  }}
                >
                  {threat.description}
                </div>
                {threat.network_ssid && (
                  <div style={{ fontSize: "0.75rem", color: "#999" }}>
                    Network: <strong>{threat.network_ssid}</strong>
                  </div>
                )}
                <div
                  style={{
                    fontSize: "0.75rem",
                    color: "#999",
                    marginTop: "0.5rem",
                  }}
                >
                  {new Date(threat.detected_at).toLocaleString()}
                </div>
              </div>
            ))}
          </div>
        )}
      </div>

      {/* Network History */}
      <div
        style={{
          background: "white",
          padding: "1.5rem",
          borderRadius: "12px",
          boxShadow: "0 4px 6px rgba(0,0,0,0.1)",
        }}
      >
        <h2 style={{ marginTop: 0, marginBottom: "1rem" }}>
          📡 Network Scan History
        </h2>
        {networks.length === 0 ? (
          <p style={{ color: "#999", textAlign: "center", padding: "2rem" }}>
            No networks scanned yet
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
                    Risk Score
                  </th>
                  <th
                    style={{
                      textAlign: "left",
                      padding: "1rem",
                      fontWeight: 600,
                    }}
                  >
                    Risk Level
                  </th>
                  <th
                    style={{
                      textAlign: "left",
                      padding: "1rem",
                      fontWeight: 600,
                    }}
                  >
                    Scans
                  </th>
                  <th
                    style={{
                      textAlign: "left",
                      padding: "1rem",
                      fontWeight: 600,
                    }}
                  >
                    Last Seen
                  </th>
                </tr>
              </thead>
              <tbody>
                {networks.map((net, idx) => (
                  <tr key={idx} style={{ borderBottom: "1px solid #f0f0f0" }}>
                    <td style={{ padding: "1rem", fontWeight: 500 }}>
                      {net.ssid}
                    </td>
                    <td
                      style={{
                        padding: "1rem",
                        fontSize: "0.85rem",
                        fontFamily: "monospace",
                      }}
                    >
                      {net.bssid}
                    </td>
                    <td style={{ padding: "1rem" }}>
                      {net.encryption || "Unknown"}
                    </td>
                    <td style={{ padding: "1rem" }}>
                      <div
                        style={{
                          display: "inline-block",
                          background: getRiskColor(net.risk_level) + "20",
                          color: getRiskColor(net.risk_level),
                          padding: "0.25rem 0.75rem",
                          borderRadius: "4px",
                          fontWeight: 600,
                        }}
                      >
                        {net.risk_score}
                      </div>
                    </td>
                    <td style={{ padding: "1rem" }}>
                      <span
                        style={{
                          background: getRiskColor(net.risk_level) + "20",
                          color: getRiskColor(net.risk_level),
                          padding: "0.25rem 0.75rem",
                          borderRadius: "4px",
                          fontSize: "0.875rem",
                          fontWeight: 600,
                        }}
                      >
                        {net.risk_level || "N/A"}
                      </span>
                    </td>
                    <td style={{ padding: "1rem", textAlign: "center" }}>
                      {net.scan_count}
                    </td>
                    <td
                      style={{
                        padding: "1rem",
                        fontSize: "0.875rem",
                        color: "#666",
                      }}
                    >
                      {new Date(net.last_seen).toLocaleString()}
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

export default Analytics;
