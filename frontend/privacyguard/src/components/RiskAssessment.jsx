import React, { useState, useEffect } from "react";

const RiskAssessment = () => {
  const [scanData, setScanData] = useState(null);
  const [loading, setLoading] = useState(false);
  const [riskScore, setRiskScore] = useState(0);
  const [threatsList, setThreatsList] = useState([]);
  const [recommendations, setRecommendations] = useState([]);

  const performScan = async () => {
    setLoading(true);
    try {
      // Get current network scan with detailed info
      const response = await fetch("http://localhost:5000/api/scan", {
        method: "GET",
        headers: { "Content-Type": "application/json" },
      });

      const scanResult = await response.json();
      console.log("Full scan result:", scanResult);
      console.log("Current network:", scanResult.current_network);

      // Use current_network which has BSSID, encryption, signal, etc
      const network = scanResult.current_network;

      if (network && network.ssid) {
        console.log("Network BSSID:", network.bssid);
        console.log("Network Signal Strength:", network.signal_strength);
        console.log("Network Encryption:", network.encryption_type);
        setScanData(network);

        // Calculate risk score based on actual data
        let riskScore = 20; // baseline

        const encryption = (network.encryption_type || "unknown").toUpperCase();

        if (encryption.includes("OPEN") || encryption === "UNKNOWN") {
          riskScore += 50;
        } else if (encryption.includes("WEP")) {
          riskScore += 40;
        } else if (encryption.includes("WPA") && !encryption.includes("WPA3")) {
          riskScore += 15;
        }

        // DNS latency factor
        if (network.dns_latency_ms > 200) {
          riskScore += 10;
        }

        // Packet loss factor
        if (network.packet_loss_percent > 10) {
          riskScore += 15;
        }

        // ARP issues
        if (network.arp_issues && network.arp_issues.length > 0) {
          riskScore += 30;
        }

        // Captive portal
        if (network.captive_portal) {
          riskScore += 15;
        }

        setRiskScore(Math.min(100, riskScore));

        // Fetch threats for this network
        const threatsResponse = await fetch(
          "http://localhost:5000/api/threats"
        );
        const threatsData = await threatsResponse.json();
        setThreatsList(threatsData.threats || []);

        // Generate recommendations
        generateRecommendations(network, Math.min(100, riskScore));
      } else {
        alert(
          "No network information available. Make sure you are connected to WiFi."
        );
      }
    } catch (error) {
      console.error("Scan failed:", error);
      alert("Failed to perform scan: " + error.message);
    } finally {
      setLoading(false);
    }
  };

  const generateRecommendations = (network, score) => {
    const recs = [];

    if (!network.bssids || network.bssids.length === 0) {
      recs.push("✅ Network appears secure - Standard precautions recommended");
      setRecommendations(recs);
      return;
    }

    const bssid = network.bssids[0];
    const encryption = (bssid.encryption || "OPEN").toUpperCase();

    if (encryption.includes("OPEN") || encryption.includes("WEP")) {
      recs.push("⚠️ Use a VPN immediately - Network has no/weak encryption");
    }

    if (encryption.includes("WPA") && !encryption.includes("WPA3")) {
      recs.push(
        "ℹ️ Upgrade to WPA3 for better security - Current encryption is older"
      );
    }

    if (score >= 70) {
      recs.push("🚨 HIGH RISK - Avoid sensitive transactions on this network");
    } else if (score >= 40) {
      recs.push("⚠️ MEDIUM RISK - Use VPN for additional protection");
    } else {
      recs.push("✅ LOW RISK - Network appears relatively secure");
    }

    if (bssid.signal) {
      const signalValue = parseInt(bssid.signal);
      if (signalValue < 30) {
        recs.push("� Weak signal - Connection may be unstable");
      }
    }

    if (recs.length === 1) {
      recs.push(
        "💡 Tip: Always use strong passwords and enable two-factor authentication"
      );
    }

    setRecommendations(recs);
  };

  const getRiskColor = (score) => {
    if (score >= 70) return "#ef4444";
    if (score >= 40) return "#f59e0b";
    return "#10b981";
  };

  const getRiskLevel = (score) => {
    if (score >= 70) return "CRITICAL";
    if (score >= 40) return "MEDIUM";
    return "LOW";
  };

  const drawGaugeChart = (value) => {
    const percentage = Math.min(100, Math.max(0, value));
    const circumference = 2 * Math.PI * 45;
    const strokeDashoffset = circumference - (percentage / 100) * circumference;

    return (
      <svg
        width="150"
        height="150"
        style={{ margin: "0 auto", display: "block" }}
      >
        <circle
          cx="75"
          cy="75"
          r="45"
          fill="none"
          stroke="#e5e7eb"
          strokeWidth="8"
        />
        <circle
          cx="75"
          cy="75"
          r="45"
          fill="none"
          stroke={getRiskColor(value)}
          strokeWidth="8"
          strokeDasharray={circumference}
          strokeDashoffset={strokeDashoffset}
          transform="rotate(-90 75 75)"
          style={{ transition: "stroke-dashoffset 0.5s ease" }}
        />
        <text
          x="75"
          y="75"
          textAnchor="middle"
          dominantBaseline="middle"
          fontSize="24"
          fontWeight="bold"
          fill={getRiskColor(value)}
        >
          {value}
        </text>
        <text
          x="75"
          y="95"
          textAnchor="middle"
          dominantBaseline="middle"
          fontSize="12"
          fill="#666"
        >
          /100
        </text>
      </svg>
    );
  };

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
        <h1 style={{ margin: 0, fontSize: "2rem" }}>
          📡 Network Risk Assessment
        </h1>
        <p style={{ margin: "0.5rem 0 0 0", opacity: 0.9 }}>
          Comprehensive security analysis of your connected network
        </p>
      </div>

      <div
        style={{
          background: "white",
          padding: "2rem",
          borderRadius: "12px",
          marginBottom: "2rem",
          boxShadow: "0 4px 6px rgba(0,0,0,0.1)",
          textAlign: "center",
        }}
      >
        <button
          onClick={performScan}
          disabled={loading}
          style={{
            padding: "1rem 2rem",
            fontSize: "1rem",
            background: loading ? "#ccc" : "#667eea",
            color: "white",
            border: "none",
            borderRadius: "8px",
            cursor: loading ? "not-allowed" : "pointer",
            fontWeight: 600,
            marginBottom: "1rem",
          }}
        >
          {loading ? "🔄 Analyzing Network..." : "🔬 Analyze Current Network"}
        </button>
      </div>

      {scanData && (
        <>
          {/* Risk Score Display */}
          <div
            style={{
              background: getRiskColor(riskScore) + "10",
              border: `2px solid ${getRiskColor(riskScore)}`,
              padding: "2rem",
              borderRadius: "12px",
              marginBottom: "2rem",
            }}
          >
            <div
              style={{
                display: "grid",
                gridTemplateColumns: "1fr 1fr",
                gap: "2rem",
              }}
            >
              <div>
                <h2 style={{ marginTop: 0, color: "#333" }}>Risk Score</h2>
                {drawGaugeChart(riskScore)}
              </div>
              <div
                style={{
                  display: "flex",
                  flexDirection: "column",
                  justifyContent: "center",
                }}
              >
                <div style={{ marginBottom: "1rem" }}>
                  <div
                    style={{
                      fontSize: "0.875rem",
                      color: "#666",
                      marginBottom: "0.25rem",
                    }}
                  >
                    Level:
                  </div>
                  <div
                    style={{
                      fontSize: "1.5rem",
                      fontWeight: 700,
                      color: getRiskColor(riskScore),
                    }}
                  >
                    {getRiskLevel(riskScore)}
                  </div>
                </div>
                <div>
                  <div
                    style={{
                      fontSize: "0.875rem",
                      color: "#666",
                      marginBottom: "0.25rem",
                    }}
                  >
                    Network:
                  </div>
                  <div style={{ fontSize: "1.1rem", fontWeight: 600 }}>
                    {scanData.ssid || "Unknown"}
                  </div>
                </div>
              </div>
            </div>
          </div>

          {/* Network Details */}
          <div
            style={{
              background: "white",
              padding: "1.5rem",
              borderRadius: "12px",
              marginBottom: "2rem",
              boxShadow: "0 4px 6px rgba(0,0,0,0.1)",
            }}
          >
            <h3 style={{ marginTop: 0 }}>📋 Network Details</h3>
            <div
              style={{
                display: "grid",
                gridTemplateColumns: "repeat(auto-fit, minmax(250px, 1fr))",
                gap: "1rem",
              }}
            >
              <DetailItem label="SSID" value={scanData.ssid} />
              <DetailItem label="BSSID" value={scanData.bssid || "Unknown"} />
              <DetailItem
                label="Encryption"
                value={scanData.encryption_type || "Unknown"}
              />
              <DetailItem
                label="Signal Strength"
                value={
                  scanData.signal_strength
                    ? `${scanData.signal_strength} dBm`
                    : "N/A"
                }
              />
              <DetailItem label="Channel" value={scanData.channel || "N/A"} />
              <DetailItem
                label="Interface"
                value={scanData.interface || "N/A"}
              />
            </div>
          </div>

          {/* Network Security Details */}
          <div
            style={{
              background: "white",
              padding: "1.5rem",
              borderRadius: "12px",
              marginBottom: "2rem",
              boxShadow: "0 4px 6px rgba(0,0,0,0.1)",
            }}
          >
            <h3 style={{ marginTop: 0 }}>🔍 Security Metrics</h3>
            <div
              style={{
                display: "grid",
                gridTemplateColumns: "repeat(auto-fit, minmax(200px, 1fr))",
                gap: "1rem",
              }}
            >
              <FeatureCard
                name="DNS Latency"
                value={
                  scanData.dns_latency_ms
                    ? `${scanData.dns_latency_ms}ms`
                    : "N/A"
                }
              />
              <FeatureCard
                name="Packet Loss"
                value={
                  scanData.packet_loss_percent !== undefined
                    ? `${scanData.packet_loss_percent}%`
                    : "N/A"
                }
              />
              <FeatureCard
                name="Captive Portal"
                value={scanData.captive_portal ? "Detected" : "Not Detected"}
              />
              <FeatureCard
                name="TLS Cert Valid"
                value={scanData.tls_cert_validity === 1 ? "Valid" : "Invalid"}
              />
              <FeatureCard
                name="ARP Issues"
                value={scanData.arp_issues?.length || 0}
              />
              <FeatureCard name="Risk Score" value={riskScore} />
            </div>
          </div>

          {/* Threats */}
          {threatsList.length > 0 && (
            <div
              style={{
                background: "#fef2f2",
                border: "2px solid #ef4444",
                padding: "1.5rem",
                borderRadius: "12px",
                marginBottom: "2rem",
              }}
            >
              <h3 style={{ marginTop: 0, color: "#dc2626" }}>
                🚨 Threats Detected
              </h3>
              {threatsList.map((threat, idx) => (
                <div
                  key={idx}
                  style={{
                    background: "white",
                    padding: "1rem",
                    borderRadius: "8px",
                    marginBottom: "0.5rem",
                    borderLeft: `4px solid #ef4444`,
                  }}
                >
                  <div style={{ fontWeight: 600, marginBottom: "0.25rem" }}>
                    {threat.type}
                  </div>
                  <div style={{ fontSize: "0.875rem", color: "#666" }}>
                    {threat.description}
                  </div>
                  <div
                    style={{
                      fontSize: "0.75rem",
                      color: "#999",
                      marginTop: "0.5rem",
                    }}
                  >
                    Severity:{" "}
                    <span style={{ fontWeight: 600 }}>{threat.severity}</span>
                  </div>
                </div>
              ))}
            </div>
          )}

          {/* Recommendations */}
          <div
            style={{
              background: "#fef3c7",
              border: "2px solid #f59e0b",
              padding: "1.5rem",
              borderRadius: "12px",
              marginBottom: "2rem",
            }}
          >
            <h3 style={{ marginTop: 0, color: "#d97706" }}>
              🛡️ Recommendations
            </h3>
            {recommendations.map((rec, idx) => (
              <div
                key={idx}
                style={{
                  padding: "0.75rem",
                  marginBottom: "0.5rem",
                  background: "white",
                  borderRadius: "6px",
                }}
              >
                {rec}
              </div>
            ))}
          </div>

          {/* Debug Panel - Raw Data */}
          <div
            style={{
              background: "#f0f0f0",
              border: "2px solid #999",
              padding: "1rem",
              borderRadius: "8px",
              marginTop: "2rem",
              fontFamily: "monospace",
              fontSize: "0.75rem",
              maxHeight: "300px",
              overflow: "auto",
            }}
          >
            <div
              style={{
                fontWeight: "bold",
                marginBottom: "0.5rem",
                color: "#333",
              }}
            >
              📊 Raw Data (Debug):
            </div>
            <pre
              style={{
                margin: 0,
                color: "#333",
                whiteSpace: "pre-wrap",
                wordBreak: "break-all",
              }}
            >
              {JSON.stringify(scanData, null, 2)}
            </pre>
          </div>
        </>
      )}
    </div>
  );
};

const DetailItem = ({ label, value }) => (
  <div
    style={{
      padding: "1rem",
      background: "#f8f9fa",
      borderRadius: "8px",
    }}
  >
    <div
      style={{ fontSize: "0.875rem", color: "#666", marginBottom: "0.5rem" }}
    >
      {label}
    </div>
    <div
      style={{ fontSize: "1.1rem", fontWeight: 600, wordBreak: "break-all" }}
    >
      {value || "N/A"}
    </div>
  </div>
);

const FeatureCard = ({ name, value }) => (
  <div
    style={{
      padding: "1rem",
      background: "#f8f9fa",
      borderRadius: "8px",
      border: "1px solid #e5e7eb",
    }}
  >
    <div
      style={{
        fontSize: "0.75rem",
        color: "#666",
        marginBottom: "0.5rem",
        textTransform: "uppercase",
      }}
    >
      {name.replace(/_/g, " ")}
    </div>
    <div style={{ fontSize: "1.25rem", fontWeight: 700, color: "#667eea" }}>
      {typeof value === "number" ? value.toFixed(2) : value}
    </div>
  </div>
);

export default RiskAssessment;
