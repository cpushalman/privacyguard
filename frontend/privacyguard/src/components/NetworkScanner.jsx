import React, { useState, useEffect } from "react";
import socketService from "../services/socket";

const NetworkScanner = ({ onNetworkConnect }) => {
  const [networks, setNetworks] = useState([]);
  const [loading, setLoading] = useState(false);
  const [connecting, setConnecting] = useState(null);
  const [error, setError] = useState(null);
  const [realtimeScanning, setRealtimeScanning] = useState(false);
  const [connectionStatus, setConnectionStatus] = useState("disconnected");
  const [lastUpdateTime, setLastUpdateTime] = useState(null);

  // Mock data for demonstration - replace with actual API call
  const mockNetworks = [
    {
      id: "wifi-001",
      ssid: "HomeNetwork_5G",
      bssid: "00:1B:44:11:3A:B7",
      signal: -45,
      security: "WPA2",
      frequency: "5.2 GHz",
      risks: ["safe"],
      riskLevel: "low",
    },
    {
      id: "wifi-002",
      ssid: "CoffeeShop_Guest",
      bssid: "00:1B:44:11:3A:C8",
      signal: -67,
      security: "Open",
      frequency: "2.4 GHz",
      risks: ["open_network", "public_wifi"],
      riskLevel: "high",
    },
    {
      id: "wifi-003",
      ssid: "Office_Network",
      bssid: "00:1B:44:11:3A:D9",
      signal: -52,
      security: "WPA3",
      frequency: "5.2 GHz",
      risks: ["unknown_network"],
      riskLevel: "medium",
    },
    {
      id: "wifi-004",
      ssid: "Neighbor_WiFi",
      bssid: "00:1B:44:11:3A:EA",
      signal: -78,
      security: "WEP",
      frequency: "2.4 GHz",
      risks: ["weak_security", "old_encryption"],
      riskLevel: "high",
    },
  ];

  // Transform backend network data to frontend format
  const transformNetworkData = (backendNetworks) => {
    if (!backendNetworks || !Array.isArray(backendNetworks)) return [];

    return backendNetworks.map((network, index) => {
      console.log("Processing network:", network); // Debug log

      const bssids = network.bssids || [];
      const primaryBssid = bssids[0] || {};

      console.log("Primary BSSID object:", primaryBssid); // Debug log

      // Parse signal strength
      let signalValue = -70; // default
      if (primaryBssid.signal) {
        const signalStr = primaryBssid.signal.toString();
        const signalMatch = signalStr.match(/-?\d+/);
        if (signalMatch) {
          signalValue = parseInt(signalMatch[0]);
        }
      }

      // Determine security and risks
      const auth = primaryBssid.authentication || "Unknown";
      const encryption = primaryBssid.encryption || "Unknown";

      let security = "Unknown";
      let risks = [];
      let riskLevel = "medium";

      if (
        auth.toLowerCase().includes("open") ||
        encryption.toLowerCase().includes("none")
      ) {
        security = "Open";
        risks = ["open_network", "no_encryption"];
        riskLevel = "high";
      } else if (auth.toLowerCase().includes("wep")) {
        security = "WEP";
        risks = ["weak_security", "old_encryption"];
        riskLevel = "high";
      } else if (auth.toLowerCase().includes("wpa3")) {
        security = "WPA3";
        risks = [];
        riskLevel = "low";
      } else if (auth.toLowerCase().includes("wpa2")) {
        security = "WPA2";
        risks = [];
        riskLevel = "low";
      } else if (auth.toLowerCase().includes("wpa")) {
        security = "WPA/WPA2";
        risks = [];
        riskLevel = "low";
      }

      // Add public wifi risk if it looks like a public network
      const ssid = network.ssid || `<hidden-${index}>`;
      if (
        ssid.toLowerCase().includes("guest") ||
        ssid.toLowerCase().includes("public") ||
        ssid.toLowerCase().includes("free") ||
        ssid.toLowerCase().includes("wifi")
      ) {
        risks.push("public_wifi");
        if (riskLevel === "low") riskLevel = "medium";
      }

      // Better BSSID extraction - try multiple possible locations
      let bssidValue = "Unknown";

      // Check if BSSID is directly in the primaryBssid object
      if (primaryBssid.bssid) {
        bssidValue = primaryBssid.bssid;
      }
      // Check if BSSID is at network level
      else if (network.bssid) {
        bssidValue = network.bssid;
      }
      // Check if bssids array has string values directly
      else if (bssids.length > 0 && typeof bssids[0] === "string") {
        bssidValue = bssids[0];
      }
      // Try to extract from any property that looks like a MAC address
      else if (primaryBssid) {
        // Look for any property that looks like a MAC address pattern
        for (const [key, value] of Object.entries(primaryBssid)) {
          if (
            typeof value === "string" &&
            /^([0-9A-Fa-f]{2}[:-]){5}([0-9A-Fa-f]{2})$/.test(value)
          ) {
            bssidValue = value;
            break;
          }
        }
      }

      // If still unknown, generate a placeholder based on index
      if (bssidValue === "Unknown") {
        bssidValue = `Unknown-${index}`;
      }

      console.log("Final BSSID value:", bssidValue); // Debug log

      return {
        id: `wifi-${index}-${bssidValue.replace(/:/g, "") || Date.now()}`,
        ssid: ssid,
        bssid: bssidValue,
        signal: signalValue,
        security: security,
        frequency: primaryBssid.channel
          ? `Channel ${primaryBssid.channel}`
          : "Unknown",
        channel: primaryBssid.channel || "Unknown",
        authentication: auth,
        encryption: encryption,
        risks: risks,
        riskLevel: riskLevel,
        allBssids: bssids,
      };
    });
  };

  const scanNetworks = async () => {
    setLoading(true);
    setError(null);

    try {
      if (connectionStatus !== "connected") {
        await socketService.connect();
        setConnectionStatus("connected");
      }

      // Request a single scan
      socketService.requestSingleScan();

      // The results will come via WebSocket events
    } catch (err) {
      setError("Failed to connect to scan service. Please try again.");
      setLoading(false);
    }
  };

  const toggleRealtimeScanning = async () => {
    try {
      if (connectionStatus !== "connected") {
        await socketService.connect();
        setConnectionStatus("connected");
      }

      if (realtimeScanning) {
        socketService.stopRealtimeScan();
        setRealtimeScanning(false);
      } else {
        socketService.startRealtimeScan();
        setRealtimeScanning(true);
      }
    } catch (err) {
      setError("Failed to toggle real-time scanning.");
    }
  };

  const connectToNetwork = async (network) => {
    setConnecting(network.id);

    try {
      // Replace with actual API call to connect to network
      // const response = await fetch('/api/connect-network', {
      //   method: 'POST',
      //   headers: { 'Content-Type': 'application/json' },
      //   body: JSON.stringify({ networkId: network.id, ssid: network.ssid })
      // })

      // Simulate connection delay
      await new Promise((resolve) => setTimeout(resolve, 3000));

      onNetworkConnect(network);
    } catch (err) {
      setError(`Failed to connect to ${network.ssid}`);
    } finally {
      setConnecting(null);
    }
  };

  const getRiskBadge = (risks, riskLevel) => {
    if (riskLevel === "low") {
      return <span className="status-badge status-safe">🟢 Safe</span>;
    } else if (riskLevel === "medium") {
      return <span className="status-badge status-warning">🟡 Caution</span>;
    } else {
      return <span className="status-badge status-danger">🔴 High Risk</span>;
    }
  };

  const getSignalStrength = (signal) => {
    if (signal > -50) return "📶 Excellent";
    if (signal > -60) return "📶 Good";
    if (signal > -70) return "📶 Fair";
    return "📶 Weak";
  };

  useEffect(() => {
    // Initialize WebSocket connection and set up event listeners
    const initializeConnection = async () => {
      try {
        await socketService.connect();
        setConnectionStatus("connected");

        // Set up WebSocket event listeners
        const handleNetworkUpdate = (data) => {
          setLastUpdateTime(new Date(data.timestamp * 1000));
          setLoading(false);

          if (data.data && data.data.networks) {
            const transformedNetworks = transformNetworkData(
              data.data.networks
            );
            setNetworks(transformedNetworks);
            setError(null);
          } else if (data.data && data.data.error) {
            setError(`Scan failed: ${data.data.error}`);
          }
        };

        const handleScanStatus = (data) => {
          console.log("Scan status:", data);
          if (data.status === "started") {
            setRealtimeScanning(true);
          } else if (data.status === "stopped") {
            setRealtimeScanning(false);
          }
        };

        const handleScanError = (data) => {
          setError(`Real-time scan error: ${data.error}`);
          setLoading(false);
        };

        // Register event listeners
        socketService.onNetworkUpdate(handleNetworkUpdate);
        socketService.onScanStatus(handleScanStatus);
        socketService.onScanError(handleScanError);

        // Perform initial scan
        socketService.requestSingleScan();

        // Cleanup function
        return () => {
          socketService.removeNetworkUpdateListener(handleNetworkUpdate);
          socketService.removeScanStatusListener(handleScanStatus);
          socketService.removeScanErrorListener(handleScanError);
        };
      } catch (err) {
        console.error("Failed to initialize WebSocket connection:", err);
        setConnectionStatus("disconnected");
        setError("Failed to connect to scan service. Using offline mode.");
      }
    };

    initializeConnection();

    // Cleanup on unmount
    return () => {
      if (realtimeScanning) {
        socketService.stopRealtimeScan();
      }
      socketService.disconnect();
    };
  }, []);

  return (
    <div className="network-scanner">
      <div className="card">
        <div className="card-header">
          <div
            style={{
              display: "flex",
              justifyContent: "space-between",
              alignItems: "flex-start",
            }}
          >
            <div>
              <h2 className="card-title">Available Networks</h2>
              <p className="card-subtitle">
                Scan and analyze nearby WiFi networks for potential security
                threats
              </p>
            </div>
            <div
              style={{ display: "flex", alignItems: "center", gap: "0.5rem" }}
            >
              <span
                className={`status-badge ${
                  connectionStatus === "connected"
                    ? "status-safe"
                    : "status-danger"
                }`}
              >
                {connectionStatus === "connected"
                  ? "🟢 Connected"
                  : "🔴 Disconnected"}
              </span>
              {lastUpdateTime && (
                <span style={{ fontSize: "0.75rem", color: "#64748b" }}>
                  Last update: {lastUpdateTime.toLocaleTimeString()}
                </span>
              )}
            </div>
          </div>

          <div
            style={{
              marginTop: "1rem",
              display: "flex",
              gap: "0.5rem",
              flexWrap: "wrap",
            }}
          >
            <button
              className="btn btn-primary"
              onClick={scanNetworks}
              disabled={loading}
            >
              {loading ? <div className="loading-spinner" /> : "🔄"}
              {loading ? "Scanning..." : "Single Scan"}
            </button>

            <button
              className={`btn ${
                realtimeScanning ? "btn-danger" : "btn-success"
              }`}
              onClick={toggleRealtimeScanning}
              disabled={connectionStatus !== "connected"}
            >
              {realtimeScanning ? "⏹️ Stop Real-time" : "▶️ Start Real-time"}
            </button>

            {realtimeScanning && (
              <span className="status-badge status-warning">
                🔄 Live Scanning Active
              </span>
            )}
          </div>
        </div>

        <div className="card-content">
          {error && (
            <div
              className="error-message"
              style={{
                background: "#fee2e2",
                color: "#991b1b",
                padding: "1rem",
                borderRadius: "8px",
                marginBottom: "1rem",
              }}
            >
              ⚠️ {error}
            </div>
          )}

          {loading ? (
            <div style={{ textAlign: "center", padding: "2rem" }}>
              <div className="loading-spinner" style={{ margin: "0 auto" }} />
              <p style={{ marginTop: "1rem", color: "#64748b" }}>
                Scanning for available networks...
              </p>
            </div>
          ) : (
            <div className="networks-grid">
              {networks.map((network) => (
                <div key={network.id} className="network-card">
                  <div className="network-header">
                    <div className="network-info">
                      <h3 className="network-name">{network.ssid}</h3>
                      <p className="network-bssid">BSSID: {network.bssid}</p>
                    </div>
                    <div className="network-risk">
                      {getRiskBadge(network.risks, network.riskLevel)}
                    </div>
                  </div>

                  <div className="network-details">
                    <div className="detail-row">
                      <span className="detail-label">Signal:</span>
                      <span className="detail-value">
                        {getSignalStrength(network.signal)} ({network.signal}{" "}
                        dBm)
                      </span>
                    </div>
                    <div className="detail-row">
                      <span className="detail-label">Security:</span>
                      <span className="detail-value">{network.security}</span>
                    </div>
                    <div className="detail-row">
                      <span className="detail-label">Frequency:</span>
                      <span className="detail-value">{network.frequency}</span>
                    </div>

                    {network.risks.length > 0 &&
                      network.riskLevel !== "low" && (
                        <div className="risk-details">
                          <span className="detail-label">Risk Factors:</span>
                          <div className="risk-tags">
                            {network.risks.map((risk, index) => (
                              <span key={index} className="risk-tag">
                                {risk.replace("_", " ")}
                              </span>
                            ))}
                          </div>
                        </div>
                      )}
                  </div>

                  <div className="network-actions">
                    <button
                      className={`btn ${
                        network.riskLevel === "high"
                          ? "btn-danger"
                          : "btn-primary"
                      }`}
                      onClick={() => connectToNetwork(network)}
                      disabled={connecting !== null}
                    >
                      {connecting === network.id ? (
                        <>
                          <div className="loading-spinner" />
                          Connecting...
                        </>
                      ) : (
                        <>🔗 Connect & Monitor</>
                      )}
                    </button>
                  </div>
                </div>
              ))}
            </div>
          )}

          {!loading && networks.length === 0 && (
            <div
              style={{ textAlign: "center", padding: "2rem", color: "#64748b" }}
            >
              <p>No networks found. Click "Refresh Scan" to try again.</p>
            </div>
          )}
        </div>
      </div>
    </div>
  );
};

export default NetworkScanner;
