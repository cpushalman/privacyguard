import React, { useState, useEffect } from "react";
import socketService from "../services/socket";

const WebSocketTest = () => {
  const [connectionStatus, setConnectionStatus] = useState("disconnected");
  const [messages, setMessages] = useState([]);
  const [isScanning, setIsScanning] = useState(false);

  useEffect(() => {
    const initConnection = async () => {
      try {
        await socketService.connect();
        setConnectionStatus("connected");

        // Set up event listeners
        socketService.onNetworkUpdate((data) => {
          console.log("Raw network data received:", data); // Debug log
          setMessages((prev) =>
            [
              ...prev,
              {
                type: "network_update",
                timestamp: new Date(),
                data: data,
              },
            ].slice(-10)
          ); // Keep only last 10 messages
        });

        socketService.onScanStatus((data) => {
          setMessages((prev) =>
            [
              ...prev,
              {
                type: "scan_status",
                timestamp: new Date(),
                data: data,
              },
            ].slice(-10)
          );

          setIsScanning(data.status === "started");
        });

        socketService.onScanError((data) => {
          setMessages((prev) =>
            [
              ...prev,
              {
                type: "scan_error",
                timestamp: new Date(),
                data: data,
              },
            ].slice(-10)
          );
        });
      } catch (error) {
        setConnectionStatus("error");
        console.error("Connection failed:", error);
      }
    };

    initConnection();

    return () => {
      socketService.disconnect();
    };
  }, []);

  const handleSingleScan = () => {
    socketService.requestSingleScan();
  };

  const handleToggleRealtime = () => {
    if (isScanning) {
      socketService.stopRealtimeScan();
    } else {
      socketService.startRealtimeScan();
    }
  };

  return (
    <div
      className="websocket-test"
      style={{ padding: "1rem", margin: "1rem 0" }}
    >
      <div className="card">
        <div className="card-header">
          <h3 className="card-title">WebSocket Connection Test</h3>
          <p className="card-subtitle">
            Test WebSocket connection to the Python backend
          </p>
        </div>

        <div className="card-content">
          <div style={{ marginBottom: "1rem" }}>
            <span
              className={`status-badge ${
                connectionStatus === "connected"
                  ? "status-safe"
                  : connectionStatus === "error"
                  ? "status-danger"
                  : "status-warning"
              }`}
            >
              {connectionStatus === "connected"
                ? "🟢 Connected"
                : connectionStatus === "error"
                ? "🔴 Error"
                : "🟡 Connecting..."}
            </span>

            {isScanning && (
              <span
                className="status-badge status-warning"
                style={{ marginLeft: "0.5rem" }}
              >
                🔄 Real-time Scanning Active
              </span>
            )}
          </div>

          <div style={{ marginBottom: "1rem", display: "flex", gap: "0.5rem" }}>
            <button
              className="btn btn-primary"
              onClick={handleSingleScan}
              disabled={connectionStatus !== "connected"}
            >
              Single Scan
            </button>

            <button
              className={`btn ${isScanning ? "btn-danger" : "btn-success"}`}
              onClick={handleToggleRealtime}
              disabled={connectionStatus !== "connected"}
            >
              {isScanning ? "Stop Real-time" : "Start Real-time"}
            </button>
          </div>

          <div>
            <h4
              style={{
                margin: "1rem 0 0.5rem 0",
                fontSize: "1rem",
                color: "#374151",
              }}
            >
              Recent Messages:
            </h4>
            <div
              style={{
                maxHeight: "300px",
                overflowY: "auto",
                border: "1px solid #e2e8f0",
                borderRadius: "8px",
                padding: "0.5rem",
              }}
            >
              {messages.length === 0 ? (
                <p style={{ color: "#64748b", fontStyle: "italic" }}>
                  No messages received yet...
                </p>
              ) : (
                messages.map((msg, index) => (
                  <div
                    key={index}
                    style={{
                      padding: "0.5rem",
                      marginBottom: "0.5rem",
                      backgroundColor:
                        msg.type === "scan_error" ? "#fef2f2" : "#f8fafc",
                      borderRadius: "4px",
                      borderLeft: `3px solid ${
                        msg.type === "network_update"
                          ? "#10b981"
                          : msg.type === "scan_status"
                          ? "#3b82f6"
                          : "#ef4444"
                      }`,
                    }}
                  >
                    <div style={{ fontSize: "0.75rem", color: "#64748b" }}>
                      {msg.timestamp.toLocaleTimeString()} - {msg.type}
                    </div>
                    <pre
                      style={{
                        fontSize: "0.75rem",
                        margin: "0.25rem 0 0 0",
                        whiteSpace: "pre-wrap",
                        wordBreak: "break-word",
                      }}
                    >
                      {JSON.stringify(msg.data, null, 2)}
                    </pre>
                  </div>
                ))
              )}
            </div>
          </div>
        </div>
      </div>
    </div>
  );
};

export default WebSocketTest;
