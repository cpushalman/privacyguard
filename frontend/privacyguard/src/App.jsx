import { useState, useEffect } from "react";
import "./App.css";
import NetworkScanner from "./components/NetworkScanner";
import ConnectionMonitor from "./components/ConnectionMonitor";
import Header from "./components/Header";
import Dashboard from "./components/Dashboard";
import RiskAssessment from "./components/RiskAssessment";
import Analytics from "./components/Analytics";

function App() {
  const [currentView, setCurrentView] = useState("dashboard"); // 'dashboard', 'scanner', 'risk', 'monitor', 'analytics'
  const [connectedNetwork, setConnectedNetwork] = useState(null);

  return (
    <div className="app">
      <Header />
      <main className="main-content">
        {/* Tab Navigation */}
        <div
          style={{
            display: "flex",
            gap: "1rem",
            marginBottom: "1rem",
            borderBottom: "2px solid #e2e8f0",
            flexWrap: "wrap",
          }}
        >
          <TabButton
            active={currentView === "dashboard"}
            onClick={() => setCurrentView("dashboard")}
            label="📊 Dashboard"
          />
          <TabButton
            active={currentView === "scanner"}
            onClick={() => setCurrentView("scanner")}
            label="🔍 Network Scanner"
          />
          <TabButton
            active={currentView === "risk"}
            onClick={() => setCurrentView("risk")}
            label="📡 Risk Assessment"
          />
          <TabButton
            active={currentView === "monitor"}
            onClick={() => setCurrentView("monitor")}
            label="🔐 Connection Monitor"
          />
          <TabButton
            active={currentView === "analytics"}
            onClick={() => setCurrentView("analytics")}
            label="📈 Analytics & Reports"
          />
        </div>

        {/* Content */}
        {currentView === "dashboard" && <Dashboard />}
        {currentView === "scanner" && (
          <NetworkScanner
            onNetworkConnect={(network) => {
              setConnectedNetwork(network);
              setCurrentView("monitor");
            }}
          />
        )}
        {currentView === "risk" && <RiskAssessment />}
        {currentView === "monitor" && connectedNetwork && (
          <ConnectionMonitor
            network={connectedNetwork}
            onBackToScanner={() => setCurrentView("scanner")}
          />
        )}
        {currentView === "analytics" && <Analytics />}
      </main>
    </div>
  );
}

const TabButton = ({ active, onClick, label }) => (
  <button
    onClick={onClick}
    style={{
      padding: "0.75rem 1.5rem",
      background: active ? "#667eea" : "transparent",
      color: active ? "white" : "#666",
      border: "none",
      borderBottom: active ? "3px solid #667eea" : "none",
      cursor: "pointer",
      fontWeight: active ? 600 : 500,
      fontSize: "1rem",
      transition: "all 0.2s ease",
    }}
  >
    {label}
  </button>
);

export default App;
