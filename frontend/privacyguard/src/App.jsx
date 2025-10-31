import { useState, useEffect } from "react";
import "./App.css";
import NetworkScanner from "./components/NetworkScanner";
import ConnectionMonitor from "./components/ConnectionMonitor";
import Header from "./components/Header";

function App() {
  const [currentView, setCurrentView] = useState("scanner"); // 'scanner' or 'monitor'
  const [connectedNetwork, setConnectedNetwork] = useState(null);

  return (
    <div className="app">
      <Header />
      <main className="main-content">
        {currentView === "scanner" ? (
          <NetworkScanner
            onNetworkConnect={(network) => {
              setConnectedNetwork(network);
              setCurrentView("monitor");
            }}
          />
        ) : (
          <ConnectionMonitor
            network={connectedNetwork}
            onBackToScanner={() => setCurrentView("scanner")}
          />
        )}
      </main>
    </div>
  );
}

export default App;
