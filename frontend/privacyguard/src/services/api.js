// API service for communicating with the backend
const API_BASE_URL = import.meta.env?.VITE_API_URL || "http://localhost:5000";

class ApiService {
  async request(endpoint, options = {}) {
    const url = `${API_BASE_URL}${endpoint}`;
    const config = {
      headers: {
        "Content-Type": "application/json",
        ...options.headers,
      },
      ...options,
    };

    try {
      const response = await fetch(url, config);
      if (!response.ok) {
        throw new Error(`HTTP error! status: ${response.status}`);
      }
      return await response.json();
    } catch (error) {
      console.error("API request failed:", error);
      throw error;
    }
  }

  // Network scanning endpoints
  async scanNetworks() {
    return this.request("/api/scan");
  }

  async startRealtimeScan() {
    return this.request("/api/scan/start", {
      method: "POST",
    });
  }

  async stopRealtimeScan() {
    return this.request("/api/scan/stop", {
      method: "POST",
    });
  }

  async connectToNetwork(networkData) {
    return this.request("/api/connect-network", {
      method: "POST",
      body: JSON.stringify(networkData),
    });
  }

  async disconnectNetwork() {
    return this.request("/api/disconnect-network", {
      method: "POST",
    });
  }

  // Monitoring endpoints
  async startMonitoring(networkId) {
    return this.request("/api/start-monitoring", {
      method: "POST",
      body: JSON.stringify({ networkId }),
    });
  }

  async stopMonitoring() {
    return this.request("/api/stop-monitoring", {
      method: "POST",
    });
  }

  async getArpTable() {
    return this.request("/api/arp-table");
  }

  async getThreats() {
    return this.request("/api/threats");
  }

  async getConnectionStats() {
    return this.request("/api/connection-stats");
  }

  // Real-time updates using Server-Sent Events
  subscribeToUpdates(onUpdate) {
    const eventSource = new EventSource(`${API_BASE_URL}/api/updates`);

    eventSource.onmessage = (event) => {
      try {
        const data = JSON.parse(event.data);
        onUpdate(data);
      } catch (error) {
        console.error("Failed to parse SSE data:", error);
      }
    };

    eventSource.onerror = (error) => {
      console.error("SSE connection error:", error);
    };

    return () => eventSource.close();
  }
}

export default new ApiService();
