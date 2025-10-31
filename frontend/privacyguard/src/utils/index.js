// Utility functions for the PrivacyGuard frontend

export const formatSignalStrength = (signal) => {
  if (signal > -50) return { text: "📶 Excellent", class: "signal-excellent" };
  if (signal > -60) return { text: "📶 Good", class: "signal-good" };
  if (signal > -70) return { text: "📶 Fair", class: "signal-fair" };
  return { text: "📶 Weak", class: "signal-weak" };
};

export const getRiskLevel = (risks) => {
  const highRiskFactors = [
    "open_network",
    "weak_security",
    "old_encryption",
    "arp_spoofing",
  ];
  const mediumRiskFactors = ["unknown_network", "public_wifi"];

  const hasHighRisk = risks.some((risk) => highRiskFactors.includes(risk));
  const hasMediumRisk = risks.some((risk) => mediumRiskFactors.includes(risk));

  if (hasHighRisk) return "high";
  if (hasMediumRisk) return "medium";
  return "low";
};

export const formatRiskBadge = (riskLevel) => {
  switch (riskLevel) {
    case "low":
      return { text: "🟢 Safe", class: "status-safe" };
    case "medium":
      return { text: "🟡 Caution", class: "status-warning" };
    case "high":
      return { text: "🔴 High Risk", class: "status-danger" };
    default:
      return { text: "⚪ Unknown", class: "status-secondary" };
  }
};

export const formatTime = (seconds) => {
  const hours = Math.floor(seconds / 3600);
  const minutes = Math.floor((seconds % 3600) / 60);
  const secs = seconds % 60;
  return `${hours.toString().padStart(2, "0")}:${minutes
    .toString()
    .padStart(2, "0")}:${secs.toString().padStart(2, "0")}`;
};

export const formatBytes = (bytes) => {
  if (bytes === 0) return "0 Bytes";
  const k = 1024;
  const sizes = ["Bytes", "KB", "MB", "GB", "TB"];
  const i = Math.floor(Math.log(bytes) / Math.log(k));
  return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + " " + sizes[i];
};

export const getVendorFromMac = (mac) => {
  // Simple MAC vendor lookup - in production, use a proper OUI database
  const vendors = {
    "00:1B:44": "Cisco Systems",
    "00:50:56": "VMware",
    "08:00:27": "VirtualBox",
    "00:0C:29": "VMware",
    "00:16:3E": "Xensource",
    "AA:BB:CC": "Unknown",
    "11:22:33": "Apple Inc",
    "FF:FF:FF": "Broadcast",
  };

  const prefix = mac.substring(0, 8).toUpperCase();
  return vendors[prefix] || "Unknown";
};

export const formatMacAddress = (mac) => {
  return mac
    .toUpperCase()
    .replace(/(.{2})/g, "$1:")
    .slice(0, -1);
};

export const isPrivateIP = (ip) => {
  const parts = ip.split(".").map(Number);
  return (
    parts[0] === 10 ||
    (parts[0] === 172 && parts[1] >= 16 && parts[1] <= 31) ||
    (parts[0] === 192 && parts[1] === 168)
  );
};

export const getSeverityColor = (severity) => {
  switch (severity.toLowerCase()) {
    case "critical":
      return "#dc2626";
    case "high":
      return "#ea580c";
    case "medium":
      return "#d97706";
    case "low":
      return "#65a30d";
    default:
      return "#6b7280";
  }
};

export const generateMockNetworks = () => {
  return [
    {
      id: "wifi-001",
      ssid: "HomeNetwork_5G",
      bssid: "00:1B:44:11:3A:B7",
      signal: -45,
      security: "WPA3",
      frequency: "5.2 GHz",
      channel: 36,
      risks: [],
      riskLevel: "low",
    },
    {
      id: "wifi-002",
      ssid: "CoffeeShop_Guest",
      bssid: "00:1B:44:11:3A:C8",
      signal: -67,
      security: "Open",
      frequency: "2.4 GHz",
      channel: 6,
      risks: ["open_network", "public_wifi"],
      riskLevel: "high",
    },
    {
      id: "wifi-003",
      ssid: "Office_Network",
      bssid: "00:1B:44:11:3A:D9",
      signal: -52,
      security: "WPA2",
      frequency: "5.2 GHz",
      channel: 44,
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
      channel: 11,
      risks: ["weak_security", "old_encryption"],
      riskLevel: "high",
    },
    {
      id: "wifi-005",
      ssid: "xfinitywifi",
      bssid: "00:1B:44:11:3A:FB",
      signal: -61,
      security: "Open",
      frequency: "2.4 GHz",
      channel: 1,
      risks: ["open_network", "public_wifi", "captive_portal"],
      riskLevel: "high",
    },
  ];
};

export const generateMockArpEntries = () => {
  return [
    {
      id: "arp-001",
      ip: "192.168.1.1",
      mac: "00:1B:44:11:3A:B7",
      vendor: "Cisco Systems",
      hostname: "router.local",
      status: "router",
      lastSeen: new Date(),
      suspicious: false,
      isGateway: true,
    },
    {
      id: "arp-002",
      ip: "192.168.1.100",
      mac: "AA:BB:CC:DD:EE:FF",
      vendor: "Unknown",
      hostname: null,
      status: "active",
      lastSeen: new Date(),
      suspicious: true,
      threats: ["MAC address spoofing", "Unknown vendor", "Rapid IP changes"],
    },
    {
      id: "arp-003",
      ip: "192.168.1.45",
      mac: "11:22:33:44:55:66",
      vendor: "Apple Inc",
      hostname: "Johns-iPhone.local",
      status: "active",
      lastSeen: new Date(),
      suspicious: false,
    },
    {
      id: "arp-004",
      ip: "192.168.1.23",
      mac: "00:50:56:AA:BB:CC",
      vendor: "VMware",
      hostname: "vm-workstation",
      status: "active",
      lastSeen: new Date(Date.now() - 30000),
      suspicious: false,
    },
  ];
};
