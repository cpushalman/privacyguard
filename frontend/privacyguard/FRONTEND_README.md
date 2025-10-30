# PrivacyGuard Frontend

A modern, white-themed React frontend for the PrivacyGuard network threat detection tool.

## Features

### 🛡️ Network Security Monitoring

- **WiFi Network Scanning**: Lists all available networks with detailed information
- **Risk Assessment**: Automated security risk evaluation with color-coded indicators
- **Real-time Monitoring**: Live ARP table monitoring for threat detection
- **Connection Management**: Secure network connection with monitoring capabilities

### 🎨 Modern UI/UX

- **Clean White Theme**: Modern, professional interface design
- **Responsive Design**: Works seamlessly on desktop and mobile devices
- **Real-time Updates**: Live data updates without page refreshes
- **Interactive Cards**: Intuitive network and device information display

### 🔍 Security Features

- **ARP Spoofing Detection**: Monitors for suspicious MAC address changes
- **Network Risk Analysis**: Identifies open networks, weak security, and potential threats
- **Threat Alerts**: Real-time security threat notifications
- **Connection Statistics**: Detailed monitoring of network activity

## Project Structure

```
src/
├── components/
│   ├── Header.jsx              # Main header component
│   ├── NetworkScanner.jsx      # WiFi network scanning interface
│   └── ConnectionMonitor.jsx   # ARP table and threat monitoring
├── services/
│   └── api.js                  # Backend API communication
├── utils/
│   └── index.js                # Utility functions and helpers
├── App.jsx                     # Main application component
├── App.css                     # Application styles
├── index.css                   # Global styles
└── main.jsx                    # Application entry point
```

## Components Overview

### NetworkScanner

- Displays available WiFi networks
- Shows signal strength, security type, and risk levels
- Provides network connection functionality
- Color-coded risk indicators (Green: Safe, Yellow: Caution, Red: High Risk)

### ConnectionMonitor

- Real-time ARP table monitoring
- Connection statistics and duration tracking
- Threat detection and alerts
- Device identification and vendor lookup

### Header

- Application branding and navigation
- System status indicators
- Modern logo and title display

## API Integration

The frontend communicates with the backend through REST endpoints:

- `GET /api/scan-networks` - Retrieve available networks
- `POST /api/connect-network` - Connect to a selected network
- `POST /api/disconnect-network` - Disconnect from current network
- `GET /api/arp-table` - Get current ARP table entries
- `GET /api/threats` - Retrieve detected threats
- `POST /api/start-monitoring` - Start network monitoring
- `POST /api/stop-monitoring` - Stop network monitoring

## Getting Started

### Prerequisites

- Node.js 16+ and npm
- PrivacyGuard backend server running

### Installation

1. **Navigate to the frontend directory:**

   ```bash
   cd frontend/privacyguard
   ```

2. **Install dependencies:**

   ```bash
   npm install
   ```

3. **Configure environment:**

   ```bash
   # Copy and edit environment file
   cp .env.example .env
   # Edit REACT_APP_API_URL to match your backend server
   ```

4. **Start development server:**

   ```bash
   npm run dev
   ```

5. **Open in browser:**
   Navigate to `http://localhost:5173`

### Production Build

```bash
npm run build
npm run preview
```

## Configuration

### Environment Variables

Create a `.env` file in the project root:

```env
# API Configuration
REACT_APP_API_URL=http://localhost:8000

# Feature Flags
REACT_APP_ENABLE_MOCK_DATA=true
REACT_APP_ENABLE_REAL_TIME_UPDATES=true
REACT_APP_DEBUG_MODE=false

# Network Configuration
REACT_APP_SCAN_INTERVAL=5000
REACT_APP_ARP_UPDATE_INTERVAL=3000
```

## Usage Guide

### 1. Network Scanning

- Click "Refresh Scan" to discover available networks
- Review risk indicators and security information
- Networks are color-coded based on security assessment

### 2. Connecting to Networks

- Click "Connect & Monitor" on your chosen network
- High-risk networks show warning dialogs
- Connection process includes automatic monitoring setup

### 3. Monitoring Active Connections

- View real-time ARP table updates
- Monitor for suspicious device activity
- Receive instant security threat alerts
- Track connection statistics and duration

### 4. Security Alerts

- Automatic threat detection notifications
- Detailed threat information and affected devices
- Severity-based color coding and prioritization

## Customization

### Theming

The application uses a modern white theme with customizable CSS variables:

```css
:root {
  --primary-color: #3b82f6;
  --background-color: #f8fafc;
  --card-background: #ffffff;
  --text-primary: #1e293b;
  --text-secondary: #64748b;
}
```

### Risk Assessment

Customize risk evaluation in `utils/index.js`:

```javascript
export const getRiskLevel = (risks) => {
  const highRiskFactors = ["open_network", "weak_security"];
  const mediumRiskFactors = ["unknown_network", "public_wifi"];
  // Add your custom risk factors
};
```

## Development

### Available Scripts

- `npm run dev` - Start development server
- `npm run build` - Build for production
- `npm run preview` - Preview production build
- `npm run lint` - Run ESLint

### Code Style

- Uses ESLint for code quality
- Follows React best practices
- Component-based architecture
- Functional components with hooks

## Security Considerations

- All API communications should use HTTPS in production
- Sensitive network information is handled securely
- No credentials stored in frontend code
- Real-time updates use secure WebSocket connections

## Browser Compatibility

- Modern browsers (Chrome 90+, Firefox 88+, Safari 14+)
- Responsive design for mobile devices
- Progressive Web App features available

## Contributing

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

## License

This project is part of the PrivacyGuard network security suite.

## Support

For issues and questions:

- Check the GitHub issues page
- Review the backend API documentation
- Ensure proper network permissions for scanning

---

**Note**: This frontend requires the PrivacyGuard backend server to be running for full functionality. Mock data is available for development and testing purposes.
