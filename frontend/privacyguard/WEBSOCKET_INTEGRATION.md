# Real-time Network Scanner Integration

This document explains how the frontend integrates with the Python backend using WebSocket technology for real-time network scanning.

## Backend WebSocket Server

Your Python backend (`realtimescan.py`) provides:

### WebSocket Endpoints (namespace: `/scan`)
- **Connection**: Automatic network scan on client connection
- **Events**: 
  - `network_update` - Real-time scan results
  - `scan_status` - Scanning state changes
  - `scan_error` - Error notifications

### WebSocket Commands
- `start_scan` - Begin continuous scanning
- `stop_scan` - Stop continuous scanning  
- `request_scan` - Request single scan

### HTTP API Endpoints
- `GET /api/scan` - Single network scan
- `POST /api/scan/start` - Start real-time scanning
- `POST /api/scan/stop` - Stop real-time scanning

## Frontend WebSocket Integration

### Components Updated

1. **NetworkScanner.jsx**
   - Real-time network list updates
   - Live scanning controls
   - Connection status indicators
   - Network data transformation from backend format

2. **WebSocketTest.jsx** (Debug Component)
   - Connection testing
   - Message logging
   - Manual scan controls

3. **SocketService.js**
   - WebSocket connection management
   - Event handling
   - Reconnection logic

## Data Flow

```
Backend (Python) → WebSocket → Frontend (React)
┌─────────────────┐    ┌──────────────┐    ┌─────────────────┐
│ netsh/scapy     │───▶│ Socket.IO    │───▶│ NetworkScanner  │
│ Network Scan    │    │ Events       │    │ Component       │
└─────────────────┘    └──────────────┘    └─────────────────┘
```

### Backend Data Format
```json
{
  "method": "netsh",
  "networks": [
    {
      "ssid": "NetworkName",
      "bssids": [
        {
          "bssid": "00:1B:44:11:3A:B7",
          "signal": "100%",
          "channel": "6",
          "authentication": "WPA2-Personal",
          "encryption": "CCMP"
        }
      ]
    }
  ]
}
```

### Frontend Transformed Format
```json
{
  "id": "wifi-0-00:1B:44:11:3A:B7",
  "ssid": "NetworkName",
  "bssid": "00:1B:44:11:3A:B7",
  "signal": -45,
  "security": "WPA2",
  "frequency": "Channel 6",
  "risks": [],
  "riskLevel": "low"
}
```

## Features

### Real-time Scanning
- **Auto-connect**: WebSocket connects on component mount
- **Live Updates**: Networks refresh every 3 seconds during real-time mode
- **Status Indicators**: Connection and scanning status visible
- **Error Handling**: Connection failures and scan errors displayed

### Risk Assessment
The frontend analyzes backend data to determine security risks:

- **Open Networks**: No authentication/encryption
- **Weak Security**: WEP encryption
- **Public WiFi**: Networks with guest/public names
- **Old Encryption**: Deprecated security methods

### Connection Status
- 🟢 **Connected**: WebSocket active, receiving updates
- 🔴 **Disconnected**: No backend connection
- 🟡 **Connecting**: Establishing connection

## Usage

### 1. Start Backend Server
```bash
python realtimescan.py
```
Server runs on `http://localhost:5000`

### 2. Start Frontend
```bash
cd frontend/privacyguard
npm run dev
```
Frontend runs on `http://localhost:5173`

### 3. Using the Interface

#### Single Scan
- Click "Single Scan" for one-time network discovery
- Results display immediately when scan completes

#### Real-time Scanning
- Click "Start Real-time" to begin continuous scanning
- Networks update automatically every 3 seconds  
- Click "Stop Real-time" to end continuous mode

#### Debug Mode
- Click "Show WebSocket Debug" to view raw messages
- Monitor connection status and data flow
- Useful for troubleshooting backend communication

## Configuration

### Environment Variables
```env
# Backend server URL
REACT_APP_API_URL=http://localhost:5000

# Feature toggles
REACT_APP_ENABLE_REAL_TIME_UPDATES=true
REACT_APP_DEBUG_MODE=true
```

### WebSocket Settings
```javascript
// Connection settings in SocketService
{
  transports: ['websocket', 'polling'],
  timeout: 10000,
  reconnection: true,
  reconnectionAttempts: 5,
  reconnectionDelay: 1000
}
```

## Error Handling

### Connection Errors
- **Backend Offline**: Shows "Disconnected" status
- **Network Issues**: Automatic reconnection attempts
- **Timeout**: 10-second connection timeout

### Scan Errors
- **Windows netsh Fails**: Error message displayed
- **Permission Issues**: Admin rights may be required
- **No Networks Found**: Empty state shown

## Security Considerations

### WebSocket Security
- CORS enabled for local development
- Consider authentication for production
- Use HTTPS/WSS in production environments

### Network Scanning
- Requires Windows platform for netsh
- May need administrator privileges
- Respects system network permissions

## Troubleshooting

### Common Issues

1. **WebSocket Connection Failed**
   - Verify backend is running on port 5000
   - Check firewall settings
   - Ensure CORS is configured

2. **No Networks Found**
   - Run backend as administrator
   - Check Wi-Fi adapter is enabled
   - Ensure netsh command works in CMD

3. **Real-time Updates Not Working**
   - Check WebSocket connection status
   - Verify backend thread is running
   - Look for errors in browser console

### Debug Tools
- Browser Developer Tools → Network tab
- WebSocket Debug component in frontend
- Backend console logs
- Windows Event Viewer for system issues

## Production Deployment

### Backend
- Use production WSGI server (gunicorn, uWSGI)
- Configure proper CORS origins
- Set up HTTPS/SSL certificates
- Consider rate limiting

### Frontend
- Build for production: `npm run build`
- Use HTTPS for WebSocket connections
- Configure environment variables
- Set up proper error tracking

## API Reference

### WebSocket Events

#### Incoming (Backend → Frontend)
```javascript
// Network scan results
socket.on('network_update', (data) => {
  // data.timestamp: Unix timestamp
  // data.data: Scan results object
})

// Scanning status changes
socket.on('scan_status', (data) => {
  // data.status: 'started' | 'stopped' | 'already_running'
  // data.message: Status description
})

// Error notifications
socket.on('scan_error', (data) => {
  // data.timestamp: Unix timestamp
  // data.error: Error message
})
```

#### Outgoing (Frontend → Backend)
```javascript
// Request single scan
socket.emit('request_scan')

// Start continuous scanning
socket.emit('start_scan')

// Stop continuous scanning
socket.emit('stop_scan')
```

This integration provides a seamless real-time network scanning experience with proper error handling, connection management, and user feedback.