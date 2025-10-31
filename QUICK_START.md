# Privacy Guard - Quick Reference Guide

## 🚀 Running the Application

### Terminal 1: Start Backend API Server (Port 5000)

```powershell
cd 'c:\Users\Ahamed shalman\cicada\privacyguard'
python app.py
```

Expected output:

```
============================================================
Privacy Guard Backend API Server
============================================================
✓ Database initialized
- REST API: http://localhost:5000
- WebSocket: ws://localhost:5000/socket.io/
```

### Terminal 2: Start React Frontend (Port 5173)

```powershell
cd 'c:\Users\Ahamed shalman\cicada\privacyguard\frontend\privacyguard'
npm run dev
```

Expected output:

```
VITE v7.1.12  ready in 1415 ms
➜ Local:   http://localhost:5173/
```

## 🌐 Access the Application

Open browser: **http://localhost:5173**

## 📊 Available Tabs

| Tab                        | Description                                             |
| -------------------------- | ------------------------------------------------------- |
| 📊 **Dashboard**           | Statistics, network scanner controls, protection toggle |
| 🔍 **Network Scanner**     | Real-time WiFi network discovery                        |
| 📡 **Risk Assessment**     | Detailed security analysis with threat detection        |
| 🔐 **Connection Monitor**  | Connected device monitoring via ARP table               |
| 📈 **Analytics & Reports** | Threat history and network scan history                 |

## 🔑 Key Features

### 1. **Risk Assessment** (Most Important)

- Click "🔬 Analyze Current Network"
- Displays:
  - ✅ BSSID (MAC Address)
  - ✅ Encryption Type (WPA3, WPA2, WPA, Open)
  - ✅ Signal Strength (dBm)
  - ✅ Channel Number
  - ✅ DNS Latency
  - ✅ Packet Loss %
  - ✅ TLS Certificate Validity
  - ✅ ARP Spoofing Detection

### 2. **Security Metrics**

- Automatic risk score calculation (0-100)
- Risk levels: SAFE, LOW, MEDIUM, CRITICAL
- Real-time threat detection
- Security recommendations

### 3. **Real-Time Scanning**

- Auto-discovers available WiFi networks
- Shows signal strength for each network
- Displays encryption type
- Indicates risk level

## 🛠️ Backend API Endpoints

| Endpoint                 | Method | Purpose                                  |
| ------------------------ | ------ | ---------------------------------------- |
| `/api/scan`              | GET    | Get current network + available networks |
| `/api/networks`          | GET    | Get all networks with enhanced details   |
| `/api/threats`           | GET    | Get recent threats                       |
| `/api/stats`             | GET    | Get dashboard statistics                 |
| `/api/scan/start`        | POST   | Start real-time scanning                 |
| `/api/scan/stop`         | POST   | Stop real-time scanning                  |
| `/api/protection/enable` | POST   | Enable VPN protection                    |
| `/api/arp-table`         | GET    | Get connected devices                    |
| `/health`                | GET    | API health check                         |

## 🐛 Debugging

### View Console Logs

1. Open browser DevTools (F12)
2. Go to Console tab
3. Click "Analyze Current Network"
4. Watch logs for:
   - `Full scan result:`
   - `Current network:`
   - `Network BSSID:`
   - `Network Signal Strength:`
   - `Network Encryption:`

### View Raw JSON Data

- Scroll to bottom of Risk Assessment page
- See "📊 Raw Data (Debug)" panel
- Shows complete current_network JSON object

### Check Backend Logs

- Watch the Python terminal where `app.py` is running
- Look for:
  - `GET /api/scan HTTP/1.1" 200` ✅
  - `Starting network scan on interface:` ✅
  - Errors or exceptions ❌

## 📋 Expected Data Structure

```json
{
  "current_network": {
    "ssid": "realme P1 5G",
    "bssid": "fa:f1:08:30:3c:8b",
    "encryption_type": "WPA3",
    "signal_strength": -50.5,
    "channel": 11,
    "interface": "Wi-Fi",
    "captive_portal": false,
    "dns_latency_ms": 25.71,
    "packet_loss_percent": 0.0,
    "tls_cert_validity": 1,
    "arp_issues": [],
    "traffic_analysis": {
      "http_ratio": 10.53,
      "https_ratio": 63.16,
      "unencrypted_count": 2,
      "packet_count": 19
    }
  },
  "available_networks": [ ... ],
  "method": "combined"
}
```

## ⚠️ Common Issues

### "BSSID shows Unknown"

**Cause**: Backend not returning BSSID data
**Fix**:

1. Check browser console for error messages
2. Verify backend is running on port 5000
3. Check backend logs for `netsh` command errors

### "Signal Strength shows N/A"

**Cause**: WiFi adapter not connected or netsh not working
**Fix**:

1. Ensure WiFi adapter is connected
2. Run: `netsh wlan show interfaces` in PowerShell
3. Verify signal strength appears in output

### "Encryption shows Unknown"

**Cause**: Authentication line not parsed correctly
**Fix**:

1. Run: `netsh wlan show interfaces` in PowerShell
2. Look for "Authentication :" line
3. Check if value is WPA2, WPA3, WPA, or Open

### Backend returns error 500

**Cause**: Python exception in scanner.py
**Fix**:

1. Check backend terminal for full error traceback
2. Verify Python 3.13 is installed
3. Verify scanner module is in correct location
4. Run: `python scanner/scanner.py` directly to test

## 🔄 Auto-Reload

Both frontend and backend support auto-reload:

- **Frontend**: Saves JSX file → auto-reloads immediately
- **Backend**: Saves `.py` file → auto-restarts server

No manual restart needed!

## 📞 Quick Commands

```powershell
# Test scanner directly
python scanner/scanner.py

# Test specific network data
python -c "from scanner.scanner import scan_current_network; import json; print(json.dumps(scan_current_network(), indent=2, default=str))"

# Check if backend is responding
curl http://localhost:5000/health

# Build production bundle
cd frontend/privacyguard
npm run build

# Run tests
npm run lint
```

## 🎯 Success Indicators

✅ **Backend Running Successfully**

- See "Debugger is active!" message
- No crashes or restart loops
- Logs show client connections

✅ **Frontend Running Successfully**

- No JavaScript errors in console
- Dashboard loads and shows buttons
- Can switch between tabs

✅ **Data Fetching Works**

- Risk Assessment shows actual BSSID
- Signal strength displays value (not N/A)
- Encryption type shows WPA3/WPA2/etc.

✅ **Full Integration Success**

- All network details populate correctly
- Risk score calculates (0-100)
- Recommendations appear based on security level
