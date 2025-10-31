import subprocess
import re
import json
import platform
import threading
import time
from flask import Flask, jsonify, request
from flask_socketio import SocketIO, emit

app = Flask(__name__)
app.config['SECRET_KEY'] = 'your-secret-key-here'
socketio = SocketIO(app, cors_allowed_origins="*", async_mode='threading')

# Global state for real-time scanning
scanning_active = False
scan_thread = None
scan_lock = threading.Lock()

def parse_netsh_output(text):
    """
    Parse output from `netsh wlan show networks mode=bssid`.
    Returns list of dicts: {ssid, bssids: [{bssid, signal, channel, auth, encryption}], ...}
    """
    networks = []
    # Split by "SSID X :" blocks
    ssid_blocks = re.split(r'\nSSID \d+ :', text)[1:]
    for block in ssid_blocks:
        lines = [ln.strip() for ln in block.splitlines() if ln.strip()]
        ssid = lines[0] if lines else "<hidden>"
        # find BSSID blocks
        bssids = []
        current = {}
        for ln in lines[1:]:
            # BSSID line
            m = re.match(r'BSSID \d+ : (.*)', ln)
            if m:
                if current:
                    bssids.append(current)
                current = {"bssid": m.group(1)}
                continue
            m = re.match(r'Signal\s*:\s*(.*)', ln)
            if m and current is not None:
                current["signal"] = m.group(1)
                continue
            m = re.match(r'Channel\s*:\s*(.*)', ln)
            if m and current is not None:
                current["channel"] = m.group(1)
                continue
            # Authentication / Encryption lines are usually per SSID
            m = re.match(r'Authentication\s*:\s*(.*)', ln)
            if m:
                auth = m.group(1)
                # store at SSID-level if there are no BSSIDs yet
                # We'll copy to each BSSID later if needed
                ssid_auth = auth
                continue
            m = re.match(r'Encryption\s*:\s*(.*)', ln)
            if m:
                enc = m.group(1)
                ssid_enc = enc
                continue
        if current:
            bssids.append(current)
        # attach auth/encryption to each bssid if available
        for b in bssids:
            if 'signal' not in b:
                b['signal'] = None
            if 'channel' not in b:
                b['channel'] = None
            # attach ssid-level auth/enc if present
            if 'ssid_auth' in locals():
                b['authentication'] = ssid_auth
            else:
                b['authentication'] = None
            if 'ssid_enc' in locals():
                b['encryption'] = ssid_enc
            else:
                b['encryption'] = None

        networks.append({
            "ssid": ssid,
            "bssids": bssids
        })
    return networks

def scan_with_netsh():
    """
    Uses Windows `netsh wlan show networks mode=bssid` to fetch networks.
    Returns JSON-serializable list.
    """
    try:
        # Ensure platform is Windows
        if platform.system().lower() != 'windows':
            return {"error": "netsh-based scanning works only on Windows."}
        completed = subprocess.run(
            ["netsh", "wlan", "show", "networks", "mode=bssid"],
            capture_output=True, text=True, check=True
        )
        text = completed.stdout
        networks = parse_netsh_output(text)
        return {"method": "netsh", "networks": networks}
    except subprocess.CalledProcessError as e:
        return {"error": "netsh command failed", "details": str(e), "stdout": e.stdout, "stderr": e.stderr}
    except Exception as e:
        return {"error": "unexpected error", "details": str(e)}

# Optional scapy monitor-mode capture (only when NPCAP + monitor mode + admin)
def scan_with_scapy(timeout=6, iface=None):
    """
    Passive sniff of 802.11 beacon/probe frames to collect SSID/BSSID/encryption info.
    Requires scapy and a monitor-capable adapter on Windows (Npcap installed with raw 802.11 support).
    Returns dict with collected networks.
    """
    try:
        from scapy.all import sniff, Dot11, Dot11Beacon, Dot11Elt, Dot11EltRSN
    except Exception as e:
        return {"error": "scapy not available", "details": str(e)}

    seen = {}

    def handle_pkt(pkt):
        if pkt.haslayer(Dot11Beacon) or pkt.haslayer(Dot11):
            try:
                bssid = pkt.addr2
                ssid = None
                capability = {}
                # gather SSID
                if pkt.haslayer(Dot11Elt):
                    elems = pkt.getlayer(Dot11Elt)
                    # iterate Dot11Elt layers
                    cur = elems
                    while cur:
                        if cur.ID == 0 and hasattr(cur, 'info'):
                            ssid = cur.info.decode(errors='ignore')
                        cur = cur.payload.getlayer(Dot11Elt)
                # Attempt to detect encryption/auth from RSN or capability flags
                encryption = "OPEN"
                # RSN or WPA present detection (best-effort)
                if pkt.haslayer(Dot11EltRSN):
                    encryption = "WPA/WPA2/WPA3 (RSN)"
                else:
                    # check capability / tag for privacy
                    if pkt.haslayer(Dot11Beacon) and pkt[Dot11Beacon].network_stats().get("crypto"):
                        crypto = pkt[Dot11Beacon].network_stats().get("crypto")
                        encryption = ",".join(crypto) if crypto else "UNKNOWN"
                key = (ssid or "<hidden>", bssid)
                if key not in seen:
                    seen[key] = {"ssid": ssid or "<hidden>", "bssid": bssid, "encryption": encryption}
            except Exception:
                pass

    # sniff
    sniff_kwargs = {"prn": handle_pkt, "timeout": timeout}
    if iface:
        sniff_kwargs["iface"] = iface
    try:
        sniff(**sniff_kwargs)
    except Exception as e:
        return {"error": "sniff failed (needs admin & monitor-mode adapter & npcap configured?)", "details": str(e)}

    return {"method": "scapy", "networks": list(seen.values())}

# Real-time scanning functions
def background_scan():
    """Background thread that continuously scans and emits results via WebSocket"""
    global scanning_active
    scan_interval = 3  # seconds between scans
    
    while scanning_active:
        try:
            # Perform network scan
            result = scan_with_netsh()
            
            # Emit results to all connected clients
            socketio.emit('network_update', {
                'timestamp': time.time(),
                'data': result
            }, namespace='/scan')
            
            # Sleep before next scan
            time.sleep(scan_interval)
            
        except Exception as e:
            socketio.emit('scan_error', {
                'timestamp': time.time(),
                'error': str(e)
            }, namespace='/scan')
            time.sleep(scan_interval)

def start_scanning():
    """Start the background scanning thread"""
    global scanning_active, scan_thread
    
    with scan_lock:
        if not scanning_active:
            scanning_active = True
            scan_thread = threading.Thread(target=background_scan, daemon=True)
            scan_thread.start()
            return True
    return False

def stop_scanning():
    """Stop the background scanning thread"""
    global scanning_active, scan_thread
    
    with scan_lock:
        if scanning_active:
            scanning_active = False
            if scan_thread and scan_thread.is_alive():
                scan_thread.join(timeout=2)
            return True
    return False

# WebSocket event handlers
@socketio.on('connect', namespace='/scan')
def on_connect():
    """Handle client connection"""
    print(f"Client connected: {request.sid}")
    # Send initial scan immediately
    result = scan_with_netsh()
    emit('network_update', {
        'timestamp': time.time(),
        'data': result
    })

@socketio.on('disconnect', namespace='/scan')
def on_disconnect():
    """Handle client disconnection"""
    print(f"Client disconnected: {request.sid}")

@socketio.on('start_scan', namespace='/scan')
def handle_start_scan():
    """Handle request to start real-time scanning"""
    if start_scanning():
        emit('scan_status', {'status': 'started', 'message': 'Real-time scanning started'})
    else:
        emit('scan_status', {'status': 'already_running', 'message': 'Scanning already active'})

@socketio.on('stop_scan', namespace='/scan')
def handle_stop_scan():
    """Handle request to stop real-time scanning"""
    if stop_scanning():
        emit('scan_status', {'status': 'stopped', 'message': 'Real-time scanning stopped'})
    else:
        emit('scan_status', {'status': 'not_running', 'message': 'Scanning was not active'})

@socketio.on('request_scan', namespace='/scan')
def handle_request_scan():
    """Handle one-time scan request"""
    result = scan_with_netsh()
    emit('network_update', {
        'timestamp': time.time(),
        'data': result
    })

# HTTP API endpoints
@app.route("/api/scan", methods=["GET"])
def api_scan():
    """
    Primary endpoint: attempt netsh first (reliable on Windows).
    If netsh fails and scapy is available and you're on Windows with Npcap+monitor mode,
    the endpoint will try scapy as fallback.
    """
    # Try netsh
    netsh_result = scan_with_netsh()
    if "networks" in netsh_result:
        return jsonify(netsh_result)
    # Fallback: try scapy capture (best effort)
    scapy_result = scan_with_scapy()
    # Return both results for transparency
    return jsonify({"netsh_result": netsh_result, "scapy_result": scapy_result})

@app.route("/api/scan/start", methods=["POST"])
def api_start_scan():
    """Start real-time scanning via HTTP"""
    if start_scanning():
        return jsonify({"status": "started", "message": "Real-time scanning started"})
    else:
        return jsonify({"status": "already_running", "message": "Scanning already active"})

@app.route("/api/scan/stop", methods=["POST"])
def api_stop_scan():
    """Stop real-time scanning via HTTP"""
    if stop_scanning():
        return jsonify({"status": "stopped", "message": "Real-time scanning stopped"})
    else:
        return jsonify({"status": "not_running", "message": "Scanning was not active"})

@app.route("/")
def index():
    """Serve a simple test page for WebSocket connection"""
    return '''
<!DOCTYPE html>
<html>
<head>
    <title>Network Scanner - Real-time</title>
    <script src="https://cdn.socket.io/4.0.0/socket.io.min.js"></script>
</head>
<body>
    <h1>Real-time Network Scanner</h1>
    <div>
        <button onclick="startScan()">Start Real-time Scan</button>
        <button onclick="stopScan()">Stop Scan</button>
        <button onclick="requestScan()">One-time Scan</button>
    </div>
    <div id="status"></div>
    <div id="networks"></div>

    <script>
        const socket = io('/scan');
        
        socket.on('connect', function() {
            document.getElementById('status').innerHTML = '<p style="color: green;">Connected to server</p>';
        });
        
        socket.on('network_update', function(data) {
            const networksDiv = document.getElementById('networks');
            const timestamp = new Date(data.timestamp * 1000).toLocaleTimeString();
            
            let html = `<h3>Networks (${timestamp})</h3>`;
            
            if (data.data.networks && data.data.networks.length > 0) {
                html += '<ul>';
                data.data.networks.forEach(network => {
                    html += `<li><strong>${network.ssid}</strong>`;
                    if (network.bssids && network.bssids.length > 0) {
                        html += '<ul>';
                        network.bssids.forEach(bssid => {
                            html += `<li>BSSID: ${bssid.bssid}, Signal: ${bssid.signal}, Channel: ${bssid.channel}</li>`;
                        });
                        html += '</ul>';
                    }
                    html += '</li>';
                });
                html += '</ul>';
            } else {
                html += '<p>No networks found</p>';
            }
            
            networksDiv.innerHTML = html;
        });
        
        socket.on('scan_status', function(data) {
            document.getElementById('status').innerHTML = `<p>Status: ${data.status} - ${data.message}</p>`;
        });
        
        socket.on('scan_error', function(data) {
            document.getElementById('status').innerHTML = `<p style="color: red;">Error: ${data.error}</p>`;
        });
        
        function startScan() {
            socket.emit('start_scan');
        }
        
        function stopScan() {
            socket.emit('stop_scan');
        }
        
        function requestScan() {
            socket.emit('request_scan');
        }
    </script>
</body>
</html>
'''

if __name__ == "__main__":
    socketio.run(app, host="0.0.0.0", port=5000, debug=True)
