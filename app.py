"""
Unified Privacy Guard Backend API Server
Combines main.py (REST API) + realtimescan.py (WebSocket) into one Flask-SocketIO app
"""
import subprocess
import re
import json
import platform
import threading
import time
import sqlite3
import datetime
from typing import Dict, List

from flask import Flask, jsonify, request
from flask_cors import CORS
from flask_socketio import SocketIO, emit

# Import scanner functions
from scanner.scanner import scan_current_network, calculate_risk_score

# Initialize Flask app
app = Flask(__name__)
app.config['SECRET_KEY'] = 'your-secret-key-here'

# Enable CORS for all routes
CORS(app)

# Initialize Socket.IO with CORS
socketio = SocketIO(app, cors_allowed_origins="*", async_mode='threading')

# Database setup
DB_PATH = 'db.sqlite'

# Global state for real-time scanning
scanning_active = False
scan_thread = None
scan_lock = threading.Lock()

# ============================================================================
# DATABASE FUNCTIONS (from main.py)
# ============================================================================

def init_db():
    """Initialize SQLite database with required tables"""
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    
    # Networks table
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS networks (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            ssid TEXT NOT NULL,
            bssid TEXT,
            encryption_type TEXT,
            signal_strength INTEGER,
            risk_score INTEGER,
            risk_level TEXT,
            first_seen TIMESTAMP,
            last_seen TIMESTAMP,
            scan_count INTEGER DEFAULT 1
        )
    ''')
    
    # Threats table
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS threats (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            network_id INTEGER,
            threat_type TEXT,
            severity TEXT,
            description TEXT,
            detected_at TIMESTAMP,
            FOREIGN KEY (network_id) REFERENCES networks(id)
        )
    ''')
    
    # Sessions table
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS sessions (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            network_id INTEGER,
            connected_at TIMESTAMP,
            disconnected_at TIMESTAMP,
            duration INTEGER,
            FOREIGN KEY (network_id) REFERENCES networks(id)
        )
    ''')
    
    # Telemetry table
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS telemetry (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            session_id INTEGER,
            timestamp TIMESTAMP,
            packet_count INTEGER,
            data_usage INTEGER,
            FOREIGN KEY (session_id) REFERENCES sessions(id)
        )
    ''')
    
    conn.commit()
    conn.close()

def get_db_connection():
    """Get database connection"""
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn

# ============================================================================
# NETSH SCANNING FUNCTIONS (from realtimescan.py)
# ============================================================================

def parse_netsh_output(text):
    """Parse output from netsh wlan show networks mode=bssid"""
    networks = []
    ssid_blocks = re.split(r'\nSSID \d+ :', text)[1:]
    for block in ssid_blocks:
        lines = [ln.strip() for ln in block.splitlines() if ln.strip()]
        ssid = lines[0] if lines else "<hidden>"
        bssids = []
        current = {}
        ssid_auth = None
        ssid_enc = None
        
        for ln in lines[1:]:
            m = re.match(r'BSSID \d+ : (.*)', ln)
            if m:
                if current:
                    bssids.append(current)
                current = {"bssid": m.group(1)}
                continue
            m = re.match(r'Signal\s*:\s*(.*)', ln)
            if m and current:
                current["signal"] = m.group(1)
                continue
            m = re.match(r'Channel\s*:\s*(.*)', ln)
            if m and current:
                current["channel"] = m.group(1)
                continue
            m = re.match(r'Authentication\s*:\s*(.*)', ln)
            if m:
                ssid_auth = m.group(1)
                continue
            m = re.match(r'Encryption\s*:\s*(.*)', ln)
            if m:
                ssid_enc = m.group(1)
                continue
        
        if current:
            bssids.append(current)
        
        for b in bssids:
            if 'signal' not in b:
                b['signal'] = None
            if 'channel' not in b:
                b['channel'] = None
            b['authentication'] = ssid_auth
            b['encryption'] = ssid_enc
        
        networks.append({
            "ssid": ssid,
            "bssids": bssids
        })
    return networks

def scan_with_netsh():
    """Use Windows netsh to fetch networks"""
    try:
        if platform.system().lower() != 'windows':
            return {"error": "netsh-based scanning works only on Windows."}
        
        completed = subprocess.run(
            ["netsh", "wlan", "show", "networks", "mode=bssid"],
            capture_output=True,
            text=True,
            check=True,
            encoding='utf-8',
            errors='replace'
        )
        text = completed.stdout
        networks = parse_netsh_output(text)
        return {"method": "netsh", "networks": networks}
    except subprocess.CalledProcessError as e:
        return {"error": "netsh command failed", "details": str(e)}
    except UnicodeDecodeError as e:
        try:
            completed = subprocess.run(
                ["netsh", "wlan", "show", "networks", "mode=bssid"],
                capture_output=True,
                text=True,
                check=True,
                encoding='cp1252',
                errors='replace'
            )
            text = completed.stdout
            networks = parse_netsh_output(text)
            return {"method": "netsh", "networks": networks}
        except Exception as fallback_e:
            return {"error": "encoding error", "details": str(fallback_e)}
    except Exception as e:
        return {"error": "unexpected error", "details": str(e)}

# ============================================================================
# BACKGROUND SCANNING (from realtimescan.py)
# ============================================================================

def background_scan():
    """Background thread that continuously scans and emits results via WebSocket"""
    global scanning_active
    scan_interval = 3
    
    print("Background scanning thread started")
    
    while scanning_active:
        try:
            print("Performing background network scan...")
            result = scan_with_netsh()
            
            if 'error' in result:
                print(f"Scan error: {result['error']}")
            else:
                print(f"Scan successful: found {len(result.get('networks', []))} networks")
            
            socketio.emit('network_update', {
                'timestamp': time.time(),
                'data': result
            }, namespace='/scan')
            
            time.sleep(scan_interval)
        except Exception as e:
            print(f"Background scan exception: {str(e)}")
            socketio.emit('scan_error', {
                'timestamp': time.time(),
                'error': str(e)
            }, namespace='/scan')
            time.sleep(scan_interval)
    
    print("Background scanning thread stopped")

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

# ============================================================================
# WEBSOCKET HANDLERS (from realtimescan.py)
# ============================================================================

@socketio.on('connect', namespace='/scan')
def on_connect():
    """Handle client connection"""
    print(f"Client connected: {request.sid}")
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

# ============================================================================
# REST API ENDPOINTS (from main.py + additions)
# ============================================================================

@app.route('/api/scan', methods=['GET'])
def api_scan():
    """Get network scan results - combines netsh + scanner module data"""
    try:
        # Get current network info from scanner module (has BSSID, encryption, etc)
        current_network = scan_current_network()
        
        # Also get all available networks from netsh
        netsh_result = scan_with_netsh()
        
        # Combine both sources
        return jsonify({
            "current_network": current_network,
            "available_networks": netsh_result.get("networks", []),
            "method": "combined"
        })
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route('/api/networks', methods=['GET'])
def get_networks():
    """Get all networks with enhanced details"""
    try:
        # Get available networks from netsh
        netsh_result = scan_with_netsh()
        networks = netsh_result.get('networks', [])
        
        # Enrich each network with additional details
        for network in networks:
            if network.get('bssids') and len(network['bssids']) > 0:
                bssid_info = network['bssids'][0]
                # Add parsed signal strength
                signal_str = bssid_info.get('signal', 'Unknown')
                if isinstance(signal_str, str):
                    # Extract percentage if format is "XX %"
                    match = re.search(r'(\d+)', signal_str)
                    if match:
                        percent = int(match.group(1))
                        bssid_info['signal_percent'] = percent
                        bssid_info['signal_dbm'] = -100 + (percent / 2)  # Approximate dBm conversion
        
        return jsonify({"networks": networks, "count": len(networks)})
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route('/api/scan/start', methods=['POST'])
def api_start_scan():
    """Start real-time scanning via HTTP"""
    if start_scanning():
        return jsonify({"status": "started", "message": "Real-time scanning started"})
    else:
        return jsonify({"status": "already_running", "message": "Scanning already active"})

@app.route('/api/scan/stop', methods=['POST'])
def api_stop_scan():
    """Stop real-time scanning via HTTP"""
    if stop_scanning():
        return jsonify({"status": "stopped", "message": "Real-time scanning stopped"})
    else:
        return jsonify({"status": "not_running", "message": "Scanning was not active"})

@app.route('/api/stats', methods=['GET'])
def get_stats():
    """Get statistics from database"""
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        
        # Get total networks
        cursor.execute('SELECT COUNT(*) as count FROM networks')
        total_networks = cursor.fetchone()['count']
        
        # Get high risk networks
        cursor.execute('SELECT COUNT(*) as count FROM networks WHERE risk_level = "HIGH"')
        high_risk = cursor.fetchone()['count']
        
        # Get total threats
        cursor.execute('SELECT COUNT(*) as count FROM threats')
        total_threats = cursor.fetchone()['count']
        
        # Get active sessions
        cursor.execute('SELECT COUNT(*) as count FROM sessions WHERE disconnected_at IS NULL')
        active_sessions = cursor.fetchone()['count']
        
        conn.close()
        
        return jsonify({
            "totalNetworks": total_networks,
            "highRiskNetworks": high_risk,
            "totalThreats": total_threats,
            "protectionSessions": active_sessions
        })
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route('/api/networks/history', methods=['GET'])
def get_networks_history():
    """Get historical network data"""
    try:
        limit = request.args.get('limit', 50, type=int)
        conn = get_db_connection()
        cursor = conn.cursor()
        
        cursor.execute('''
            SELECT id, ssid, bssid, encryption_type, signal_strength, risk_score, 
                   risk_level, first_seen, last_seen, scan_count
            FROM networks
            ORDER BY last_seen DESC
            LIMIT ?
        ''', (limit,))
        
        rows = cursor.fetchall()
        networks = [dict(row) for row in rows]
        conn.close()
        
        return jsonify({"networks": networks})
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route('/api/threats', methods=['GET'])
def get_threats():
    """Get threat history"""
    try:
        limit = request.args.get('limit', 20, type=int)
        conn = get_db_connection()
        cursor = conn.cursor()
        
        cursor.execute('''
            SELECT t.id, t.threat_type, t.severity, t.description, t.detected_at, n.ssid as network_ssid
            FROM threats t
            LEFT JOIN networks n ON t.network_id = n.id
            ORDER BY t.detected_at DESC
            LIMIT ?
        ''', (limit,))
        
        rows = cursor.fetchall()
        threats = [dict(row) for row in rows]
        conn.close()
        
        return jsonify({"threats": threats})
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route('/api/protection/enable', methods=['POST'])
def enable_protection():
    """Enable VPN protection"""
    try:
        data = request.json or {}
        network_id = data.get('network_id')
        
        conn = get_db_connection()
        cursor = conn.cursor()
        
        cursor.execute('''
            INSERT INTO sessions (network_id, connected_at)
            VALUES (?, ?)
        ''', (network_id, datetime.datetime.now()))
        
        conn.commit()
        session_id = cursor.lastrowid
        conn.close()
        
        return jsonify({
            "status": "enabled",
            "session_id": session_id,
            "message": "Protection enabled"
        })
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route('/api/protection/disable', methods=['POST'])
def disable_protection():
    """Disable VPN protection"""
    try:
        data = request.json or {}
        session_id = data.get('session_id')
        
        conn = get_db_connection()
        cursor = conn.cursor()
        
        cursor.execute('''
            UPDATE sessions
            SET disconnected_at = ?
            WHERE id = ?
        ''', (datetime.datetime.now(), session_id))
        
        conn.commit()
        conn.close()
        
        return jsonify({
            "status": "disabled",
            "message": "Protection disabled"
        })
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route('/api/arp-table', methods=['GET'])
def get_arp_table():
    """Get ARP table (connected devices)"""
    try:
        if platform.system().lower() != 'windows':
            return jsonify({"error": "ARP table fetching only supported on Windows"}), 400
        
        result = subprocess.run(
            ["arp", "-a"],
            capture_output=True,
            text=True,
            encoding='utf-8',
            errors='replace'
        )
        
        # Parse ARP output
        devices = []
        for line in result.stdout.split('\n'):
            line = line.strip()
            if not line or 'Internet Address' in line or 'Physical Address' in line:
                continue
            parts = line.split()
            if len(parts) >= 3:
                devices.append({
                    "ip": parts[0],
                    "mac": parts[1],
                    "status": parts[2] if len(parts) > 2 else "unknown"
                })
        
        return jsonify({"devices": devices})
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route('/health', methods=['GET'])
def health():
    """Health check endpoint"""
    return jsonify({"status": "ok", "service": "privacy-guard-api"})

@app.route('/')
def index():
    """Root endpoint"""
    return jsonify({
        "service": "Privacy Guard Backend API",
        "version": "1.0",
        "endpoints": {
            "REST": [
                "/api/scan",
                "/api/scan/start",
                "/api/scan/stop",
                "/api/stats",
                "/api/networks/history",
                "/api/threats",
                "/api/protection/enable",
                "/api/protection/disable",
                "/api/arp-table",
                "/health"
            ],
            "WebSocket": {
                "namespace": "/scan",
                "events": ["network_update", "scan_status", "scan_error"],
                "emit": ["start_scan", "stop_scan", "request_scan"]
            }
        }
    })

# ============================================================================
# APP INITIALIZATION
# ============================================================================

if __name__ == '__main__':
    print("=" * 60)
    print("Privacy Guard Backend API Server")
    print("=" * 60)
    print("Initializing database...")
    init_db()
    print("✓ Database initialized")
    print()
    print("Starting server on http://0.0.0.0:5000")
    print("- REST API: http://localhost:5000")
    print("- WebSocket: ws://localhost:5000/socket.io/?EIO=4&transport=websocket")
    print("- Health: http://localhost:5000/health")
    print()
    print("=" * 60)
    
    socketio.run(app, host='0.0.0.0', port=5000, debug=True, allow_unsafe_werkzeug=True)
