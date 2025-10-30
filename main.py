"""
Privacy Guard Backend API Server
Handles network scanning, risk assessment, and VPN management
"""
from scanner.scanner import scan_current_network, calculate_risk_score
from flask import Flask, jsonify, request
from flask_cors import CORS
import sqlite3
import datetime
import json
from typing import Dict, List
import threading
import time


app = Flask(__name__)
CORS(app)

# Database setup
DB_PATH = 'db.sqlite'

def init_db():
    """Initialize SQLite database with required tables"""
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    
    # Networks table - stores scanned network info
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
    
    # Threats table - logs detected threats
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS threats (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            network_id INTEGER,
            threat_type TEXT,
            severity TEXT,
            description TEXT,
            detected_at TIMESTAMP,
            FOREIGN KEY(network_id) REFERENCES networks(id)
        )
    ''')
    
    # Sessions table - tracks protection sessions
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS sessions (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            network_id INTEGER,
            started_at TIMESTAMP,
            ended_at TIMESTAMP,
            protection_type TEXT,
            data_protected_mb REAL,
            FOREIGN KEY(network_id) REFERENCES networks(id)
        )
    ''')
    
    # Telemetry table - general usage stats
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS telemetry (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            event_type TEXT,
            event_data TEXT,
            timestamp TIMESTAMP
        )
    ''')
    
    conn.commit()
    conn.close()

# Initialize database on startup
init_db()

# Global state for current scan
current_scan = {
    'scanning': False,
    'current_network': None,
    'last_scan': None,
    'protection_active': False
}

# ==================== API ENDPOINTS ====================


@app.route('/')
def index():
    return {
        "message": "✅ Privacy Guard Backend is Running",
        "available_endpoints": [
            "/api/scan/start",
            "/api/scan/results",
            "/api/telemetry"
        ]
    }


@app.route('/api/health', methods=['GET'])
def health_check():
    """Health check endpoint"""
    return jsonify({
        'status': 'healthy',
        'timestamp': datetime.datetime.now().isoformat(),
        'version': '1.0.0'
    })

@app.route('/api/scan/status', methods=['GET'])
def get_scan_status():
    """Get current scanning status and network info"""
    return jsonify({
        'scanning': current_scan['scanning'],
        'current_network': current_scan['current_network'],
        'last_scan': current_scan['last_scan'],
        'protection_active': current_scan['protection_active']
    })

@app.route('/api/scan/start', methods=['POST'])
def start_scan():
    """
    Start network scanning
    Expected input: {"interface": "wlan0"} (optional)
    """
    if current_scan['scanning']:
        return jsonify({'error': 'Scan already in progress'}), 409
    
    data = request.get_json() or {}
    interface = data.get('interface', 'auto')
    
    # Start scan in background thread
    scan_thread = threading.Thread(
        target=perform_network_scan,
        args=(interface,)
    )
    scan_thread.daemon = True
    scan_thread.start()
    
    return jsonify({
        'message': 'Scan started',
        'interface': interface
    })

@app.route('/api/networks/current', methods=['GET'])
def get_current_network():
    """Get detailed info about currently connected network"""
    if not current_scan['current_network']:
        return jsonify({'error': 'No network connected'}), 404
    
    network = current_scan['current_network']
    
    # Get threat history from database
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute('''
        SELECT threat_type, severity, description, detected_at
        FROM threats
        WHERE network_id = ?
        ORDER BY detected_at DESC
        LIMIT 10
    ''', (network.get('db_id'),))
    threats = cursor.fetchall()
    conn.close()
    
    network['threat_history'] = [
        {
            'type': t[0],
            'severity': t[1],
            'description': t[2],
            'detected_at': t[3]
        }
        for t in threats
    ]
    
    return jsonify(network)

@app.route('/api/networks/history', methods=['GET'])
def get_network_history():
    """Get list of previously scanned networks"""
    limit = request.args.get('limit', 50, type=int)
    
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute('''
        SELECT id, ssid, bssid, encryption_type, risk_score, 
               risk_level, last_seen, scan_count
        FROM networks
        ORDER BY last_seen DESC
        LIMIT ?
    ''', (limit,))
    
    networks = cursor.fetchall()
    conn.close()
    
    return jsonify({
        'networks': [
            {
                'id': n[0],
                'ssid': n[1],
                'bssid': n[2],
                'encryption': n[3],
                'risk_score': n[4],
                'risk_level': n[5],
                'last_seen': n[6],
                'scan_count': n[7]
            }
            for n in networks
        ]
    })

@app.route('/api/protection/enable', methods=['POST'])
def enable_protection():
    """
    Enable VPN/proxy protection
    Expected input: {"method": "wireguard|openvpn|proxy"}
    """
    data = request.get_json() or {}
    method = data.get('method', 'proxy')
    
    # This would integrate with vpn/wg_manager.py
    # For now, simulate activation
    current_scan['protection_active'] = True
    
    # Log session start
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    network_id = current_scan['current_network'].get('db_id') if current_scan['current_network'] else None
    cursor.execute('''
        INSERT INTO sessions (network_id, started_at, protection_type)
        VALUES (?, ?, ?)
    ''', (network_id, datetime.datetime.now(), method))
    session_id = cursor.lastrowid
    conn.commit()
    conn.close()
    
    return jsonify({
        'status': 'protected',
        'method': method,
        'session_id': session_id,
        'message': f'Protection enabled via {method}'
    })

@app.route('/api/protection/disable', methods=['POST'])
def disable_protection():
    """Disable VPN/proxy protection"""
    current_scan['protection_active'] = False
    
    # Update last session
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute('''
        UPDATE sessions
        SET ended_at = ?
        WHERE ended_at IS NULL
        ORDER BY started_at DESC
        LIMIT 1
    ''', (datetime.datetime.now(),))
    conn.commit()
    conn.close()
    
    return jsonify({
        'status': 'unprotected',
        'message': 'Protection disabled'
    })

@app.route('/api/threats', methods=['GET'])
def get_threats():
    """Get recent threat detections"""
    limit = request.args.get('limit', 20, type=int)
    severity = request.args.get('severity', None)
    
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    
    query = '''
        SELECT t.id, t.threat_type, t.severity, t.description, 
               t.detected_at, n.ssid
        FROM threats t
        LEFT JOIN networks n ON t.network_id = n.id
        WHERE 1=1
    '''
    params = []
    
    if severity:
        query += ' AND t.severity = ?'
        params.append(severity)
    
    query += ' ORDER BY t.detected_at DESC LIMIT ?'
    params.append(limit)
    
    cursor.execute(query, params)
    threats = cursor.fetchall()
    conn.close()
    
    return jsonify({
        'threats': [
            {
                'id': t[0],
                'type': t[1],
                'severity': t[2],
                'description': t[3],
                'detected_at': t[4],
                'network_ssid': t[5]
            }
            for t in threats
        ]
    })

@app.route('/api/stats', methods=['GET'])
def get_statistics():
    """Get usage statistics and analytics"""
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    
    # Total networks scanned
    cursor.execute('SELECT COUNT(*) FROM networks')
    total_networks = cursor.fetchone()[0]
    
    # High-risk networks
    cursor.execute("SELECT COUNT(*) FROM networks WHERE risk_level = 'HIGH'")
    high_risk = cursor.fetchone()[0]
    
    # Total threats detected
    cursor.execute('SELECT COUNT(*) FROM threats')
    total_threats = cursor.fetchone()[0]
    
    # Protection sessions
    cursor.execute('SELECT COUNT(*) FROM sessions')
    total_sessions = cursor.fetchone()[0]
    
    # Average risk score
    cursor.execute('SELECT AVG(risk_score) FROM networks')
    avg_risk = cursor.fetchone()[0] or 0
    
    conn.close()
    
    return jsonify({
        'total_networks_scanned': total_networks,
        'high_risk_networks': high_risk,
        'total_threats_detected': total_threats,
        'protection_sessions': total_sessions,
        'average_risk_score': round(avg_risk, 2)
    })

@app.route('/api/telemetry', methods=['POST'])
def log_telemetry():
    """Log telemetry event"""
    data = request.get_json()
    
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute('''
        INSERT INTO telemetry (event_type, event_data, timestamp)
        VALUES (?, ?, ?)
    ''', (
        data.get('event_type'),
        json.dumps(data.get('event_data', {})),
        datetime.datetime.now()
    ))
    conn.commit()
    conn.close()
    
    return jsonify({'status': 'logged'})

# ==================== BACKGROUND FUNCTIONS ====================

def perform_network_scan(interface: str):
    """
    Perform actual network scanning
    This integrates with scanner/scanner.py
    """
    current_scan['scanning'] = True
    
    try:
        # Import scanner module (from scanner/scanner.py)
        from scanner.scanner import scan_current_network, calculate_risk_score
        
        # Scan network
        network_info = scan_current_network(interface)
        risk_data = calculate_risk_score(network_info)
        
        # Combine data
        scan_result = {
            **network_info,
            **risk_data,
            'scanned_at': datetime.datetime.now().isoformat()
        }
        
        # Save to database
        db_id = save_network_to_db(scan_result)
        scan_result['db_id'] = db_id
        
        # Save detected threats
        if risk_data.get('threats'):
            save_threats_to_db(db_id, risk_data['threats'])
        
        # Update current scan state
        current_scan['current_network'] = scan_result
        current_scan['last_scan'] = datetime.datetime.now().isoformat()
        
    except Exception as e:
        print(f"Scan error: {e}")
        current_scan['current_network'] = None
    finally:
        current_scan['scanning'] = False

def save_network_to_db(network_data: Dict) -> int:
    """Save or update network in database"""
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    
    # Check if network exists
    cursor.execute('SELECT id FROM networks WHERE bssid = ?', (network_data.get('bssid'),))
    existing = cursor.fetchone()
    
    now = datetime.datetime.now()
    
    if existing:
        # Update existing
        network_id = existing[0]
        cursor.execute('''
            UPDATE networks
            SET ssid = ?, encryption_type = ?, signal_strength = ?,
                risk_score = ?, risk_level = ?, last_seen = ?,
                scan_count = scan_count + 1
            WHERE id = ?
        ''', (
            network_data.get('ssid'),
            network_data.get('encryption_type'),
            network_data.get('signal_strength'),
            network_data.get('score'),
            network_data.get('level'),
            now,
            network_id
        ))
    else:
        # Insert new
        cursor.execute('''
            INSERT INTO networks 
            (ssid, bssid, encryption_type, signal_strength, risk_score, 
             risk_level, first_seen, last_seen)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        ''', (
            network_data.get('ssid'),
            network_data.get('bssid'),
            network_data.get('encryption_type'),
            network_data.get('signal_strength'),
            network_data.get('score'),
            network_data.get('level'),
            now,
            now
        ))
        network_id = cursor.lastrowid
    
    conn.commit()
    conn.close()
    
    return network_id

def save_threats_to_db(network_id: int, threats: List[Dict]):
    """Save detected threats to database"""
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    
    for threat in threats:
        cursor.execute('''
            INSERT INTO threats (network_id, threat_type, severity, description, detected_at)
            VALUES (?, ?, ?, ?, ?)
        ''', (
            network_id,
            threat.get('type'),
            threat.get('severity'),
            threat.get('description'),
            datetime.datetime.now()
        ))
    
    conn.commit()
    conn.close()

if __name__ == '__main__':
    print("Starting Privacy Guard Backend API...")
    print("API will be available at http://localhost:5000")
    app.run(host='0.0.0.0', port=5000, debug=True)