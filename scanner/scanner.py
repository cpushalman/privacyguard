"""
Privacy Guard Network Scanner
Detects network properties, security issues, and calculates risk scores
"""
import time
import ssl
import urllib.request
from datetime import datetime
import subprocess
import re
import platform
from typing import Dict, List, Optional
import socket
import struct

try:
    from scapy.all import ARP, Ether, srp, sniff, IP, TCP, UDP, DNS
    SCAPY_AVAILABLE = True
except ImportError:
    SCAPY_AVAILABLE = False
    print("Warning: Scapy not available. Install with: pip install scapy")


def measure_dns_latency(domains=["google.com", "cloudflare.com"]) -> float:
    """Average DNS resolution time in ms"""
    times = []
    for domain in domains:
        start = time.time()
        try:
            socket.gethostbyname(domain)
            times.append((time.time() - start) * 1000)
        except:
            times.append(500)  # timeout penalty
    return round(sum(times) / len(times), 2) if times else 500.0

def measure_packet_loss(host="8.8.8.8", count=10) -> float:
    """Ping and return packet loss %"""
    try:
        param = "-n" if platform.system() == "Windows" else "-c"
        result = subprocess.run(
            ["ping", param, str(count), host],
            capture_output=True, text=True, timeout=20
        )
        if platform.system() == "Windows":
            lost = result.stdout.count("Request timed out")
        else:
            lost = int(re.search(r'(\d+)% packet loss', result.stdout).group(1))
        return (lost / count) * 100
    except:
        return 100.0
    


def check_tls_cert(host="www.google.com", port=443) -> int:
    """Return 1 if valid cert, 0 otherwise"""
    try:
        context = ssl.create_default_context()
        with socket.create_connection((host, port), timeout=5) as sock:
            with context.wrap_socket(sock, server_hostname=host) as ssock:
                cert = ssock.getpeercert()
                if not cert:
                    return 0
                not_after = cert.get("notAfter")
                if not_after:
                    from email.utils import parsedate
                    expiry = time.mktime(parsedate(not_after))
                    if expiry < time.time():
                        return 0
                return 1
    except:
        return 0
    

def export_features_for_ml(network_data: Dict, risk_data: Dict, label: int = None) -> Dict:
    """Return ML-ready feature dict"""
    return {
        "Signal_Strength_dBm": network_data.get("signal_strength"),
        "Encryption_Type": network_data.get("encryption_type"),
        "ARP_Anomalies": 1 if network_data.get("arp_issues") else 0,
        "TLS_Cert_Validity": check_tls_cert(),
        "Captive_Portal": 1 if network_data.get("captive_portal") else 0,
        "DNS_Latency_ms": measure_dns_latency(),
        "Packet_Loss_%": measure_packet_loss(),
        "Data_Leak_Attempts": network_data.get("traffic_analysis", {}).get("unencrypted_count", 0),
        "Is_Suspicious": label if label is not None else 0,
        "SSID": network_data.get("ssid"),
        "BSSID": network_data.get("bssid"),
        "Timestamp": datetime.now().isoformat()
    }

# Network interface detection
def get_default_interface() -> str:
    """Get the default network interface"""
    system = platform.system()
    
    try:
        if system == "Linux":
            result = subprocess.run(['ip', 'route'], capture_output=True, text=True)
            match = re.search(r'default via .+ dev (\S+)', result.stdout)
            return match.group(1) if match else 'wlan0'
        
        elif system == "Darwin":  # macOS
            result = subprocess.run(['route', 'get', 'default'], capture_output=True, text=True)
            match = re.search(r'interface: (\S+)', result.stdout)
            return match.group(1) if match else 'en0'
        
        elif system == "Windows":
            # Windows uses different interface names
            return "Wi-Fi"
    except:
        pass
    
    return "auto"

def get_wifi_info(interface: str = None) -> Dict:
    """
    Get current WiFi connection information
    Returns: {ssid, bssid, encryption_type, signal_strength, channel}
    """
    if interface is None or interface == "auto":
        interface = get_default_interface()
    
    system = platform.system()
    wifi_info = {
        'ssid': None,
        'bssid': None,
        'encryption_type': 'unknown',
        'signal_strength': 0,
        'channel': 0,
        'interface': interface
    }
    
    try:
        if system == "Linux":
            # Use iwconfig
            result = subprocess.run(['iwconfig', interface], capture_output=True, text=True)
            output = result.stdout
            
            # Extract SSID
            ssid_match = re.search(r'ESSID:"([^"]+)"', output)
            if ssid_match:
                wifi_info['ssid'] = ssid_match.group(1)
            
            # Extract signal strength
            signal_match = re.search(r'Signal level=(-?\d+)', output)
            if signal_match:
                wifi_info['signal_strength'] = int(signal_match.group(1))
            
            # Use iw for more details
            result = subprocess.run(['iw', 'dev', interface, 'link'], 
                                   capture_output=True, text=True)
            output = result.stdout
            
            # Extract BSSID
            bssid_match = re.search(r'Connected to ([0-9a-fA-F:]+)', output)
            if bssid_match:
                wifi_info['bssid'] = bssid_match.group(1)
            
            # Check encryption
            if 'WPA' in output or 'RSN' in output:
                wifi_info['encryption_type'] = 'WPA2' if 'RSN' in output else 'WPA'
            elif 'WEP' in output:
                wifi_info['encryption_type'] = 'WEP'
            else:
                wifi_info['encryption_type'] = 'Open'
        
        elif system == "Darwin":  # macOS
            result = subprocess.run(['/System/Library/PrivateFrameworks/Apple80211.framework/Versions/Current/Resources/airport', '-I'],
                                   capture_output=True, text=True)
            output = result.stdout
            
            for line in output.split('\n'):
                if 'SSID:' in line:
                    wifi_info['ssid'] = line.split(':')[1].strip()
                elif 'BSSID:' in line:
                    wifi_info['bssid'] = line.split(':')[1].strip()
                elif 'agrCtlRSSI:' in line:
                    wifi_info['signal_strength'] = int(line.split(':')[1].strip())
                elif 'channel:' in line:
                    wifi_info['channel'] = int(line.split(':')[1].strip().split(',')[0])
            
            # Check encryption
            result = subprocess.run(['networksetup', '-getairportnetwork', interface],
                                   capture_output=True, text=True)
            if 'security' in result.stdout.lower():
                wifi_info['encryption_type'] = 'WPA2'
            else:
                wifi_info['encryption_type'] = 'Open'
        
        elif system == "Windows":
            result = subprocess.run(['netsh', 'wlan', 'show', 'interfaces'],
                                   capture_output=True, text=True)
            output = result.stdout
            
            for line in output.split('\n'):
                if 'SSID' in line and 'BSSID' not in line:
                    wifi_info['ssid'] = line.split(':')[1].strip()
                elif 'BSSID' in line:
                    wifi_info['bssid'] = line.split(':')[1].strip()
                elif 'Signal' in line:
                    signal_match = re.search(r'(\d+)%', line)
                    if signal_match:
                        # Convert percentage to dBm (approximate)
                        percent = int(signal_match.group(1))
                        wifi_info['signal_strength'] = -100 + (percent / 2)
                elif 'Authentication' in line:
                    auth = line.split(':')[1].strip()
                    if 'Open' in auth:
                        wifi_info['encryption_type'] = 'Open'
                    elif 'WPA2' in auth:
                        wifi_info['encryption_type'] = 'WPA2'
                    elif 'WPA' in auth:
                        wifi_info['encryption_type'] = 'WPA'
    
    except Exception as e:
        print(f"Error getting WiFi info: {e}")
    
    return wifi_info

def detect_arp_spoofing(interface: str, timeout: int = 5) -> List[Dict]:
    """
    Detect ARP spoofing attacks
    Returns list of suspicious ARP entries
    """
    if not SCAPY_AVAILABLE:
        return []
    
    suspicious = []
    ip_mac_map = {}
    
    try:
        # Get local network subnet
        gateway = get_gateway_ip()
        if not gateway:
            return []
        
        # Build subnet (e.g., 192.168.1.0/24)
        subnet = '.'.join(gateway.split('.')[:-1]) + '.0/24'
        
        # Perform ARP scan
        arp_request = ARP(pdst=subnet)
        broadcast = Ether(dst="ff:ff:ff:ff:ff:ff")
        arp_request_broadcast = broadcast / arp_request
        
        answered_list = srp(arp_request_broadcast, timeout=timeout, verbose=False, iface=interface)[0]
        
        for sent, received in answered_list:
            ip = received.psrc
            mac = received.hwsrc
            
            if ip in ip_mac_map and ip_mac_map[ip] != mac:
                suspicious.append({
                    'type': 'arp_spoof',
                    'ip': ip,
                    'mac_1': ip_mac_map[ip],
                    'mac_2': mac,
                    'description': f'Multiple MACs detected for IP {ip}'
                })
            
            ip_mac_map[ip] = mac
    
    except Exception as e:
        print(f"ARP spoofing detection error: {e}")
    
    return suspicious

def analyze_traffic(interface: str, duration: int = 10) -> Dict:
    """
    Analyze network traffic for security issues
    Returns: {http_ratio, https_ratio, suspicious_dns, packet_count}
    """
    if not SCAPY_AVAILABLE:
        return {
            'http_ratio': 0,
            'https_ratio': 0,
            'suspicious_dns': [],
            'packet_count': 0,
            'unencrypted_count': 0
        }
    
    packets_http = 0
    packets_https = 0
    packets_total = 0
    suspicious_dns = []
    unencrypted_protocols = 0
    
    def packet_callback(packet):
        nonlocal packets_http, packets_https, packets_total, unencrypted_protocols
        
        packets_total += 1
        
        # Check for HTTP/HTTPS
        if packet.haslayer(TCP):
            if packet[TCP].dport == 80 or packet[TCP].sport == 80:
                packets_http += 1
                unencrypted_protocols += 1
            elif packet[TCP].dport == 443 or packet[TCP].sport == 443:
                packets_https += 1
        
        # Check for suspicious DNS
        if packet.haslayer(DNS) and packet.haslayer(IP):
            dns_layer = packet[DNS]
            if dns_layer.qr == 1:  # DNS response
                # Check for common domains with wrong IPs
                qname = dns_layer.qd.qname.decode('utf-8') if hasattr(dns_layer.qd, 'qname') else ''
                if any(domain in qname.lower() for domain in ['google.com', 'facebook.com', 'amazon.com']):
                    if dns_layer.an:
                        response_ip = dns_layer.an.rdata
                        suspicious_dns.append({
                            'domain': qname,
                            'ip': str(response_ip)
                        })
    
    try:
        # Capture packets
        sniff(iface=interface, prn=packet_callback, timeout=duration, store=False)
    except Exception as e:
        print(f"Traffic analysis error: {e}")
    
    http_ratio = (packets_http / packets_total * 100) if packets_total > 0 else 0
    https_ratio = (packets_https / packets_total * 100) if packets_total > 0 else 0
    
    return {
        'http_ratio': round(http_ratio, 2),
        'https_ratio': round(https_ratio, 2),
        'suspicious_dns': suspicious_dns,
        'packet_count': packets_total,
        'unencrypted_count': unencrypted_protocols
    }

def check_captive_portal() -> bool:
    """
    Check if connected to a captive portal network
    """
    try:
        # Try to fetch a known HTTP endpoint
        import urllib.request
        response = urllib.request.urlopen('http://www.google.com/generate_204', timeout=3)
        
        # Google returns 204 for this endpoint
        # Captive portals will redirect (3xx) or return different code
        return response.getcode() != 204
    except:
        return False

def get_gateway_ip() -> Optional[str]:
    """Get default gateway IP address"""
    system = platform.system()
    
    try:
        if system == "Linux" or system == "Darwin":
            result = subprocess.run(['ip', 'route'], capture_output=True, text=True)
            match = re.search(r'default via ([\d.]+)', result.stdout)
            return match.group(1) if match else None
        elif system == "Windows":
            result = subprocess.run(['ipconfig'], capture_output=True, text=True)
            match = re.search(r'Default Gateway.*: ([\d.]+)', result.stdout)
            return match.group(1) if match else None
    except:
        pass
    
    return None

def scan_current_network(interface: str = None) -> Dict:
    """
    Main scanning function - orchestrates all checks
    """
    print(f"Starting network scan on interface: {interface or 'auto'}")
    
    # Get WiFi info
    wifi_info = get_wifi_info(interface)
    
    # Additional checks
    has_captive_portal = check_captive_portal()
    
    # Traffic analysis (quick 5-second capture)
    traffic_data = analyze_traffic(wifi_info['interface'], duration=5)
    
    # ARP spoofing check
    arp_issues = detect_arp_spoofing(wifi_info['interface'], timeout=3)
    dns_latency = measure_dns_latency()
    packet_loss = measure_packet_loss()
    tls_valid = check_tls_cert()
    
    return {
        **wifi_info,
        'captive_portal': has_captive_portal,
        'traffic_analysis': traffic_data,
        'arp_issues': arp_issues,
        'dns_latency_ms': dns_latency,
        'packet_loss_percent': packet_loss,
        'tls_cert_validity': tls_valid
    }

def calculate_risk_score(network_data: Dict) -> Dict:
    """
    Calculate risk score based on network properties
    Returns: {score: int, level: str, reasons: List[str], threats: List[Dict]}
    """
    score = 0
    reasons = []
    threats = []
    

    if network_data.get('dns_latency_ms', 0) > 200:
        score += 15
        reasons.append(f"High DNS latency ({network_data['dns_latency_ms']}ms)")
    
    if network_data.get('packet_loss_percent', 0) > 10:
        score += 20
        reasons.append(f"High packet loss ({network_data['packet_loss_percent']:.1f}%)")
        threats.append({
            'type': 'network_instability',
            'severity': 'MEDIUM',
            'description': 'High packet loss may indicate MITM or interference'
        })
    
    if network_data.get('tls_cert_validity') == 0:
        score += 30
        reasons.append("Invalid or missing TLS certificate")
        threats.append({
            'type': 'invalid_tls',
            'severity': 'HIGH',
            'description': 'HTTPS connection failed certificate validation'
        })
    # Check encryption
    encryption = network_data.get('encryption_type', '').lower()
    if 'open' in encryption or encryption == 'unknown':
        score += 40
        reasons.append("Unencrypted network (Open WiFi)")
        threats.append({
            'type': 'no_encryption',
            'severity': 'HIGH',
            'description': 'Network has no encryption - all traffic visible to others'
        })
    elif 'wep' in encryption:
        score += 30
        reasons.append("Weak encryption (WEP)")
        threats.append({
            'type': 'weak_encryption',
            'severity': 'MEDIUM',
            'description': 'WEP encryption is easily breakable'
        })
    
    # Check for captive portal
    if network_data.get('captive_portal'):
        score += 15
        reasons.append("Captive portal detected (possible MITM)")
    
    # Analyze traffic
    traffic = network_data.get('traffic_analysis', {})
    http_ratio = traffic.get('http_ratio', 0)
    https_ratio = traffic.get('https_ratio', 0)
    
    if http_ratio > 30:
        score += 20
        reasons.append(f"High unencrypted HTTP traffic ({http_ratio:.1f}%)")
        threats.append({
            'type': 'unencrypted_traffic',
            'severity': 'MEDIUM',
            'description': f'{http_ratio:.1f}% of traffic is unencrypted HTTP'
        })
    
    if https_ratio < 20 and traffic.get('packet_count', 0) > 10:
        score += 10
        reasons.append("Low HTTPS usage")
    
    # Check ARP spoofing
    arp_issues = network_data.get('arp_issues', [])
    if arp_issues:
        score += 35
        reasons.append(f"ARP spoofing detected ({len(arp_issues)} suspicious entries)")
        threats.append({
            'type': 'arp_spoofing',
            'severity': 'CRITICAL',
            'description': f'Active ARP spoofing attack detected'
        })
    
    # Check suspicious DNS
    suspicious_dns = traffic.get('suspicious_dns', [])
    if suspicious_dns:
        score += 25
        reasons.append("Suspicious DNS responses detected")
        threats.append({
            'type': 'dns_hijacking',
            'severity': 'HIGH',
            'description': 'DNS responses may be tampered with'
        })
    
    # Determine risk level
    if score >= 70:
        level = "HIGH"
    elif score >= 40:
        level = "MEDIUM"
    elif score >= 20:
        level = "LOW"
    else:
        level = "SAFE"
    
    return {
        'score': min(score, 100),
        'level': level,
        'reasons': reasons,
        'threats': threats
    }

# CLI testing
if __name__ == "__main__":
    print("Privacy Guard Network Scanner\n")
    
    # Scan current network
    network_data = scan_current_network()
    
    print(f"Network: {network_data.get('ssid', 'Unknown')}")
    print(f"BSSID: {network_data.get('bssid', 'Unknown')}")
    print(f"Encryption: {network_data.get('encryption_type', 'Unknown')}")
    print(f"Signal: {network_data.get('signal_strength', 0)} dBm")
    
    # Calculate risk
    risk = calculate_risk_score(network_data)
    
    print(f"\nRisk Score: {risk['score']}/100")
    print(f"Risk Level: {risk['level']}")
    print(f"\nReasons:")
    for reason in risk['reasons']:
        print(f"  - {reason}")
    
    print(f"\nThreats Detected: {len(risk['threats'])}")
    for threat in risk['threats']:
        print(f"  [{threat['severity']}] {threat['type']}: {threat['description']}")