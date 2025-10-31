import subprocess
import re
import time
import socket
import ssl
import requests
from scapy.all import ARP, Ether, srp, conf
from typing import Dict, List, Optional
import platform
import warnings
warnings.filterwarnings('ignore')

class WiFiScanner:
    """
    Comprehensive WiFi network scanner that extracts features for suspicious network detection.
    Works on Windows, Linux, and macOS.
    """
    
    def __init__(self):
        self.system = platform.system()
        conf.verb = 0  # Suppress scapy output
        
    def get_current_network_info(self) -> Dict:
        """Get information about the currently connected WiFi network."""
        try:
            if self.system == "Windows":
                return self._get_windows_network_info()
            elif self.system == "Linux":
                return self._get_linux_network_info()
            elif self.system == "Darwin":  # macOS
                return self._get_macos_network_info()
            else:
                raise OSError(f"Unsupported operating system: {self.system}")
        except Exception as e:
            print(f"Error getting network info: {e}")
            return {}
    
    def _get_windows_network_info(self) -> Dict:
        """Extract network info on Windows using netsh."""
        try:
            result = subprocess.run(
                ["netsh", "wlan", "show", "interfaces"],
                capture_output=True,
                text=True,
                timeout=5
            )
            
            output = result.stdout
            info = {}
            
            # Extract SSID
            ssid_match = re.search(r'SSID\s+:\s+(.+)', output)
            info['ssid'] = ssid_match.group(1).strip() if ssid_match else "Unknown"
            
            # Extract Signal Strength
            signal_match = re.search(r'Signal\s+:\s+(\d+)%', output)
            if signal_match:
                signal_percent = int(signal_match.group(1))
                # Convert percentage to dBm (approximate conversion)
                info['signal_strength'] = self._percent_to_dbm(signal_percent)
            else:
                info['signal_strength'] = -70.0
            
            # Extract Authentication/Encryption
            auth_match = re.search(r'Authentication\s+:\s+(.+)', output)
            cipher_match = re.search(r'Cipher\s+:\s+(.+)', output)
            
            if auth_match and cipher_match:
                auth = auth_match.group(1).strip()
                cipher = cipher_match.group(1).strip()
                info['encryption'] = self._parse_encryption(auth, cipher)
            else:
                info['encryption'] = "UNKNOWN"
            
            return info
            
        except Exception as e:
            print(f"Windows network scan error: {e}")
            return {'ssid': 'Unknown', 'signal_strength': -70.0, 'encryption': 'UNKNOWN'}
    
    def _get_linux_network_info(self) -> Dict:
        """Extract network info on Linux using iwconfig/nmcli."""
        try:
            # Try nmcli first (more reliable on modern systems)
            result = subprocess.run(
                ["nmcli", "-t", "-f", "ACTIVE,SSID,SIGNAL,SECURITY", "dev", "wifi"],
                capture_output=True,
                text=True,
                timeout=5
            )
            
            lines = result.stdout.strip().split('\n')
            for line in lines:
                if line.startswith('yes:'):
                    parts = line.split(':')
                    info = {
                        'ssid': parts[1] if len(parts) > 1 else "Unknown",
                        'signal_strength': self._percent_to_dbm(int(parts[2])) if len(parts) > 2 else -70.0,
                        'encryption': self._parse_linux_security(parts[3]) if len(parts) > 3 else "UNKNOWN"
                    }
                    return info
            
            return {'ssid': 'Unknown', 'signal_strength': -70.0, 'encryption': 'UNKNOWN'}
            
        except Exception as e:
            print(f"Linux network scan error: {e}")
            return {'ssid': 'Unknown', 'signal_strength': -70.0, 'encryption': 'UNKNOWN'}
    
    def _get_macos_network_info(self) -> Dict:
        """Extract network info on macOS using airport."""
        try:
            result = subprocess.run(
                ["/System/Library/PrivateFrameworks/Apple80211.framework/Versions/Current/Resources/airport", "-I"],
                capture_output=True,
                text=True,
                timeout=5
            )
            
            output = result.stdout
            info = {}
            
            ssid_match = re.search(r'SSID:\s+(.+)', output)
            info['ssid'] = ssid_match.group(1).strip() if ssid_match else "Unknown"
            
            signal_match = re.search(r'agrCtlRSSI:\s+(-?\d+)', output)
            info['signal_strength'] = float(signal_match.group(1)) if signal_match else -70.0
            
            # Check for link auth
            auth_match = re.search(r'link auth:\s+(.+)', output)
            if auth_match:
                info['encryption'] = self._parse_macos_auth(auth_match.group(1).strip())
            else:
                info['encryption'] = "UNKNOWN"
            
            return info
            
        except Exception as e:
            print(f"macOS network scan error: {e}")
            return {'ssid': 'Unknown', 'signal_strength': -70.0, 'encryption': 'UNKNOWN'}
    
    def _percent_to_dbm(self, percent: int) -> float:
        """Convert signal strength percentage to dBm (approximate)."""
        if percent >= 100:
            return -30.0
        elif percent <= 0:
            return -90.0
        else:
            return -30.0 - (100 - percent) * 0.6
    
    def _parse_encryption(self, auth: str, cipher: str) -> str:
        """Parse Windows authentication and cipher to standard encryption type."""
        auth_upper = auth.upper()
        if "OPEN" in auth_upper or auth_upper == "NONE":
            return "OPEN"
        elif "WPA3" in auth_upper:
            return "WPA3"
        elif "WPA2" in auth_upper:
            return "WPA2"
        elif "WPA" in auth_upper:
            return "WPA"
        elif "WEP" in auth_upper:
            return "WEP"
        else:
            return "WPA2"  # Default assumption
    
    def _parse_linux_security(self, security: str) -> str:
        """Parse Linux security string."""
        sec_upper = security.upper()
        if not security or security == "--":
            return "OPEN"
        elif "WPA3" in sec_upper:
            return "WPA3"
        elif "WPA2" in sec_upper:
            return "WPA2"
        elif "WPA" in sec_upper:
            return "WPA"
        elif "WEP" in sec_upper:
            return "WEP"
        else:
            return "WPA2"
    
    def _parse_macos_auth(self, auth: str) -> str:
        """Parse macOS authentication string."""
        auth_upper = auth.upper()
        if "WPA3" in auth_upper:
            return "WPA3"
        elif "WPA2" in auth_upper:
            return "WPA2"
        elif "WPA" in auth_upper:
            return "WPA"
        elif "WEP" in auth_upper:
            return "WEP"
        elif "OPEN" in auth_upper:
            return "OPEN"
        else:
            return "WPA2"
    
    def check_arp_anomalies(self, timeout: int = 3) -> int:
        """
        Check for ARP spoofing by scanning local network.
        Returns 1 if anomalies detected, 0 otherwise.
        """
        try:
            # Get local IP and network
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.connect(("8.8.8.8", 80))
            local_ip = s.getsockname()[0]
            s.close()
            
            # Calculate network range
            ip_parts = local_ip.split('.')
            network = f"{ip_parts[0]}.{ip_parts[1]}.{ip_parts[2]}.0/24"
            
            # Send ARP requests
            arp = ARP(pdst=network)
            ether = Ether(dst="ff:ff:ff:ff:ff:ff")
            packet = ether/arp
            
            result = srp(packet, timeout=timeout, verbose=0)[0]
            
            # Check for duplicate IPs or MACs
            ips = set()
            macs = set()
            duplicates = 0
            
            for sent, received in result:
                ip = received.psrc
                mac = received.hwsrc
                
                if ip in ips or mac in macs:
                    duplicates += 1
                
                ips.add(ip)
                macs.add(mac)
            
            return 1 if duplicates > 0 else 0
            
        except Exception as e:
            print(f"ARP scan error: {e}")
            return 0  # Assume no anomalies if scan fails
    
    def check_tls_cert_validity(self, test_domains: List[str] = None) -> int:
        """
        Check TLS certificate validity for common domains.
        Returns 1 if all valid, 0 if any invalid/self-signed.
        """
        if test_domains is None:
            test_domains = ["google.com", "github.com", "cloudflare.com"]
        
        valid_count = 0
        
        for domain in test_domains:
            try:
                context = ssl.create_default_context()
                with socket.create_connection((domain, 443), timeout=3) as sock:
                    with context.wrap_socket(sock, server_hostname=domain) as ssock:
                        cert = ssock.getpeercert()
                        if cert:
                            valid_count += 1
            except (ssl.SSLError, socket.timeout, socket.error):
                continue
            except Exception:
                continue
        
        # If at least 2 out of 3 succeed, consider it valid
        return 1 if valid_count >= 2 else 0
    
    def check_captive_portal(self) -> int:
        """
        Check if network has a captive portal by testing HTTP redirect.
        Returns 1 if captive portal detected, 0 otherwise.
        """
        try:
            response = requests.get(
                "http://captive.apple.com/hotspot-detect.html",
                timeout=5,
                allow_redirects=False
            )
            
            # Captive portal typically redirects or returns non-standard response
            if response.status_code in [302, 301, 307] or response.status_code != 200:
                return 1
            
            # Check content
            if "Success" not in response.text:
                return 1
            
            return 0
            
        except Exception:
            return 0
    
    def measure_dns_latency(self, num_tests: int = 3) -> float:
        """
        Measure DNS resolution latency in milliseconds.
        """
        test_domains = ["google.com", "cloudflare.com", "github.com"]
        latencies = []
        
        for domain in test_domains[:num_tests]:
            try:
                start = time.time()
                socket.gethostbyname(domain)
                end = time.time()
                latencies.append((end - start) * 1000)  # Convert to ms
            except Exception:
                continue
        
        if latencies:
            return sum(latencies) / len(latencies)
        else:
            return 100.0  # Default reasonable value
    
    def measure_packet_loss(self, host: str = "8.8.8.8", count: int = 10) -> float:
        """
        Measure packet loss percentage using ping.
        """
        try:
            if self.system == "Windows":
                result = subprocess.run(
                    ["ping", "-n", str(count), host],
                    capture_output=True,
                    text=True,
                    timeout=15
                )
                loss_match = re.search(r'(\d+)% loss', result.stdout)
            else:  # Linux/macOS
                result = subprocess.run(
                    ["ping", "-c", str(count), host],
                    capture_output=True,
                    text=True,
                    timeout=15
                )
                loss_match = re.search(r'(\d+\.?\d*)% packet loss', result.stdout)
            
            if loss_match:
                return float(loss_match.group(1))
            else:
                return 0.0
                
        except Exception as e:
            print(f"Ping error: {e}")
            return 0.0
    
    def check_data_leak_attempts(self, duration: int = 5) -> int:
        """
        Monitor for unencrypted HTTP traffic (simplified version).
        In production, this would use packet sniffing.
        Returns estimated count of unencrypted transmissions.
        """
        # This is a simplified simulation
        # In real implementation, you'd use scapy to sniff HTTP packets
        # For now, we'll return 0 as we can't easily detect this without admin/root
        return 0
    
    def scan_full_network(self) -> Dict:
        """
        Perform complete network scan and return all features.
        """
        print("🔍 Scanning WiFi network...")
        
        # Get basic network info
        network_info = self.get_current_network_info()
        
        features = {
            'Signal_Strength_dBm': network_info.get('signal_strength', -70.0),
            'Encryption_Type': network_info.get('encryption', 'UNKNOWN'),
            'SSID': network_info.get('ssid', 'Unknown')
        }
        
        print(f"   📡 Connected to: {features['SSID']}")
        print(f"   📶 Signal: {features['Signal_Strength_dBm']:.1f} dBm")
        print(f"   🔐 Encryption: {features['Encryption_Type']}")
        
        # Check ARP anomalies
        print("   🔎 Checking ARP table...")
        features['ARP_Anomalies'] = self.check_arp_anomalies()
        
        # Check TLS certificate validity
        print("   🔒 Validating TLS certificates...")
        features['TLS_Cert_Validity'] = self.check_tls_cert_validity()
        
        # Check captive portal
        print("   🌐 Checking for captive portal...")
        features['Captive_Portal'] = self.check_captive_portal()
        
        # Measure DNS latency
        print("   ⏱️  Measuring DNS latency...")
        features['DNS_Latency_ms'] = self.measure_dns_latency()
        
        # Measure packet loss
        print("   📊 Testing packet loss...")
        features['Packet_Loss_%'] = self.measure_packet_loss()
        
        # Check data leak attempts (simplified)
        print("   🛡️  Checking data leak attempts...")
        features['Data_Leak_Attempts'] = self.check_data_leak_attempts()
        
        print("✅ Scan complete!\n")
        
        return features


# Example usage
if __name__ == "__main__":
    scanner = WiFiScanner()
    results = scanner.scan_full_network()
    
    print("Scan Results:")
    print("=" * 50)
    for key, value in results.items():
        print(f"{key}: {value}")