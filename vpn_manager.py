"""
Privacy Guard VPN Manager
Manages WireGuard, OpenVPN, and SOCKS5 proxy connections
"""

import subprocess
import os
import platform
import time
from typing import Dict, Optional, List
import configparser
import tempfile

class VPNManager:
    """Manages VPN connections and protection modes"""
    
    def __init__(self):
        self.system = platform.system()
        self.active_connection = None
        self.connection_type = None
        self.status = "disconnected"
    
    def detect_available_methods(self) -> List[str]:
        """Detect which VPN methods are available on the system"""
        available = []
        
        # Check for WireGuard
        if self._check_wireguard():
            available.append('wireguard')
        
        # Check for OpenVPN
        if self._check_openvpn():
            available.append('openvpn')
        
        # SOCKS5 proxy via SSH always available if SSH is present
        if self._check_ssh():
            available.append('ssh_proxy')
        
        # Fallback: HTTP/HTTPS proxy
        available.append('http_proxy')
        
        return available
    
    def _check_wireguard(self) -> bool:
        """Check if WireGuard is installed"""
        try:
            if self.system == "Windows":
                result = subprocess.run(['where', 'wg'], capture_output=True)
            else:
                result = subprocess.run(['which', 'wg'], capture_output=True)
            return result.returncode == 0
        except:
            return False
    
    def _check_openvpn(self) -> bool:
        """Check if OpenVPN is installed"""
        try:
            if self.system == "Windows":
                result = subprocess.run(['where', 'openvpn'], capture_output=True)
            else:
                result = subprocess.run(['which', 'openvpn'], capture_output=True)
            return result.returncode == 0
        except:
            return False
    
    def _check_ssh(self) -> bool:
        """Check if SSH is available"""
        try:
            if self.system == "Windows":
                result = subprocess.run(['where', 'ssh'], capture_output=True)
            else:
                result = subprocess.run(['which', 'ssh'], capture_output=True)
            return result.returncode == 0
        except:
            return False
    
    def connect_wireguard(self, config_path: str = None, config_data: Dict = None) -> Dict:
        """
        Connect to WireGuard VPN
        
        Args:
            config_path: Path to wg0.conf file
            config_data: Dictionary with WireGuard config
        
        Returns:
            Status dictionary
        """
        try:
            if config_data:
                # Create temporary config file
                config_path = self._create_wg_config(config_data)
            
            if not config_path or not os.path.exists(config_path):
                return {
                    'success': False,
                    'error': 'No valid WireGuard configuration found'
                }
            
            # Bring up WireGuard interface
            if self.system == "Windows":
                # Windows uses wireguard.exe
                cmd = ['wireguard.exe', '/installtunnelservice', config_path]
            else:
                # Linux/macOS use wg-quick
                cmd = ['sudo', 'wg-quick', 'up', config_path]
            
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=10)
            
            if result.returncode == 0:
                self.active_connection = config_path
                self.connection_type = 'wireguard'
                self.status = 'connected'
                
                return {
                    'success': True,
                    'method': 'wireguard',
                    'message': 'WireGuard VPN connected successfully',
                    'interface': 'wg0'
                }
            else:
                return {
                    'success': False,
                    'error': result.stderr or 'WireGuard connection failed'
                }
        
        except subprocess.TimeoutExpired:
            return {'success': False, 'error': 'Connection timeout'}
        except Exception as e:
            return {'success': False, 'error': str(e)}
    
    def disconnect_wireguard(self) -> Dict:
        """Disconnect WireGuard VPN"""
        try:
            if self.system == "Windows":
                cmd = ['wireguard.exe', '/uninstalltunnelservice', 'wg0']
            else:
                cmd = ['sudo', 'wg-quick', 'down', 'wg0']
            
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=10)
            
            self.active_connection = None
            self.connection_type = None
            self.status = 'disconnected'
            
            return {
                'success': True,
                'message': 'WireGuard VPN disconnected'
            }
        except Exception as e:
            return {'success': False, 'error': str(e)}
    
    def connect_openvpn(self, config_path: str) -> Dict:
        """Connect to OpenVPN"""
        try:
            if not os.path.exists(config_path):
                return {'success': False, 'error': 'OpenVPN config not found'}
            
            # Start OpenVPN in background
            if self.system == "Windows":
                cmd = ['openvpn-gui', '--connect', config_path]
            else:
                cmd = ['sudo', 'openvpn', '--config', config_path, '--daemon']
            
            result = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            
            # Wait a bit and check if process is still running
            time.sleep(2)
            if result.poll() is None or result.returncode == 0:
                self.active_connection = config_path
                self.connection_type = 'openvpn'
                self.status = 'connected'
                
                return {
                    'success': True,
                    'method': 'openvpn',
                    'message': 'OpenVPN connected successfully',
                    'pid': result.pid
                }
            else:
                return {'success': False, 'error': 'OpenVPN failed to start'}
        
        except Exception as e:
            return {'success': False, 'error': str(e)}
    
    def disconnect_openvpn(self) -> Dict:
        """Disconnect OpenVPN"""
        try:
            if self.system == "Windows":
                subprocess.run(['taskkill', '/F', '/IM', 'openvpn.exe'], capture_output=True)
            else:
                subprocess.run(['sudo', 'killall', 'openvpn'], capture_output=True)
            
            self.active_connection = None
            self.connection_type = None
            self.status = 'disconnected'
            
            return {'success': True, 'message': 'OpenVPN disconnected'}
        except Exception as e:
            return {'success': False, 'error': str(e)}
    
    def connect_ssh_proxy(self, host: str, port: int = 22, 
                         username: str = None, key_path: str = None,
                         local_port: int = 1080) -> Dict:
        """
        Create SOCKS5 proxy via SSH tunnel
        
        Args:
            host: Remote SSH server
            port: SSH port (default 22)
            username: SSH username
            key_path: Path to SSH private key
            local_port: Local SOCKS5 port (default 1080)
        """
        try:
            cmd = ['ssh', '-D', str(local_port), '-N', '-f']
            
            if key_path:
                cmd.extend(['-i', key_path])
            
            if username:
                cmd.append(f'{username}@{host}')
            else:
                cmd.append(host)
            
            if port != 22:
                cmd.extend(['-p', str(port)])
            
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=10)
            
            if result.returncode == 0:
                self.active_connection = f'socks5://localhost:{local_port}'
                self.connection_type = 'ssh_proxy'
                self.status = 'connected'
                
                # Configure system to use SOCKS5 proxy
                self._set_system_proxy(f'socks5://localhost:{local_port}')
                
                return {
                    'success': True,
                    'method': 'ssh_proxy',
                    'message': f'SOCKS5 proxy active on localhost:{local_port}',
                    'proxy_url': f'socks5://localhost:{local_port}'
                }
            else:
                return {'success': False, 'error': result.stderr}
        
        except Exception as e:
            return {'success': False, 'error': str(e)}
    
    def disconnect_ssh_proxy(self) -> Dict:
        """Disconnect SSH proxy"""
        try:
            # Kill SSH tunnel process
            if self.system == "Windows":
                subprocess.run(['taskkill', '/F', '/IM', 'ssh.exe'], capture_output=True)
            else:
                # Find and kill SSH process with -D flag
                result = subprocess.run(['pgrep', '-f', 'ssh -D'], capture_output=True, text=True)
                if result.stdout:
                    pids = result.stdout.strip().split('\n')
                    for pid in pids:
                        subprocess.run(['kill', pid])
            
            # Clear system proxy settings
            self._clear_system_proxy()
            
            self.active_connection = None
            self.connection_type = None
            self.status = 'disconnected'
            
            return {'success': True, 'message': 'SSH proxy disconnected'}
        except Exception as e:
            return {'success': False, 'error': str(e)}
    
    def connect_http_proxy(self, proxy_url: str) -> Dict:
        """
        Configure HTTP/HTTPS proxy
        
        Args:
            proxy_url: Proxy URL (e.g., http://proxy.example.com:8080)
        """
        try:
            self._set_system_proxy(proxy_url)
            
            self.active_connection = proxy_url
            self.connection_type = 'http_proxy'
            self.status = 'connected'
            
            return {
                'success': True,
                'method': 'http_proxy',
                'message': f'HTTP proxy configured: {proxy_url}'
            }
        except Exception as e:
            return {'success': False, 'error': str(e)}
    
    def disconnect_http_proxy(self) -> Dict:
        """Disconnect HTTP proxy"""
        try:
            self._clear_system_proxy()
            
            self.active_connection = None
            self.connection_type = None
            self.status = 'disconnected'
            
            return {'success': True, 'message': 'HTTP proxy disabled'}
        except Exception as e:
            return {'success': False, 'error': str(e)}
    
    def _set_system_proxy(self, proxy_url: str):
        """Set system-wide proxy settings"""
        if self.system == "Windows":
            # Windows registry settings
            subprocess.run([
                'reg', 'add',
                'HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Internet Settings',
                '/v', 'ProxyEnable', '/t', 'REG_DWORD', '/d', '1', '/f'
            ])
            subprocess.run([
                'reg', 'add',
                'HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Internet Settings',
                '/v', 'ProxyServer', '/t', 'REG_SZ', '/d', proxy_url, '/f'
            ])
        
        elif self.system == "Darwin":  # macOS
            # Use networksetup
            subprocess.run([
                'networksetup', '-setwebproxy', 'Wi-Fi',
                proxy_url.split('://')[1].split(':')[0],
                proxy_url.split(':')[-1]
            ])
        
        elif self.system == "Linux":
            # Set environment variables
            os.environ['http_proxy'] = proxy_url
            os.environ['https_proxy'] = proxy_url
            os.environ['all_proxy'] = proxy_url
    
    def _clear_system_proxy(self):
        """Clear system-wide proxy settings"""
        if self.system == "Windows":
            subprocess.run([
                'reg', 'add',
                'HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Internet Settings',
                '/v', 'ProxyEnable', '/t', 'REG_DWORD', '/d', '0', '/f'
            ])
        
        elif self.system == "Darwin":
            subprocess.run(['networksetup', '-setwebproxystate', 'Wi-Fi', 'off'])
        
        elif self.system == "Linux":
            os.environ.pop('http_proxy', None)
            os.environ.pop('https_proxy', None)
            os.environ.pop('all_proxy', None)
    
    def _create_wg_config(self, config_data: Dict) -> str:
        """Create WireGuard config file from dictionary"""
        config_content = f"""[Interface]
PrivateKey = {config_data.get('private_key', '')}
Address = {config_data.get('address', '10.0.0.2/24')}
DNS = {config_data.get('dns', '1.1.1.1')}

[Peer]
PublicKey = {config_data.get('peer_public_key', '')}
Endpoint = {config_data.get('endpoint', '')}
AllowedIPs = {config_data.get('allowed_ips', '0.0.0.0/0')}
PersistentKeepalive = 25
"""
        
        # Write to temporary file
        temp_file = tempfile.NamedTemporaryFile(mode='w', suffix='.conf', delete=False)
        temp_file.write(config_content)
        temp_file.close()
        
        return temp_file.name
    
    def get_status(self) -> Dict:
        """Get current VPN status"""
        return {
            'status': self.status,
            'connection_type': self.connection_type,
            'connection_info': self.active_connection,
            'available_methods': self.detect_available_methods()
        }
    
    def auto_protect(self, risk_level: str) -> Dict:
        """
        Automatically choose and enable best protection method
        based on risk level
        """
        available = self.detect_available_methods()
        
        if not available:
            return {
                'success': False,
                'error': 'No protection methods available'
            }
        
        # Priority: WireGuard > OpenVPN > SSH Proxy > HTTP Proxy
        if 'wireguard' in available and risk_level in ['HIGH', 'CRITICAL']:
            # For demo, use example config
            return self.connect_wireguard(config_data={
                'private_key': 'DEMO_KEY',
                'peer_public_key': 'DEMO_PEER_KEY',
                'endpoint': 'vpn.example.com:51820',
                'address': '10.0.0.2/24'
            })
        
        elif 'ssh_proxy' in available:
            # For demo purposes
            return {
                'success': True,
                'method': 'ssh_proxy',
                'message': 'Would connect SSH proxy (demo mode)',
                'note': 'Configure with actual SSH server in production'
            }
        
        elif 'http_proxy' in available:
            return {
                'success': True,
                'method': 'http_proxy',
                'message': 'HTTP proxy mode (configure proxy server)',
                'note': 'Set proxy URL in production'
            }
        
        return {'success': False, 'error': 'No suitable method found'}
    
    def disconnect(self) -> Dict:
        """Disconnect current VPN/proxy"""
        if self.connection_type == 'wireguard':
            return self.disconnect_wireguard()
        elif self.connection_type == 'openvpn':
            return self.disconnect_openvpn()
        elif self.connection_type == 'ssh_proxy':
            return self.disconnect_ssh_proxy()
        elif self.connection_type == 'http_proxy':
            return self.disconnect_http_proxy()
        
        return {'success': True, 'message': 'No active connection'}

# CLI testing
if __name__ == "__main__":
    manager = VPNManager()
    
    print("Privacy Guard VPN Manager\n")
    print(f"System: {manager.system}")
    print(f"Available methods: {', '.join(manager.detect_available_methods())}")
    print(f"\nCurrent status: {manager.get_status()}")