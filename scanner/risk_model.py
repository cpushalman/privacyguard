"""
Privacy Guard Risk Assessment Model
Advanced risk scoring with machine learning-ready features
"""

from typing import Dict, List, Tuple
import json
from datetime import datetime

# Risk weight configurations
RISK_WEIGHTS = {
    'encryption': {
        'open': 40,
        'wep': 30,
        'wpa': 10,
        'wpa2': 5,
        'wpa3': 0
    },
    'captive_portal': 15,
    'arp_spoofing': 35,
    'dns_hijacking': 25,
    'http_traffic_high': 20,
    'https_traffic_low': 10,
    'weak_signal': 5,
    'suspicious_ssid': 15,
    'known_malicious': 50
}

# Patterns for suspicious SSIDs
SUSPICIOUS_SSID_PATTERNS = [
    'free', 'public', 'guest', 'open', 'hotspot',
    'airport', 'starbucks', 'mcdonalds', 'hotel',
    'wifi', 'internet', 'network'
]

# Known legitimate networks (whitelist - would be expanded)
TRUSTED_NETWORKS = [
    # Format: (SSID pattern, BSSID prefix, encryption_type)
    # Example: ('MyHome-5G', '00:11:22', 'WPA2')
]

class RiskAssessment:
    """Risk assessment engine for network security"""
    
    def __init__(self):
        self.weights = RISK_WEIGHTS
        self.history = []
    
    def assess_network(self, network_data: Dict) -> Dict:
        """
        Main risk assessment function
        
        Args:
            network_data: Dictionary containing network properties
        
        Returns:
            Risk assessment with score, level, reasons, and recommendations
        """
        score = 0
        reasons = []
        threats = []
        recommendations = []
        
        # 1. Encryption assessment
        enc_score, enc_reasons, enc_threats = self._assess_encryption(network_data)
        score += enc_score
        reasons.extend(enc_reasons)
        threats.extend(enc_threats)
        
        # 2. Network type assessment
        type_score, type_reasons = self._assess_network_type(network_data)
        score += type_score
        reasons.extend(type_reasons)
        
        # 3. Traffic analysis
        traffic_score, traffic_reasons, traffic_threats = self._assess_traffic(network_data)
        score += traffic_score
        reasons.extend(traffic_reasons)
        threats.extend(traffic_threats)
        
        # 4. Attack detection
        attack_score, attack_reasons, attack_threats = self._detect_attacks(network_data)
        score += attack_score
        reasons.extend(attack_reasons)
        threats.extend(attack_threats)
        
        # 5. SSID analysis
        ssid_score, ssid_reasons = self._analyze_ssid(network_data)
        score += ssid_score
        reasons.extend(ssid_reasons)
        
        # 6. Signal strength (weak signals can indicate spoofing)
        signal_score, signal_reasons = self._assess_signal(network_data)
        score += signal_score
        reasons.extend(signal_reasons)
        
        # Generate recommendations
        recommendations = self._generate_recommendations(score, threats)
        
        # Determine risk level
        level = self._calculate_risk_level(score)
        
        # Store in history
        assessment = {
            'score': min(score, 100),
            'level': level,
            'reasons': reasons,
            'threats': threats,
            'recommendations': recommendations,
            'timestamp': datetime.now().isoformat(),
            'network_ssid': network_data.get('ssid'),
            'network_bssid': network_data.get('bssid')
        }
        
        self.history.append(assessment)
        
        return assessment
    
    def _assess_encryption(self, data: Dict) -> Tuple[int, List[str], List[Dict]]:
        """Assess encryption security"""
        score = 0
        reasons = []
        threats = []
        
        encryption = data.get('encryption_type', '').lower()
        
        if 'open' in encryption or encryption == 'unknown':
            score = self.weights['encryption']['open']
            reasons.append("No encryption - all traffic is visible")
            threats.append({
                'type': 'no_encryption',
                'severity': 'HIGH',
                'description': 'Network lacks encryption. Anyone can intercept your data.',
                'cvss_score': 7.5
            })
        elif 'wep' in encryption:
            score = self.weights['encryption']['wep']
            reasons.append("Outdated WEP encryption (easily cracked)")
            threats.append({
                'type': 'weak_encryption',
                'severity': 'MEDIUM',
                'description': 'WEP can be cracked in minutes with readily available tools.',
                'cvss_score': 5.5
            })
        elif 'wpa3' in encryption:
            score = self.weights['encryption']['wpa3']
            reasons.append("Strong WPA3 encryption")
        elif 'wpa2' in encryption:
            score = self.weights['encryption']['wpa2']
        elif 'wpa' in encryption:
            score = self.weights['encryption']['wpa']
            reasons.append("WPA encryption (consider upgrading to WPA2/WPA3)")
        
        return score, reasons, threats
    
    def _assess_network_type(self, data: Dict) -> Tuple[int, List[str]]:
        """Assess network type (public, captive portal, etc.)"""
        score = 0
        reasons = []
        
        # Check for captive portal
        if data.get('captive_portal'):
            score += self.weights['captive_portal']
            reasons.append("Captive portal detected (potential MITM risk)")
        
        return score, reasons
    
    def _assess_traffic(self, data: Dict) -> Tuple[int, List[str], List[Dict]]:
        """Assess traffic patterns"""
        score = 0
        reasons = []
        threats = []
        
        traffic = data.get('traffic_analysis', {})
        http_ratio = traffic.get('http_ratio', 0)
        https_ratio = traffic.get('https_ratio', 0)
        packet_count = traffic.get('packet_count', 0)
        
        # Only assess if we have enough data
        if packet_count > 10:
            if http_ratio > 30:
                score += self.weights['http_traffic_high']
                reasons.append(f"High unencrypted traffic: {http_ratio:.1f}% HTTP")
                threats.append({
                    'type': 'unencrypted_traffic',
                    'severity': 'MEDIUM',
                    'description': f'{http_ratio:.1f}% of traffic is unencrypted and vulnerable to interception.',
                    'cvss_score': 4.5
                })
            
            if https_ratio < 20 and http_ratio > 10:
                score += self.weights['https_traffic_low']
                reasons.append("Low HTTPS usage compared to HTTP")
        
        return score, reasons, threats
    
    def _detect_attacks(self, data: Dict) -> Tuple[int, List[str], List[Dict]]:
        """Detect active attacks"""
        score = 0
        reasons = []
        threats = []
        
        # ARP spoofing
        arp_issues = data.get('arp_issues', [])
        if arp_issues:
            score += self.weights['arp_spoofing']
            reasons.append(f"ARP spoofing detected: {len(arp_issues)} suspicious entries")
            threats.append({
                'type': 'arp_spoofing',
                'severity': 'CRITICAL',
                'description': 'Active ARP spoofing attack. Attacker may be intercepting traffic.',
                'cvss_score': 8.5,
                'details': arp_issues
            })
        
        # DNS hijacking
        traffic = data.get('traffic_analysis', {})
        suspicious_dns = traffic.get('suspicious_dns', [])
        if suspicious_dns:
            score += self.weights['dns_hijacking']
            reasons.append("DNS hijacking detected")
            threats.append({
                'type': 'dns_hijacking',
                'severity': 'HIGH',
                'description': 'Suspicious DNS responses. Your DNS queries may be redirected.',
                'cvss_score': 7.0,
                'details': suspicious_dns
            })
        
        return score, reasons, threats
    
    def _analyze_ssid(self, data: Dict) -> Tuple[int, List[str]]:
        """Analyze SSID for suspicious patterns"""
        score = 0
        reasons = []
        
        ssid = data.get('ssid', '').lower()
        
        # Check for suspicious patterns
        for pattern in SUSPICIOUS_SSID_PATTERNS:
            if pattern in ssid:
                score += self.weights['suspicious_ssid']
                reasons.append(f"Suspicious SSID pattern: '{pattern}' (common in evil twin attacks)")
                break  # Only count once
        
        # Check for hidden SSID
        if not ssid or ssid == 'unknown':
            score += 5
            reasons.append("Hidden SSID (slightly suspicious)")
        
        return score, reasons
    
    def _assess_signal(self, data: Dict) -> Tuple[int, List[str]]:
        """Assess signal strength"""
        score = 0
        reasons = []
        
        signal = data.get('signal_strength', 0)
        
        # Very weak signal can indicate a distant attacker
        if signal < -80:
            score += self.weights['weak_signal']
            reasons.append("Very weak signal (potential spoofed AP)")
        
        return score, reasons
    
    def _calculate_risk_level(self, score: int) -> str:
        """Calculate risk level from score"""
        if score >= 70:
            return "CRITICAL"
        elif score >= 50:
            return "HIGH"
        elif score >= 30:
            return "MEDIUM"
        elif score >= 15:
            return "LOW"
        else:
            return "SAFE"
    
    def _generate_recommendations(self, score: int, threats: List[Dict]) -> List[str]:
        """Generate actionable recommendations"""
        recommendations = []
        
        threat_types = {t['type'] for t in threats}
        
        if 'no_encryption' in threat_types or 'weak_encryption' in threat_types:
            recommendations.append("Enable VPN immediately to encrypt all traffic")
            recommendations.append("Avoid accessing sensitive accounts on this network")
        
        if 'arp_spoofing' in threat_types:
            recommendations.append("Disconnect from this network immediately")
            recommendations.append("Use VPN or mobile hotspot instead")
            recommendations.append("Report this network to IT/security")
        
        if 'dns_hijacking' in threat_types:
            recommendations.append("Use encrypted DNS (DNS-over-HTTPS or DNS-over-TLS)")
            recommendations.append("Verify website certificates before entering credentials")
        
        if 'unencrypted_traffic' in threat_types:
            recommendations.append("Use HTTPS Everywhere browser extension")
            recommendations.append("Enable 'Force HTTPS' in browser settings")
        
        if score >= 50:
            recommendations.append("Consider using cellular data instead")
            recommendations.append("Enable kill switch on VPN to prevent data leaks")
        
        if score < 30:
            recommendations.append("Network appears safe, but always use HTTPS")
        
        return recommendations
    
    def get_threat_summary(self) -> Dict:
        """Get summary of threats across all assessments"""
        if not self.history:
            return {'total_assessments': 0, 'threat_distribution': {}}
        
        threat_counts = {}
        severity_counts = {'CRITICAL': 0, 'HIGH': 0, 'MEDIUM': 0, 'LOW': 0}
        
        for assessment in self.history:
            for threat in assessment['threats']:
                threat_type = threat['type']
                threat_counts[threat_type] = threat_counts.get(threat_type, 0) + 1
                severity_counts[threat['severity']] += 1
        
        return {
            'total_assessments': len(self.history),
            'threat_distribution': threat_counts,
            'severity_distribution': severity_counts,
            'average_risk_score': sum(a['score'] for a in self.history) / len(self.history)
        }
    
    def export_assessment(self, assessment: Dict, format: str = 'json') -> str:
        """Export assessment in various formats"""
        if format == 'json':
            return json.dumps(assessment, indent=2)
        elif format == 'text':
            lines = [
                f"Risk Assessment Report",
                f"=" * 50,
                f"Network: {assessment['network_ssid']}",
                f"BSSID: {assessment['network_bssid']}",
                f"Time: {assessment['timestamp']}",
                f"",
                f"Risk Score: {assessment['score']}/100",
                f"Risk Level: {assessment['level']}",
                f"",
                f"Threats Detected: {len(assessment['threats'])}",
            ]
            
            for threat in assessment['threats']:
                lines.append(f"  [{threat['severity']}] {threat['type']}")
                lines.append(f"    {threat['description']}")
            
            lines.append("")
            lines.append("Recommendations:")
            for rec in assessment['recommendations']:
                lines.append(f"  • {rec}")
            
            return "\n".join(lines)
        
        return str(assessment)

# Example usage
if __name__ == "__main__":
    # Test risk assessment
    assessor = RiskAssessment()
    
    # Sample network data
    test_network = {
        'ssid': 'Free Public WiFi',
        'bssid': '00:11:22:33:44:55',
        'encryption_type': 'Open',
        'signal_strength': -45,
        'captive_portal': True,
        'traffic_analysis': {
            'http_ratio': 45.5,
            'https_ratio': 15.2,
            'packet_count': 150,
            'suspicious_dns': [
                {'domain': 'google.com', 'ip': '192.168.1.100'}
            ]
        },
        'arp_issues': [
            {'ip': '192.168.1.1', 'mac_1': 'aa:bb:cc', 'mac_2': 'dd:ee:ff'}
        ]
    }
    
    assessment = assessor.assess_network(test_network)
    
    print(assessor.export_assessment(assessment, format='text'))
    print("\n" + "=" * 50)
    print("\nThreat Summary:")
    print(json.dumps(assessor.get_threat_summary(), indent=2))