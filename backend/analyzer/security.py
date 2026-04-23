"""
Security Analysis Module - Threats, vulnerabilities, anomalies
"""
import logging
from collections import Counter, defaultdict
from typing import Dict, List, Optional, Tuple

try:
    from scapy.all import IP, TCP, UDP, DNS, ICMP, ARP
    SCAPY_AVAILABLE = True
except ImportError:
    SCAPY_AVAILABLE = False

logger = logging.getLogger('SecurityAnalyzer')


class SecurityAnalyzer:
    """Analyze packets for security threats and vulnerabilities"""
    
    def __init__(self, packets, config: Optional[Dict] = None):
        self.packets = packets
        self.config = config or self._default_config()
        self.alerts = []
        self.vulnerabilities = {}
        self.threat_score = 0.0
        
    def _default_config(self) -> Dict:
        """Default security configuration"""
        return {
            'alert_ports': [22, 23, 3389, 5900, 139, 445],
            'anomaly_threshold': -0.5,
            'enable_advanced_checks': True
        }
    
    def analyze_all(self) -> Dict:
        """Run all security checks and return results"""
        return {
            'port_scan_detection': self.detect_port_scans(),
            'ddos_detection': self.detect_ddos(),
            'spoofing_detection': self.detect_spoofing(),
            'arp_poisoning': self.detect_arp_poisoning(),
            'dns_tunneling': self.detect_dns_tunneling(),
            'vulnerable_ports': self.check_vulnerable_ports(),
            'alerts': self.alerts,
            'threat_score': self.calculate_threat_score()
        }
    
    def detect_port_scans(self) -> Dict:
        """Detect port scanning activity (SYN flood, sequential probes)"""
        if not SCAPY_AVAILABLE:
            return {}
        
        syn_packets = []
        port_sequences = defaultdict(list)
        
        for pkt in self.packets:
            if TCP in pkt:
                if pkt[TCP].flags & 0x02:  # SYN flag
                    syn_packets.append(pkt)
                    dst_ip = pkt[IP].dst
                    port_sequences[dst_ip].append(pkt[TCP].dport)
        
        suspicious_sources = []
        for src_ip, ports in port_sequences.items():
            if len(set(ports)) > 10:  # Many different destination ports
                suspicious_sources.append({
                    'source': src_ip,
                    'port_count': len(set(ports)),
                    'severity': 'high' if len(set(ports)) > 20 else 'medium'
                })
                self.alerts.append({
                    'type': 'port_scan',
                    'source': src_ip,
                    'description': f'Possible port scan detected: {len(set(ports))} unique ports',
                    'severity': 'high' if len(set(ports)) > 20 else 'medium'
                })
        
        return {
            'syn_packet_count': len(syn_packets),
            'suspicious_sources': suspicious_sources,
            'risk_level': 'high' if len(suspicious_sources) > 3 else 'low'
        }
    
    def detect_ddos(self) -> Dict:
        """Detect DDoS attack patterns"""
        if not SCAPY_AVAILABLE:
            return {}
        
        packet_rate_per_source = Counter()
        packet_rate_per_dest = Counter()
        
        for pkt in self.packets:
            if IP in pkt:
                packet_rate_per_source[pkt[IP].src] += 1
                packet_rate_per_dest[pkt[IP].dst] += 1
        
        # Detect traffic anomalies
        suspicious_sources = []
        for src, count in packet_rate_per_source.most_common(5):
            if count > len(self.packets) * 0.2:  # Source sends >20% of packets
                suspicious_sources.append({
                    'source': src,
                    'packet_count': count,
                    'percentage': round(count / len(self.packets) * 100, 2)
                })
                self.alerts.append({
                    'type': 'possible_ddos',
                    'source': src,
                    'description': f'High volume from source: {count} packets',
                    'severity': 'high'
                })
        
        return {
            'high_volume_sources': suspicious_sources,
            'risk_level': 'high' if suspicious_sources else 'low'
        }
    
    def detect_spoofing(self) -> Dict:
        """Detect IP spoofing attempts"""
        if not SCAPY_AVAILABLE:
            return {}
        
        ttl_anomalies = defaultdict(list)
        spoofing_indicators = []
        
        for pkt in self.packets:
            if IP in pkt:
                src = pkt[IP].src
                ttl = pkt[IP].ttl
                ttl_anomalies[src].append(ttl)
        
        # Check for inconsistent TTL from same source
        for src, ttls in ttl_anomalies.items():
            unique_ttls = set(ttls)
            if len(unique_ttls) > 3:  # Suspicious: multiple different TTLs
                spoofing_indicators.append({
                    'source': src,
                    'ttl_values': list(unique_ttls),
                    'inconsistency': len(unique_ttls)
                })
                self.alerts.append({
                    'type': 'ttl_anomaly',
                    'source': src,
                    'description': f'Inconsistent TTL values detected: {unique_ttls}',
                    'severity': 'medium'
                })
        
        return {
            'spoofing_indicators': spoofing_indicators,
            'risk_level': 'high' if len(spoofing_indicators) > 2 else 'low'
        }
    
    def detect_arp_poisoning(self) -> Dict:
        """Detect ARP poisoning attempts (MITM attacks)"""
        if not SCAPY_AVAILABLE:
            return {}
        
        arp_packets = [p for p in self.packets if ARP in p]
        suspicious_arp = []
        
        # Look for unusual ARP patterns
        arp_reply_map = defaultdict(list)
        for pkt in arp_packets:
            if pkt[ARP].op == 2:  # ARP reply
                arp_reply_map[pkt[ARP].psrc].append(pkt[ARP].hwsrc)
        
        for ip, macs in arp_reply_map.items():
            if len(set(macs)) > 1:  # Multiple MACs claiming same IP
                suspicious_arp.append({
                    'ip': ip,
                    'mac_count': len(set(macs)),
                    'macs': list(set(macs))
                })
                self.alerts.append({
                    'type': 'arp_poisoning',
                    'target_ip': ip,
                    'description': f'Multiple MAC addresses for IP {ip}',
                    'severity': 'high'
                })
        
        return {
            'arp_anomalies': suspicious_arp,
            'risk_level': 'high' if suspicious_arp else 'low'
        }
    
    def detect_dns_tunneling(self) -> Dict:
        """Detect DNS data exfiltration/tunneling"""
        if not SCAPY_AVAILABLE:
            return {}
        
        dns_packets = [p for p in self.packets if DNS in p]
        dns_tunneling_indicators = []
        
        # Look for unusual DNS queries
        query_sizes = []
        for pkt in dns_packets:
            try:
                if pkt[DNS].opcode == 0:  # Standard query
                    # Get query string length
                    questions = pkt[DNS].questions
                    for q in questions:
                        qname = str(q.qname)
                        if len(qname) > 63:  # Unusually long DNS query
                            dns_tunneling_indicators.append({
                                'query': qname[:50] + '...',
                                'length': len(qname),
                                'source': pkt[IP].src
                            })
                            self.alerts.append({
                                'type': 'dns_tunneling',
                                'source': pkt[IP].src,
                                'description': f'Unusually long DNS query ({len(qname)} chars)',
                                'severity': 'medium'
                            })
                            break
            except:
                pass
        
        return {
            'suspicious_dns_queries': dns_tunneling_indicators,
            'risk_level': 'medium' if dns_tunneling_indicators else 'low'
        }
    
    def check_vulnerable_ports(self) -> Dict:
        """Check for traffic on vulnerable ports"""
        if not SCAPY_AVAILABLE:
            return {}
        
        port_traffic = defaultdict(int)
        alert_ports = self.config.get('alert_ports', [22, 23, 3389, 5900, 139, 445])
        
        for pkt in self.packets:
            if TCP in pkt or UDP in pkt:
                protocol = pkt[TCP] if TCP in pkt else pkt[UDP]
                port = protocol.dport
                port_traffic[port] += 1
        
        vulnerable_ports = []
        for port, count in port_traffic.items():
            if port in alert_ports:
                vulnerable_ports.append({
                    'port': port,
                    'packet_count': count,
                    'risk': 'high'
                })
                self.alerts.append({
                    'type': 'vulnerable_port',
                    'port': port,
                    'description': f'Traffic on vulnerable port {port}',
                    'severity': 'high'
                })
        
        return {
            'vulnerable_port_traffic': vulnerable_ports,
            'risk_level': 'high' if vulnerable_ports else 'low'
        }
    
    def calculate_threat_score(self, max_score: float = 100.0) -> float:
        """Calculate overall threat score (0-100)"""
        score = 0.0
        
        # Add points for each alert
        for alert in self.alerts:
            if alert['severity'] == 'high':
                score += 30
            elif alert['severity'] == 'medium':
                score += 15
            else:
                score += 5
        
        # Normalize to 0-100
        self.threat_score = min(score, max_score)
        return self.threat_score
