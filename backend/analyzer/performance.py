"""
Performance Analysis Module - Throughput, latency, packet patterns
"""
import logging
from collections import Counter, defaultdict
from typing import Dict, Optional
import numpy as np

try:
    from scapy.all import IP, TCP, UDP
    SCAPY_AVAILABLE = True
except ImportError:
    SCAPY_AVAILABLE = False

logger = logging.getLogger('PerformanceAnalyzer')


class PerformanceAnalyzer:
    """Analyze network performance metrics"""
    
    def __init__(self, packets, config: Optional[Dict] = None):
        self.packets = packets
        self.config = config or {}
        
    def analyze_all(self) -> Dict:
        """Run all performance analysis"""
        if not self.packets:
            return {}
        
        return {
            'traffic_statistics': self.traffic_statistics(),
            'protocol_breakdown': self.protocol_breakdown(),
            'top_talkers': self.top_talkers(),
            'tcp_analysis': self.tcp_connection_analysis(),
            'packet_size_distribution': self.packet_size_distribution()
        }
    
    def traffic_statistics(self) -> Dict:
        """Calculate comprehensive traffic statistics"""
        if not self.packets:
            return {}
        
        duration = self.packets[-1].time - self.packets[0].time
        total_bytes = sum(len(p) for p in self.packets)
        avg_size = total_bytes / len(self.packets) if self.packets else 0
        
        throughput_bps = total_bytes / duration if duration > 0 else 0
        throughput_mbps = throughput_bps * 8 / 1_000_000
        packet_rate = len(self.packets) / duration if duration > 0 else 0
        
        return {
            'total_packets': len(self.packets),
            'total_bytes': total_bytes,
            'duration_seconds': round(duration, 2),
            'packets_per_second': round(packet_rate, 2),
            'average_packet_size': round(avg_size, 2),
            'throughput_mbps': round(throughput_mbps, 2),
            'throughput_gbps': round(throughput_mbps / 1000, 4)
        }
    
    def protocol_breakdown(self) -> Dict:
        """Break down traffic by protocol"""
        if not SCAPY_AVAILABLE:
            return {}
        
        protocol_count = Counter()
        protocol_bytes = Counter()
        
        for pkt in self.packets:
            if IP in pkt:
                protocol_id = pkt[IP].proto
                if protocol_id == 6:
                    proto = 'TCP'
                elif protocol_id == 17:
                    proto = 'UDP'
                elif protocol_id == 1:
                    proto = 'ICMP'
                else:
                    proto = f'Other({protocol_id})'
            else:
                proto = 'Non-IP'
            
            protocol_count[proto] += 1
            protocol_bytes[proto] += len(pkt)
        
        total_packets = sum(protocol_count.values())
        breakdown = []
        for proto, count in protocol_count.most_common():
            breakdown.append({
                'protocol': proto,
                'packets': count,
                'percentage': round(count / total_packets * 100, 2) if total_packets else 0,
                'bytes': protocol_bytes[proto]
            })
        
        return {'protocols': breakdown}
    
    def top_talkers(self, limit: int = 10) -> Dict:
        """Identify top source/destination IPs"""
        if not SCAPY_AVAILABLE:
            return {}
        
        src_ips = Counter()
        dst_ips = Counter()
        src_bytes = Counter()
        dst_bytes = Counter()
        
        for pkt in self.packets:
            if IP in pkt:
                src = pkt[IP].src
                dst = pkt[IP].dst
                size = len(pkt)
                
                src_ips[src] += 1
                dst_ips[dst] += 1
                src_bytes[src] += size
                dst_bytes[dst] += size
        
        return {
            'top_source_ips': [
                {'ip': ip, 'packets': count, 'bytes': src_bytes[ip]}
                for ip, count in src_ips.most_common(limit)
            ],
            'top_dest_ips': [
                {'ip': ip, 'packets': count, 'bytes': dst_bytes[ip]}
                for ip, count in dst_ips.most_common(limit)
            ]
        }
    
    def tcp_connection_analysis(self) -> Dict:
        """Analyze TCP connection patterns"""
        if not SCAPY_AVAILABLE:
            return {}
        
        tcp_packets = [p for p in self.packets if TCP in p]
        if not tcp_packets:
            return {}
        
        connections = defaultdict(lambda: {'syn': 0, 'fin': 0, 'rst': 0, 'packets': 0})
        
        for pkt in tcp_packets:
            src = pkt[IP].src
            dst = pkt[IP].dst
            sport = pkt[TCP].sport
            dport = pkt[TCP].dport
            flags = pkt[TCP].flags
            
            conn_key = f"{src}:{sport}->{dst}:{dport}"
            conn = connections[conn_key]
            conn['packets'] += 1
            
            if flags & 0x02:  # SYN
                conn['syn'] += 1
            if flags & 0x01:  # FIN
                conn['fin'] += 1
            if flags & 0x04:  # RST
                conn['rst'] += 1
        
        # Calculate connection metrics
        established = sum(1 for c in connections.values() if c['syn'] > 0 and c['fin'] > 0)
        reset = sum(1 for c in connections.values() if c['rst'] > 0)
        
        return {
            'total_connections': len(connections),
            'established_connections': established,
            'reset_connections': reset,
            'tcp_packets': len(tcp_packets),
            'syn_fin_ratio': round(
                sum(c['syn'] for c in connections.values()) / 
                max(1, sum(c['fin'] for c in connections.values())),
                2
            )
        }
    
    def packet_size_distribution(self) -> Dict:
        """Analyze packet size distribution"""
        if not self.packets:
            return {}
        
        sizes = [len(p) for p in self.packets]
        
        return {
            'min_size': int(np.min(sizes)) if sizes else 0,
            'max_size': int(np.max(sizes)) if sizes else 0,
            'avg_size': round(float(np.mean(sizes)), 2) if sizes else 0,
            'median_size': int(np.median(sizes)) if sizes else 0,
            'std_dev': round(float(np.std(sizes)), 2) if sizes else 0
        }
