"""
🚀 PacketMaster v2.0 - Advanced Packet Analysis Suite
📊 Analyzes: Protocols, Performance, Security, Anomalies
🎯 Usage: python packetmaster.py your_capture.pcap
"""

import sys
import os
import json
import logging
import time
from datetime import datetime
from collections import Counter, defaultdict
import pandas as pd
import numpy as np
from typing import Dict, List, Optional, Tuple
import warnings
warnings.filterwarnings('ignore')

try:
    from scapy.all import rdpcap, IP, TCP, UDP, DNS, HTTP, ICMP, ARP, Ether, wrpcap
    SCAPY_AVAILABLE = True
except ImportError:
    print("⚠️ Scapy not available - limited functionality")
    SCAPY_AVAILABLE = False

try:
    from sklearn.ensemble import IsolationForest
    from sklearn.preprocessing import StandardScaler
    SKLEARN_AVAILABLE = True
except ImportError:
    SKLEARN_AVAILABLE = False

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('packetmaster.log'),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger('PacketMaster')

class PacketMaster:
    def __init__(self, pcap_file: str, config: Optional[Dict] = None):
        """Initialize with pcap file and optional configuration"""
        self.pcap_file = pcap_file
        self.config = config or self._default_config()
        self.packets = []
        self.filtered_packets = []
        self.analysis = {}
        self.ml_models = {}
        self.alerts = []

        # Load packets
        if SCAPY_AVAILABLE:
            try:
                self.packets = rdpcap(pcap_file)
                self.filtered_packets = self.packets.copy()
                logger.info(f"✅ Loaded {len(self.packets)} packets from {pcap_file}")
            except Exception as e:
                logger.error(f"❌ Failed to load {pcap_file}: {e}")
                raise
        else:
            logger.error("❌ Scapy not available")
            raise ImportError("Scapy required for packet analysis")

        # Initialize ML models if available
        if SKLEARN_AVAILABLE:
            self._init_ml_models()

    def _default_config(self) -> Dict:
        """Default configuration settings"""
        return {
            'anomaly_threshold': -0.5,
            'alert_ports': [22, 23, 3389, 5900],  # Common vulnerable ports
            'max_packets_display': 1000,
            'enable_ml': True,
            'export_formats': ['json', 'csv', 'html']
        }

    def filter_packets(self, filter_expr: str) -> List:
        """Apply Wireshark-style filter to packets"""
        if not SCAPY_AVAILABLE:
            return []

        try:
            # Simple filter implementation - can be extended
            filtered = []
            for pkt in self.packets:
                if self._matches_filter(pkt, filter_expr):
                    filtered.append(pkt)
            self.filtered_packets = filtered
            logger.info(f"Filtered to {len(filtered)} packets")
            return filtered
        except Exception as e:
            logger.error(f"Filter error: {e}")
            return self.packets

    def _matches_filter(self, pkt, filter_expr: str) -> bool:
        """Check if packet matches filter expression"""
        # Simple filter parser - extend for full Wireshark syntax
        filter_expr = filter_expr.lower()

        if 'ip' in filter_expr and IP not in pkt:
            return False
        if 'tcp' in filter_expr and TCP not in pkt:
            return False
        if 'udp' in filter_expr and UDP not in pkt:
            return False
        if 'dns' in filter_expr and DNS not in pkt:
            return False
        if 'http' in filter_expr and (TCP not in pkt or pkt[TCP].dport != 80):
            return False

        # Port filters
        if 'port' in filter_expr:
            if TCP in pkt:
                port = pkt[TCP].dport if 'dst port' in filter_expr else pkt[TCP].sport
                if str(port) in filter_expr:
                    return True
            elif UDP in pkt:
                port = pkt[UDP].dport if 'dst port' in filter_expr else pkt[UDP].sport
                if str(port) in filter_expr:
                    return True

        return True  # Default to include if no specific filter
    
    def basic_stats(self):
        """1️⃣ BASIC STATS - Comprehensive traffic statistics"""
        packets = self.filtered_packets or self.packets

        if not packets:
            logger.warning("No packets to analyze")
            return

        duration = packets[-1].time - packets[0].time
        total_bytes = sum(len(p) for p in packets)
        avg_size = total_bytes / len(packets)

        # Calculate throughput
        throughput_bps = total_bytes / duration if duration > 0 else 0
        throughput_mbps = throughput_bps * 8 / 1_000_000

        print(f"\n📊 BASIC STATISTICS")
        print(f"   Total Packets: {len(packets):,}")
        print(f"   Duration: {duration:.2f} seconds")
        print(f"   Packets/sec: {len(packets)/duration:.1f}")
        print(f"   Average packet size: {avg_size:.0f} bytes")
        print(f"   Total bytes: {total_bytes:,}")
        print(f"   Throughput: {throughput_mbps:.2f} Mbps")

        # Size distribution
        sizes = [len(p) for p in packets]
        print(f"   Min packet size: {min(sizes)} bytes")
        print(f"   Max packet size: {max(sizes)} bytes")
        print(f"   Median packet size: {np.median(sizes):.0f} bytes")

        self.analysis['basic'] = {
            'total_packets': len(packets),
            'duration': duration,
            'pps': len(packets)/duration,
            'avg_size': avg_size,
            'total_bytes': total_bytes,
            'throughput_mbps': throughput_mbps,
            'size_stats': {
                'min': min(sizes),
                'max': max(sizes),
                'median': np.median(sizes),
                'std': np.std(sizes)
            }
        }

    def detect_anomalies(self):
        """🔍 ML-BASED ANOMALY DETECTION"""
        if not SKLEARN_AVAILABLE or 'anomaly_detector' not in self.ml_models:
            logger.warning("ML not available for anomaly detection")
            return

        packets = self.filtered_packets or self.packets
        if len(packets) < 10:
            logger.warning("Not enough packets for anomaly detection")
            return

        try:
            # Extract features for ML
            features = []
            for pkt in packets:
                feat = [
                    len(pkt),  # packet size
                    pkt.time,  # timestamp
                ]
                if IP in pkt:
                    feat.extend([pkt[IP].src, pkt[IP].dst, pkt[IP].ttl])
                else:
                    feat.extend([0, 0, 0])  # padding
                features.append(feat)

            # Normalize features
            scaler = StandardScaler()
            features_scaled = scaler.fit_transform(features)

            # Detect anomalies
            anomaly_scores = self.ml_models['anomaly_detector'].fit_predict(features_scaled)
            anomaly_packets = [packets[i] for i in range(len(packets)) if anomaly_scores[i] == -1]

            print(f"\n🔍 ANOMALY DETECTION")
            print(f"   Anomalous packets: {len(anomaly_packets)}/{len(packets)} ({len(anomaly_packets)/len(packets)*100:.1f}%)")

            # Alert on anomalies
            if len(anomaly_packets) > len(packets) * 0.05:  # More than 5% anomalies
                self.alerts.append({
                    'type': 'anomaly_spike',
                    'message': f'High anomaly rate: {len(anomaly_packets)/len(packets)*100:.1f}%',
                    'severity': 'high'
                })

            self.analysis['anomalies'] = {
                'total_anomalies': len(anomaly_packets),
                'anomaly_rate': len(anomaly_packets)/len(packets),
                'anomaly_packets': anomaly_packets[:10]  # Store first 10 for inspection
            }

        except Exception as e:
            logger.error(f"Anomaly detection failed: {e}")
    
    def protocol_breakdown(self):
        """2️⃣ PROTOCOLS - What traffic types?"""
        protocols = []
        for pkt in self.packets:
            layer = pkt.getlayer()
            if layer:
                protocols.append(layer.name)
        
        counts = Counter(protocols)
        print(f"\n📈 PROTOCOL BREAKDOWN (Top 10)")
        for proto, count in counts.most_common(10):
            pct = count / len(self.packets) * 100
            print(f"   {proto:12s}: {count:6d} ({pct:5.1f}%)")
        
        self.analysis['protocols'] = dict(counts)
        return counts
    
    def top_talkers(self):
        """3️⃣ TOP TALKERS - Who sends most?"""
        src_ips = [pkt[IP].src for pkt in self.packets if IP in pkt]
        dst_ips = [pkt[IP].dst for pkt in self.packets if IP in pkt]
        
        print(f"\n🔝 TOP SOURCE IPS")
        for ip, count in Counter(src_ips).most_common(5):
            print(f"   {ip:15s}: {count:6d} packets")
        
        print(f"\n🔝 TOP DESTINATION IPS")
        for ip, count in Counter(dst_ips).most_common(5):
            print(f"   {ip:15s}: {count:6d} packets")
        
        self.analysis['top_src'] = Counter(src_ips).most_common(5)
        self.analysis['top_dst'] = Counter(dst_ips).most_common(5)
    
    def tcp_analysis(self):
        """4️⃣ TCP PERFORMANCE - Connection health"""
        tcp_pkts = [p for p in self.packets if TCP in p]
        syns = sum(1 for p in tcp_pkts if p[TCP].flags & 0x02)  # SYN flag
        fins = sum(1 for p in tcp_pkts if p[TCP].flags & 0x01)  # FIN flag
        rsts = sum(1 for p in tcp_pkts if p[TCP].flags & 0x04)  # RST flag
        
        print(f"\n🔌 TCP ANALYSIS ({len(tcp_pkts)} TCP packets)")
        print(f"   SYN (connections):  {syns}")
        print(f"   FIN (closures):    {fins}")
        print(f"   RST (resets):      {rsts}")
        
        if syns > 0:
            print(f"   SYN/FIN ratio:     {syns/fins:.2f}x {'⚠️ HIGH' if syns/fins > 2 else '✅ OK'}")
        
        self.analysis['tcp'] = {'syn': syns, 'fin': fins, 'rst': rsts}
    
    def security_scan(self):
        """5️⃣ SECURITY CHECKS - Comprehensive threat detection"""
        packets = self.filtered_packets or self.packets
        issues = []
        alerts = []

        # Scan for suspicious TTL (possible spoofing)
        low_ttl = sum(1 for p in packets if IP in p and p[IP].ttl < 32)
        if low_ttl > len(packets) * 0.01:  # More than 1% low TTL
            issues.append(f"⚠️ LOW TTL PACKETS: {low_ttl} ({low_ttl/len(packets)*100:.1f}%) - possible spoofing")
            alerts.append({'type': 'spoofing', 'count': low_ttl, 'severity': 'medium'})

        # Scan for port scans
        tcp_packets = [p for p in packets if TCP in p]
        if tcp_packets:
            src_ports = [p[TCP].sport for p in tcp_packets]
            common_ports = Counter(src_ports).most_common(10)
            if len(common_ports) > 5 and common_ports[0][1] > len(tcp_packets) * 0.1:
                issues.append(f"⚠️ POSSIBLE PORT SCAN: {common_ports[0][1]} pkts from port {common_ports[0][0]}")
                alerts.append({'type': 'port_scan', 'port': common_ports[0][0], 'count': common_ports[0][1], 'severity': 'high'})

        # DNS tunneling check
        dns_packets = [p for p in packets if DNS in p]
        dns_long = sum(1 for p in dns_packets if hasattr(p[DNS], 'qd') and p[DNS].qd and len(p[DNS].qd.qname) > 50)
        if dns_long > 0:
            issues.append(f"⚠️ SUSPICIOUS DNS: {dns_long} long queries (possible tunneling)")
            alerts.append({'type': 'dns_tunnel', 'count': dns_long, 'severity': 'medium'})

        # Check for vulnerable ports
        vulnerable_ports = self.config.get('alert_ports', [22, 23, 3389, 5900])
        for port in vulnerable_ports:
            port_traffic = sum(1 for p in tcp_packets if p[TCP].dport == port or p[TCP].sport == port)
            if port_traffic > 0:
                issues.append(f"⚠️ VULNERABLE PORT {port}: {port_traffic} connections")
                alerts.append({'type': 'vulnerable_port', 'port': port, 'count': port_traffic, 'severity': 'low'})

        # ICMP flood detection
        icmp_packets = [p for p in packets if ICMP in p]
        if len(icmp_packets) > len(packets) * 0.5:  # More than 50% ICMP
            issues.append(f"⚠️ ICMP FLOOD: {len(icmp_packets)} ICMP packets ({len(icmp_packets)/len(packets)*100:.1f}%)")
            alerts.append({'type': 'icmp_flood', 'count': len(icmp_packets), 'severity': 'high'})

        # ARP poisoning detection
        arp_packets = [p for p in packets if ARP in p]
        if len(arp_packets) > len(packets) * 0.1:  # More than 10% ARP
            issues.append(f"⚠️ ARP TRAFFIC: {len(arp_packets)} ARP packets - possible poisoning")
            alerts.append({'type': 'arp_poisoning', 'count': len(arp_packets), 'severity': 'medium'})

        print(f"\n🛡️ SECURITY SCAN")
        if issues:
            for issue in issues:
                print(f"   {issue}")
        else:
            print("   ✅ No major security issues detected")

        self.analysis['security'] = {
            'issues': issues,
            'alerts': alerts,
            'scan_stats': {
                'low_ttl_count': low_ttl,
                'dns_long_queries': dns_long,
                'icmp_count': len(icmp_packets),
                'arp_count': len(arp_packets)
            }
        }

        # Add alerts to global alerts list
        self.alerts.extend(alerts)
    
    def export_report(self, output_dir="report", formats=None):
        """6️⃣ SAVE EVERYTHING - Multi-format professional reports"""
        if formats is None:
            formats = self.config.get('export_formats', ['json', 'csv', 'html'])

        os.makedirs(output_dir, exist_ok=True)
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')

        # Save JSON summary
        if 'json' in formats:
            with open(f"{output_dir}/analysis_{timestamp}.json", 'w') as f:
                json.dump(self.analysis, f, indent=2, default=str)

        # Save CSV with all packets (limited for performance)
        if 'csv' in formats:
            packets_to_export = self.filtered_packets or self.packets
            max_packets = self.config.get('max_packets_display', 1000)

            df_data = []
            for i, p in enumerate(packets_to_export[:max_packets]):
                row = {
                    'index': i,
                    'time': p.time,
                    'src': p[IP].src if IP in p else '',
                    'dst': p[IP].dst if IP in p else '',
                    'proto': p.getlayer().name if p.getlayer() else 'Unknown',
                    'size': len(p),
                    'info': str(p.summary())
                }
                df_data.append(row)

            df = pd.DataFrame(df_data)
            df.to_csv(f"{output_dir}/packets_{timestamp}.csv", index=False)

        # Generate HTML report
        if 'html' in formats:
            self._generate_html_report(output_dir, timestamp)

        print(f"\n💾 REPORT SAVED TO: {output_dir}/")
        for fmt in formats:
            if fmt == 'json':
                print(f"   📄 analysis_{timestamp}.json  (complete analysis)")
            elif fmt == 'csv':
                print(f"   📊 packets_{timestamp}.csv   (packet details)")
            elif fmt == 'html':
                print(f"   🌐 report_{timestamp}.html   (interactive dashboard)")

    def _generate_html_report(self, output_dir: str, timestamp: str):
        """Generate interactive HTML report"""
        html_content = f"""
<!DOCTYPE html>
<html>
<head>
    <title>PacketMaster Analysis Report</title>
    <script src="https://cdn.plotly.com/plotly-latest.min.js"></script>
    <style>
        body {{ font-family: Arial, sans-serif; margin: 20px; }}
        .header {{ background: #f0f0f0; padding: 20px; border-radius: 5px; }}
        .section {{ margin: 20px 0; }}
        .alert {{ padding: 10px; margin: 5px 0; border-radius: 3px; }}
        .alert-high {{ background: #ffdddd; border-left: 5px solid #ff0000; }}
        .alert-medium {{ background: #ffffdd; border-left: 5px solid #ffaa00; }}
        .alert-low {{ background: #ddffdd; border-left: 5px solid #00aa00; }}
    </style>
</head>
<body>
    <div class="header">
        <h1>🚀 PacketMaster Analysis Report</h1>
        <p><strong>File:</strong> {self.pcap_file}</p>
        <p><strong>Generated:</strong> {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p>
        <p><strong>Total Packets:</strong> {self.analysis.get('basic', {}).get('total_packets', 0):,}</p>
    </div>

    <div class="section">
        <h2>📊 Basic Statistics</h2>
        <ul>
            <li>Duration: {self.analysis.get('basic', {}).get('duration', 0):.2f} seconds</li>
            <li>Packets/sec: {self.analysis.get('basic', {}).get('pps', 0):.1f}</li>
            <li>Throughput: {self.analysis.get('basic', {}).get('throughput_mbps', 0):.2f} Mbps</li>
        </ul>
    </div>

    <div class="section">
        <h2>🛡️ Security Alerts</h2>
        {self._generate_alerts_html()}
    </div>

    <div class="section">
        <h2>📈 Protocol Breakdown</h2>
        <div id="protocol-chart"></div>
        <script>
            var protocolData = {json.dumps(self.analysis.get('protocols', {}))};
            var data = [{{
                type: 'pie',
                labels: Object.keys(protocolData),
                values: Object.values(protocolData)
            }}];
            Plotly.newPlot('protocol-chart', data);
        </script>
    </div>
</body>
</html>
        """

        with open(f"{output_dir}/report_{timestamp}.html", 'w') as f:
            f.write(html_content)

    def _generate_alerts_html(self) -> str:
        """Generate HTML for alerts section"""
        if not self.alerts:
            return "<p>✅ No alerts generated</p>"

        html = ""
        for alert in self.alerts:
            severity_class = f"alert-{alert.get('severity', 'low')}"
            html += f"""
            <div class="alert {severity_class}">
                <strong>{alert.get('type', 'Unknown').upper()}</strong>: {alert.get('message', '')}
            </div>
            """
        return html
    
    def run_full_analysis(self):
        """🎯 RUN COMPLETE ANALYSIS SUITE"""
        print(f"\n{'='*60}")
        print(f"🚀 PACKETMASTER ANALYSIS STARTED: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        print(f"📁 File: {self.pcap_file}")
        print(f"{'='*60}")

        start_time = time.time()

        try:
            self.basic_stats()
            self.protocol_breakdown()
            self.top_talkers()
            self.tcp_analysis()
            self.security_scan()

            if self.config.get('enable_ml', True):
                self.detect_anomalies()

            self.export_report()

            analysis_time = time.time() - start_time
            print(f"\n✅ ANALYSIS COMPLETE in {analysis_time:.2f} seconds!")
            print(f"📈 Check 'report/' folder for full details")

            if self.alerts:
                print(f"\n🚨 ALERTS GENERATED: {len(self.alerts)}")
                for alert in self.alerts[:5]:  # Show first 5 alerts
                    print(f"   {alert.get('type', 'Unknown')}: {alert.get('message', '')}")

        except Exception as e:
            logger.error(f"Analysis failed: {e}")
            print(f"\n❌ ANALYSIS FAILED: {e}")

def main():
    import argparse

    parser = argparse.ArgumentParser(description='PacketMaster - Advanced Packet Analysis Suite')
    parser.add_argument('pcap_file', help='PCAP file to analyze')
    parser.add_argument('--filter', help='Apply packet filter (Wireshark syntax)')
    parser.add_argument('--no-ml', action='store_true', help='Disable machine learning features')
    parser.add_argument('--output-dir', default='report', help='Output directory for reports')
    parser.add_argument('--formats', nargs='+', default=['json', 'csv', 'html'],
                       choices=['json', 'csv', 'html'], help='Export formats')

    args = parser.parse_args()

    pcap_file = args.pcap_file
    if not os.path.exists(pcap_file):
        print(f"❌ File not found: {pcap_file}")
        sys.exit(1)

    # Configure analysis
    config = {
        'enable_ml': not args.no_ml,
        'export_formats': args.formats
    }

    try:
        analyzer = PacketMaster(pcap_file, config)

        # Apply filter if specified
        if args.filter:
            analyzer.filter_packets(args.filter)

        analyzer.run_full_analysis()

    except Exception as e:
        logger.error(f"Analysis failed: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()