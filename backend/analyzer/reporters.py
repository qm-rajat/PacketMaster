"""
Report Generation Module - PDF, JSON, HTML, CSV reports
"""
import logging
import json
from datetime import datetime
from typing import Dict, Any, Optional
import os

logger = logging.getLogger('ReportGenerator')


class ReportGenerator:
    """Generate comprehensive analysis reports in multiple formats"""
    
    def __init__(self, analysis_data: Dict[str, Any], filename: str, config: Optional[Dict] = None):
        self.analysis_data = analysis_data
        self.filename = filename
        self.config = config or {}
        self.timestamp = datetime.now().isoformat()
        
    def generate_all(self, output_dir: str = 'reports') -> Dict[str, str]:
        """Generate all report formats"""
        os.makedirs(output_dir, exist_ok=True)
        
        results = {}
        try:
            json_path = self.generate_json(output_dir)
            results['json'] = json_path
            logger.info(f"Generated JSON report: {json_path}")
        except Exception as e:
            logger.error(f"JSON generation failed: {e}")
        
        try:
            html_path = self.generate_html(output_dir)
            results['html'] = html_path
            logger.info(f"Generated HTML report: {html_path}")
        except Exception as e:
            logger.error(f"HTML generation failed: {e}")
        
        try:
            csv_path = self.generate_csv(output_dir)
            results['csv'] = csv_path
            logger.info(f"Generated CSV report: {csv_path}")
        except Exception as e:
            logger.error(f"CSV generation failed: {e}")
        
        return results
    
    def generate_json(self, output_dir: str = 'reports') -> str:
        """Generate comprehensive JSON report"""
        report = {
            'metadata': {
                'filename': self.filename,
                'timestamp': self.timestamp,
                'report_version': '1.0'
            },
            'analysis': self.analysis_data
        }
        
        filename = f"{output_dir}/analysis_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
        with open(filename, 'w') as f:
            json.dump(report, f, indent=2, default=str)
        
        return filename
    
    def generate_html(self, output_dir: str = 'reports') -> str:
        """Generate interactive HTML report"""
        html_content = f"""
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>PacketMaster Analysis Report</title>
    <script src="https://cdn.plot.ly/plotly-latest.min.js"></script>
    <style>
        * {{
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }}
        body {{
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            background: #f5f7fa;
            color: #333;
        }}
        .container {{
            max-width: 1400px;
            margin: 0 auto;
            padding: 20px;
        }}
        header {{
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
            padding: 40px 20px;
            border-radius: 8px;
            margin-bottom: 30px;
            box-shadow: 0 4px 15px rgba(0,0,0,0.1);
        }}
        header h1 {{
            font-size: 2.5em;
            margin-bottom: 10px;
        }}
        header p {{
            font-size: 1.1em;
            opacity: 0.9;
        }}
        .metrics-grid {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(250px, 1fr));
            gap: 20px;
            margin-bottom: 30px;
        }}
        .metric-card {{
            background: white;
            padding: 20px;
            border-radius: 8px;
            box-shadow: 0 2px 8px rgba(0,0,0,0.1);
            border-left: 4px solid #667eea;
        }}
        .metric-card h3 {{
            color: #667eea;
            font-size: 0.9em;
            text-transform: uppercase;
            margin-bottom: 10px;
            opacity: 0.8;
        }}
        .metric-card .value {{
            font-size: 2em;
            font-weight: bold;
            color: #333;
        }}
        .section {{
            background: white;
            padding: 25px;
            border-radius: 8px;
            margin-bottom: 25px;
            box-shadow: 0 2px 8px rgba(0,0,0,0.1);
        }}
        .section h2 {{
            color: #667eea;
            margin-bottom: 20px;
            padding-bottom: 10px;
            border-bottom: 2px solid #e0e7ff;
        }}
        .alert {{
            padding: 15px;
            margin: 10px 0;
            border-radius: 4px;
            border-left: 4px solid;
        }}
        .alert.high {{
            background-color: #fee;
            border-color: #c33;
            color: #933;
        }}
        .alert.medium {{
            background-color: #fef3cd;
            border-color: #ffc107;
            color: #856404;
        }}
        .alert.low {{
            background-color: #d1ecf1;
            border-color: #17a2b8;
            color: #0c5460;
        }}
        table {{
            width: 100%;
            border-collapse: collapse;
            margin-top: 15px;
        }}
        table th {{
            background: #f8f9fa;
            padding: 12px;
            text-align: left;
            font-weight: 600;
            border-bottom: 2px solid #dee2e6;
        }}
        table td {{
            padding: 12px;
            border-bottom: 1px solid #dee2e6;
        }}
        table tr:hover {{
            background-color: #f8f9fa;
        }}
        .chart {{
            margin: 20px 0;
        }}
        footer {{
            text-align: center;
            color: #999;
            margin-top: 40px;
            padding: 20px;
            border-top: 1px solid #e0e7ff;
        }}
    </style>
</head>
<body>
    <div class="container">
        <header>
            <h1>🔍 PacketMaster Analysis Report</h1>
            <p>Comprehensive Network Packet Analysis</p>
            <p>Generated: {self.timestamp}</p>
        </header>
        
        <div class="section">
            <h2>📊 Key Metrics</h2>
            <div class="metrics-grid">
"""
        
        # Add metrics
        if 'performance' in self.analysis_data:
            perf = self.analysis_data['performance'].get('traffic_statistics', {})
            metrics = [
                ('Total Packets', perf.get('total_packets', 0)),
                ('Duration', f"{perf.get('duration_seconds', 0)}s"),
                ('Throughput', f"{perf.get('throughput_mbps', 0)} Mbps"),
                ('Avg Packet Size', f"{perf.get('average_packet_size', 0)} bytes"),
            ]
            for label, value in metrics:
                html_content += f"""
                <div class="metric-card">
                    <h3>{label}</h3>
                    <div class="value">{value}</div>
                </div>
"""
        
        html_content += """
            </div>
        </div>
"""
        
        # Security section
        if 'security' in self.analysis_data and self.analysis_data['security'].get('alerts'):
            html_content += f"""
        <div class="section">
            <h2>🛡️ Security Analysis</h2>
            <p>Threat Score: <strong>{self.analysis_data['security'].get('threat_score', 0)}/100</strong></p>
            <div style="margin-top: 15px;">
"""
            for alert in self.analysis_data['security']['alerts'][:10]:
                severity = alert.get('severity', 'low')
                html_content += f"""
                <div class="alert {severity}">
                    <strong>[{severity.upper()}]</strong> {alert.get('type', 'Unknown')}: {alert.get('description', '')}
                </div>
"""
            html_content += """
            </div>
        </div>
"""
        
        # ML Analysis section
        if 'ml' in self.analysis_data and self.analysis_data['ml'].get('ml_available'):
            ml = self.analysis_data['ml']
            if 'anomaly_detection' in ml:
                anom = ml['anomaly_detection']
                if anom.get('status') == 'success':
                    html_content += f"""
        <div class="section">
            <h2>🤖 Machine Learning Analysis</h2>
            <table>
                <tr>
                    <th>Metric</th>
                    <th>Value</th>
                </tr>
                <tr>
                    <td>Packets Analyzed</td>
                    <td>{anom.get('total_packets_analyzed', 0)}</td>
                </tr>
                <tr>
                    <td>Anomalies Detected</td>
                    <td>{anom.get('anomalies_detected', 0)}</td>
                </tr>
                <tr>
                    <td>Anomaly Percentage</td>
                    <td>{anom.get('anomaly_percentage', 0)}%</td>
                </tr>
                <tr>
                    <td>Risk Level</td>
                    <td><strong>{anom.get('risk_level', 'unknown')}</strong></td>
                </tr>
            </table>
        </div>
"""
        
        html_content += """
        <footer>
            <p>PacketMaster v2.0 - Advanced Network Analysis Suite</p>
            <p>Comprehensive security, performance, and anomaly detection</p>
        </footer>
    </div>
</body>
</html>
"""
        
        filename = f"{output_dir}/analysis_{datetime.now().strftime('%Y%m%d_%H%M%S')}.html"
        with open(filename, 'w') as f:
            f.write(html_content)
        
        return filename
    
    def generate_csv(self, output_dir: str = 'reports') -> str:
        """Generate CSV report"""
        csv_content = "Metric,Value\n"
        
        def flatten_dict(d, parent_key=''):
            items = []
            for k, v in d.items():
                new_key = f"{parent_key}_{k}" if parent_key else k
                if isinstance(v, dict):
                    items.extend(flatten_dict(v, new_key))
                elif isinstance(v, (list, tuple)):
                    items.append((new_key, str(v)[:100]))
                else:
                    items.append((new_key, str(v)))
            return items
        
        for key, value in flatten_dict(self.analysis_data):
            csv_content += f'"{key}","{value}"\n'
        
        filename = f"{output_dir}/analysis_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv"
        with open(filename, 'w') as f:
            f.write(csv_content)
        
        return filename
    
    def generate_summary(self) -> Dict[str, Any]:
        """Generate executive summary"""
        return {
            'timestamp': self.timestamp,
            'filename': self.filename,
            'threat_score': self.analysis_data.get('security', {}).get('threat_score', 0),
            'anomalies': self.analysis_data.get('ml', {}).get('anomaly_detection', {}).get('anomalies_detected', 0),
            'total_packets': self.analysis_data.get('performance', {}).get('traffic_statistics', {}).get('total_packets', 0),
            'alerts_count': len(self.analysis_data.get('security', {}).get('alerts', []))
        }
