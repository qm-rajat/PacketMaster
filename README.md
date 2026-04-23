# 🚀 PacketMaster v2.0 - Advanced Packet Analysis Suite

**Everything Wireshark does + Automation + ML + Web Dashboard + Alerts**

PacketMaster is a production-ready, all-in-one network packet analysis tool that combines the power of Wireshark with machine learning, automated monitoring, and comprehensive reporting.

## ✨ Features

### 🔍 **Core Analysis (Wireshark-like)**
- **Packet Dissection**: Deep protocol analysis (IP, TCP, UDP, DNS, HTTP, ICMP, ARP)
- **Traffic Statistics**: Throughput, packet rates, size distributions
- **Protocol Breakdown**: Detailed protocol usage analysis
- **Top Talkers**: Identify most active IP addresses and ports
- **TCP Performance**: Connection health, SYN/FIN ratios, RST analysis
- **Filtering**: Apply Wireshark-style filters to packet captures

### 🤖 **Machine Learning & AI**
- **Anomaly Detection**: Isolation Forest-based anomaly detection
- **Traffic Classification**: Automatic traffic pattern recognition
- **Behavioral Analysis**: Identify suspicious network behavior
- **Predictive Alerts**: ML-powered threat detection

### 🛡️ **Security Analysis**
- **Threat Detection**: Port scans, spoofing attempts, tunneling
- **Vulnerability Scanning**: Check for vulnerable ports and services
- **DDoS Detection**: Identify flood attacks and volumetric threats
- **ARP Poisoning**: Detect man-in-the-middle attempts

### 🌐 **Web Dashboard**
- **Real-time Monitoring**: Live packet analysis dashboard
- **Interactive Charts**: Plotly-powered visualizations
- **File Upload**: Drag-and-drop PCAP file analysis
- **Report Generation**: Automated HTML/PDF reports

### ⚡ **Automation & Alerting**
- **Scheduled Analysis**: Automatic monitoring of PCAP directories
- **Email Alerts**: Configurable alert notifications
- **Batch Processing**: Analyze multiple files simultaneously
- **Retention Management**: Automatic cleanup of old reports

## 🚀 Quick Start

### Installation

```bash
# Clone the repository
git clone https://github.com/your-repo/PacketMaster.git
cd PacketMaster

# Install dependencies
pip install -r requirements.txt

# For Linux users, install tcpdump for live capture (optional)
sudo apt-get install tcpdump
```

### Basic Usage

```bash
# Analyze a single PCAP file
python packetmaster.py capture.pcap

# Start web dashboard
python dashboard.py

# Run automated monitoring
python automation.py

# Batch analyze multiple files
python batch_analyze.py
```

## 📖 Detailed Usage

### Command Line Analysis

```bash
python packetmaster.py your_capture.pcap
```

**Output includes:**
- 📊 Basic statistics (packets, duration, throughput)
- 📈 Protocol breakdown with percentages
- 🔝 Top talkers (source/destination IPs)
- 🔌 TCP connection analysis
- 🛡️ Security scan results
- 💾 Exported reports (JSON, CSV, HTML)

### Web Dashboard

```bash
python dashboard.py
```

**Features:**
- Upload PCAP files through web interface
- Interactive charts and graphs
- Real-time analysis results
- Downloadable reports
- Alert management

**Access:** http://localhost:5001

### Automated Monitoring

```bash
python automation.py
```

**Configuration** (`automation_config.json`):
```json
{
  "watch_directory": "pcaps/",
  "schedule_interval": 3600,
  "email_alerts": {
    "enabled": true,
    "recipients": ["admin@company.com"]
  },
  "alert_thresholds": {
    "anomaly_rate": 0.05,
    "security_alerts": 1
  }
}
```

### Batch Analysis

```bash
python batch_analyze.py
```

Analyzes all `.pcap` files in the `pcaps/` directory.

## 🔧 Configuration

### PacketMaster Configuration

The tool uses sensible defaults but can be customized:

```python
config = {
    'anomaly_threshold': -0.5,
    'alert_ports': [22, 23, 3389, 5900],
    'max_packets_display': 1000,
    'enable_ml': True,
    'export_formats': ['json', 'csv', 'html']
}
```

### Automation Configuration

Edit `automation_config.json` to customize automated monitoring:

- **watch_directory**: Directory to monitor for new PCAP files
- **schedule_interval**: Analysis frequency in seconds
- **email_alerts**: SMTP configuration for notifications
- **alert_thresholds**: Thresholds for triggering alerts

## 📊 Output Formats

### JSON Report
Complete analysis data in structured JSON format.

### CSV Export
Packet-level details for further analysis in Excel/spreadsheets.

### HTML Dashboard
Interactive web report with charts and visualizations.

### Log Files
- `packetmaster.log`: Analysis logs
- `automation.log`: Automation and alerting logs

## 🔍 Filtering Examples

PacketMaster supports Wireshark-style filtering:

```python
analyzer = PacketMaster('capture.pcap')
analyzer.filter_packets('tcp port 80')  # HTTP traffic
analyzer.filter_packets('ip src 192.168.1.1')  # From specific IP
analyzer.filter_packets('dns')  # DNS queries only
```

## 🤖 Machine Learning Features

### Anomaly Detection
- Uses Isolation Forest algorithm
- Detects unusual packet patterns
- Configurable contamination threshold

### Traffic Classification
- Automatic protocol identification
- Behavioral pattern analysis
- Suspicious activity detection

## 🛡️ Security Features

### Threat Detection
- **Port Scanning**: Identifies sequential port probes
- **Spoofing**: Detects suspicious TTL values
- **Tunneling**: DNS and ICMP tunneling detection
- **Flood Attacks**: DDoS and volumetric attack detection

### Alert Types
- **High**: Critical security threats
- **Medium**: Suspicious activity
- **Low**: Potential vulnerabilities

## 📈 Performance & Scaling

- **Memory Efficient**: Processes large PCAP files without excessive memory usage
- **Fast Analysis**: Optimized algorithms for quick results
- **Batch Processing**: Handle multiple files simultaneously
- **Background Monitoring**: Non-blocking automated analysis

## 🔧 Advanced Usage

### Custom Analysis Scripts

```python
from packetmaster import PacketMaster

# Load and analyze
analyzer = PacketMaster('capture.pcap')

# Apply filters
analyzer.filter_packets('tcp and port 443')

# Run specific analysis
analyzer.basic_stats()
analyzer.security_scan()

# Access results
print(analyzer.analysis['basic'])
print(analyzer.alerts)
```

### Integration with Other Tools

PacketMaster can be integrated with:
- **SIEM Systems**: Export alerts to Splunk, ELK, etc.
- **Network Monitoring**: Integration with Nagios, Zabbix
- **Log Analysis**: Feed data to Logstash, Fluentd
- **Databases**: Store results in MongoDB, PostgreSQL

## 🐛 Troubleshooting

### Common Issues

1. **Scapy Import Error**
   ```bash
   pip install scapy
   ```

2. **Permission Denied**
   ```bash
   sudo python packetmaster.py capture.pcap
   ```

3. **Large File Handling**
   - Use filtering to reduce memory usage
   - Increase system memory
   - Process files in chunks

4. **ML Not Working**
   - Ensure scikit-learn is installed
   - Check available memory for large datasets

### Debug Mode

Enable verbose logging:
```bash
export PYTHONPATH=.
python -c "import logging; logging.basicConfig(level=logging.DEBUG)"
python packetmaster.py capture.pcap
```

## 🤝 Contributing

1. Fork the repository
2. Create a feature branch
3. Add tests for new features
4. Submit a pull request

## 📄 License

This project is licensed under the MIT License - see the LICENSE file for details.

## 🙏 Acknowledgments

- Built on top of [Scapy](https://scapy.net/) for packet manipulation
- Uses [Plotly](https://plotly.com/) for visualizations
- Machine learning powered by [scikit-learn](https://scikit-learn.org/)

---

**Made with ❤️ for network analysts and security professionals**