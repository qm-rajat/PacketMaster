#!/usr/bin/env python3
"""
🚀 PacketMaster Automation Suite
📊 Scheduled Analysis, Alerting, and Monitoring
"""

import os
import time
import schedule
import smtplib
import json
import logging
from datetime import datetime, timedelta
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from packetmaster import PacketMaster
import glob
from typing import Dict, List, Optional

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('automation.log'),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger('PacketMaster-Automation')

class PacketMasterAutomation:
    def __init__(self, config_file: str = 'automation_config.json'):
        self.config = self._load_config(config_file)
        self.alert_history = []
        self.last_analysis = {}

    def _load_config(self, config_file: str) -> Dict:
        """Load automation configuration"""
        default_config = {
            'watch_directory': 'pcaps/',
            'report_directory': 'reports/',
            'schedule_interval': 3600,  # 1 hour
            'email_alerts': {
                'enabled': False,
                'smtp_server': 'smtp.gmail.com',
                'smtp_port': 587,
                'username': '',
                'password': '',
                'recipients': []
            },
            'alert_thresholds': {
                'anomaly_rate': 0.05,
                'security_alerts': 1,
                'packet_spike': 10000
            },
            'retention_days': 30
        }

        if os.path.exists(config_file):
            with open(config_file, 'r') as f:
                user_config = json.load(f)
                default_config.update(user_config)

        return default_config

    def start_monitoring(self):
        """Start automated monitoring"""
        logger.info("🚀 Starting PacketMaster Automation")

        # Create directories
        os.makedirs(self.config['watch_directory'], exist_ok=True)
        os.makedirs(self.config['report_directory'], exist_ok=True)

        # Schedule tasks
        schedule.every(self.config['schedule_interval']).seconds.do(self._run_scheduled_analysis)
        schedule.every().day.at("02:00").do(self._cleanup_old_reports)

        logger.info(f"📅 Scheduled analysis every {self.config['schedule_interval']} seconds")
        logger.info(f"🧹 Daily cleanup at 02:00")

        # Run initial analysis
        self._run_scheduled_analysis()

        # Main loop
        try:
            while True:
                schedule.run_pending()
                time.sleep(60)  # Check every minute
        except KeyboardInterrupt:
            logger.info("🛑 Automation stopped by user")

    def _run_scheduled_analysis(self):
        """Run scheduled analysis on new files"""
        logger.info("🔍 Running scheduled analysis")

        # Find new PCAP files
        pcap_pattern = os.path.join(self.config['watch_directory'], '*.pcap')
        pcap_files = glob.glob(pcap_pattern)

        new_files = []
        for pcap_file in pcap_files:
            filename = os.path.basename(pcap_file)
            if filename not in self.last_analysis:
                new_files.append(pcap_file)

        if not new_files:
            logger.info("📁 No new PCAP files found")
            return

        logger.info(f"📁 Found {len(new_files)} new PCAP files")

        # Analyze each file
        for pcap_file in new_files:
            try:
                logger.info(f"🔬 Analyzing {pcap_file}")
                analyzer = PacketMaster(pcap_file)

                # Run analysis
                analyzer.run_full_analysis()

                # Store results
                filename = os.path.basename(pcap_file)
                self.last_analysis[filename] = {
                    'timestamp': datetime.now().isoformat(),
                    'analysis': analyzer.analysis,
                    'alerts': analyzer.alerts
                }

                # Check for alerts
                self._check_alerts(analyzer)

                # Move processed file
                processed_dir = os.path.join(self.config['watch_directory'], 'processed')
                os.makedirs(processed_dir, exist_ok=True)
                new_path = os.path.join(processed_dir, filename)
                os.rename(pcap_file, new_path)
                logger.info(f"✅ Analysis complete for {filename}")

            except Exception as e:
                logger.error(f"❌ Failed to analyze {pcap_file}: {e}")

    def _check_alerts(self, analyzer: PacketMaster):
        """Check for alert conditions"""
        alerts = analyzer.alerts
        analysis = analyzer.analysis

        triggered_alerts = []

        # Check anomaly rate
        if 'anomalies' in analysis:
            anomaly_rate = analysis['anomalies'].get('anomaly_rate', 0)
            if anomaly_rate > self.config['alert_thresholds']['anomaly_rate']:
                triggered_alerts.append({
                    'type': 'high_anomaly_rate',
                    'message': f'Anomaly rate {anomaly_rate:.1%} exceeds threshold {self.config["alert_thresholds"]["anomaly_rate"]:.1%}',
                    'severity': 'high'
                })

        # Check security alerts
        security_alerts = len(alerts)
        if security_alerts >= self.config['alert_thresholds']['security_alerts']:
            triggered_alerts.append({
                'type': 'security_alerts',
                'message': f'{security_alerts} security alerts detected',
                'severity': 'high'
            })

        # Check packet spike
        total_packets = analysis.get('basic', {}).get('total_packets', 0)
        if total_packets > self.config['alert_thresholds']['packet_spike']:
            triggered_alerts.append({
                'type': 'packet_spike',
                'message': f'High packet count: {total_packets:,} packets',
                'severity': 'medium'
            })

        # Send alerts if any triggered
        if triggered_alerts:
            self._send_alerts(triggered_alerts, analyzer.pcap_file)

        # Store alert history
        self.alert_history.extend(triggered_alerts)

    def _send_alerts(self, alerts: List[Dict], filename: str):
        """Send alert notifications"""
        if not self.config['email_alerts']['enabled']:
            logger.info("📧 Email alerts disabled")
            return

        try:
            # Create message
            msg = MIMEMultipart()
            msg['From'] = self.config['email_alerts']['username']
            msg['To'] = ', '.join(self.config['email_alerts']['recipients'])
            msg['Subject'] = f'🚨 PacketMaster Alert: {filename}'

            body = f"""
PacketMaster Alert Report
File: {filename}
Time: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}

Alerts:
"""
            for alert in alerts:
                body += f"- {alert['type'].upper()}: {alert['message']}\n"

            msg.attach(MIMEText(body, 'plain'))

            # Send email
            server = smtplib.SMTP(self.config['email_alerts']['smtp_server'],
                                self.config['email_alerts']['smtp_port'])
            server.starttls()
            server.login(self.config['email_alerts']['username'],
                        self.config['email_alerts']['password'])
            server.send_message(msg)
            server.quit()

            logger.info(f"📧 Sent {len(alerts)} alerts via email")

        except Exception as e:
            logger.error(f"❌ Failed to send email alerts: {e}")

    def _cleanup_old_reports(self):
        """Clean up old report files"""
        retention_days = self.config['retention_days']
        cutoff_date = datetime.now() - timedelta(days=retention_days)

        report_dir = self.config['report_directory']
        if not os.path.exists(report_dir):
            return

        cleaned_count = 0
        for file_path in glob.glob(os.path.join(report_dir, '*')):
            if os.path.isfile(file_path):
                file_date = datetime.fromtimestamp(os.path.getmtime(file_path))
                if file_date < cutoff_date:
                    os.remove(file_path)
                    cleaned_count += 1

        if cleaned_count > 0:
            logger.info(f"🧹 Cleaned up {cleaned_count} old report files")

    def generate_report(self) -> str:
        """Generate automation status report"""
        report = f"""
PacketMaster Automation Report
Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}

Configuration:
- Watch Directory: {self.config['watch_directory']}
- Report Directory: {self.config['report_directory']}
- Schedule Interval: {self.config['schedule_interval']} seconds
- Email Alerts: {'Enabled' if self.config['email_alerts']['enabled'] else 'Disabled'}

Statistics:
- Files Analyzed: {len(self.last_analysis)}
- Total Alerts: {len(self.alert_history)}
- Last Analysis: {max([v['timestamp'] for v in self.last_analysis.values()] ) if self.last_analysis else 'None'}

Recent Alerts:
"""
        for alert in self.alert_history[-10:]:  # Last 10 alerts
            report += f"- {alert['timestamp'] if 'timestamp' in alert else 'Unknown'}: {alert['type']} - {alert['message']}\n"

        return report

def main():
    import argparse

    parser = argparse.ArgumentParser(description='PacketMaster Automation Suite')
    parser.add_argument('--config', default='automation_config.json',
                       help='Configuration file path')
    parser.add_argument('--report', action='store_true',
                       help='Generate and print status report')

    args = parser.parse_args()

    automation = PacketMasterAutomation(args.config)

    if args.report:
        print(automation.generate_report())
    else:
        automation.start_monitoring()

if __name__ == "__main__":
    main()