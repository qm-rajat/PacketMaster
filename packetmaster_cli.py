#!/usr/bin/env python3
"""
PacketMaster CLI - Command line interface for unified analysis
Supports both direct analysis and server mode
"""
import sys
import os
import json
import argparse
import time
from pathlib import Path

# Add backend to path
sys.path.insert(0, os.path.dirname(__file__))

from backend.analyzer.core import UnifiedAnalyzer, auto_analyze
from backend.models.database import init_db, AnalysisRecord
from backend.analyzer.reporters import ReportGenerator


def main():
    parser = argparse.ArgumentParser(
        description='PacketMaster v2.0 - Advanced Packet Analysis',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog='''
Examples:
  %(prog)s analyze sample.pcap                    # Full analysis
  %(prog)s analyze sample.pcap --no-ml            # Skip ML analysis
  %(prog)s analyze sample.pcap --output reports/  # Custom output dir
  %(prog)s analyze sample.pcap --format json,html # Specific formats
  %(prog)s serve                                   # Start web server
        '''
    )
    
    subparsers = parser.add_subparsers(dest='command', help='Command to run')
    
    # Analyze command
    analyze_parser = subparsers.add_parser('analyze', help='Analyze PCAP file')
    analyze_parser.add_argument('pcap', help='PCAP file to analyze')
    analyze_parser.add_argument('--output', '-o', default='reports', help='Output directory')
    analyze_parser.add_argument('--format', '-f', default='json,html,csv', 
                               help='Report formats (json,html,csv,pdf)')
    analyze_parser.add_argument('--no-ml', action='store_true', help='Skip ML analysis')
    analyze_parser.add_argument('--no-security', action='store_true', help='Skip security analysis')
    analyze_parser.add_argument('--no-performance', action='store_true', help='Skip performance analysis')
    analyze_parser.add_argument('--sequential', action='store_true', help='Run sequentially (slower)')
    
    # Serve command
    serve_parser = subparsers.add_parser('serve', help='Start web server')
    serve_parser.add_argument('--host', default='0.0.0.0', help='Host to bind')
    serve_parser.add_argument('--port', type=int, default=5001, help='Port')
    serve_parser.add_argument('--debug', action='store_true', help='Debug mode')
    
    # History command
    history_parser = subparsers.add_parser('history', help='Show analysis history')
    history_parser.add_argument('--limit', type=int, default=10, help='Number of records')
    
    args = parser.parse_args()
    
    if not args.command:
        parser.print_help()
        return 1
    
    try:
        if args.command == 'analyze':
            return cmd_analyze(args)
        elif args.command == 'serve':
            return cmd_serve(args)
        elif args.command == 'history':
            return cmd_history(args)
        else:
            parser.print_help()
            return 1
    
    except KeyboardInterrupt:
        print('\n❌ Interrupted by user')
        return 130
    except Exception as e:
        print(f'❌ Error: {e}', file=sys.stderr)
        return 1


def cmd_analyze(args):
    """Execute analysis"""
    pcap_file = args.pcap
    
    if not os.path.exists(pcap_file):
        print(f'❌ File not found: {pcap_file}', file=sys.stderr)
        return 1
    
    print(f'📂 Loading {pcap_file}...')
    
    # Configure analyzer
    config = {
        'enable_ml': not args.no_ml,
        'enable_security': not args.no_security,
        'enable_performance': not args.no_performance,
        'parallel_processing': not args.sequential,
        'report_formats': args.format.split(',')
    }
    
    start_time = time.time()
    
    try:
        # Run analysis
        analyzer = UnifiedAnalyzer(pcap_file, config)
        analyzer.analysis_results, exec_time = analyzer.analyze()
        
        print(f'\n✅ Analysis complete in {exec_time:.2f}s')
        
        # Print summary
        summary = analyzer.get_summary()
        print(f'\n📊 SUMMARY:')
        print(f'   Packets: {summary.get("packets_analyzed", 0):,}')
        if 'traffic' in summary:
            print(f'   Throughput: {summary["traffic"].get("throughput_mbps", 0)} Mbps')
        if 'security' in summary:
            print(f'   Threat Score: {summary["security"].get("threat_score", 0)}/100')
        if 'anomalies' in summary:
            print(f'   Anomalies: {summary["anomalies"].get("detected", 0)}')
        
        # Generate reports
        if config.get('report_formats'):
            print(f'\n📄 Generating reports...')
            os.makedirs(args.output, exist_ok=True)
            
            reporter = ReportGenerator(analyzer.analysis_results, pcap_file)
            reports = reporter.generate_all(args.output)
            
            for fmt, path in reports.items():
                print(f'   ✅ {fmt.upper()}: {path}')
        
        # Save full results as JSON
        results_file = os.path.join(args.output, f'results_{int(time.time())}.json')
        with open(results_file, 'w') as f:
            json.dump(analyzer.analysis_results, f, indent=2, default=str)
        print(f'\n💾 Full results: {results_file}')
        
        return 0
    
    except Exception as e:
        print(f'❌ Analysis failed: {e}', file=sys.stderr)
        import traceback
        traceback.print_exc()
        return 1


def cmd_serve(args):
    """Start web server"""
    print('🚀 Starting PacketMaster server...')
    print(f'   Host: {args.host}')
    print(f'   Port: {args.port}')
    print(f'   Debug: {args.debug}')
    print(f'\n📱 Open http://localhost:{args.port} in your browser')
    
    # Initialize database
    init_db()
    
    # Import and run Flask app
    from backend.app import app
    app.run(host=args.host, port=args.port, debug=args.debug)
    
    return 0


def cmd_history(args):
    """Show analysis history"""
    init_db()
    
    records = AnalysisRecord.get_all(args.limit)
    
    if not records:
        print('No analyses found')
        return 0
    
    print(f'\n📋 Analysis History (last {len(records)}):')
    print(f'{"ID":<36} {"Filename":<30} {"Status":<10} {"Score":<6} {"Date":<20}')
    print('-' * 102)
    
    for r in records:
        score = f"{r.threat_score:.0f}" if r.threat_score else "-"
        print(f'{r.id:<36} {r.filename[:29]:<30} {r.status:<10} {score:<6} {str(r.created_at)[:19]:<20}')
    
    return 0


if __name__ == '__main__':
    sys.exit(main())
