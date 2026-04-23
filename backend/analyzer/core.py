"""
Unified Analysis Orchestrator - Single entry point for ALL analysis
"""
import logging
import time
from typing import Dict, Optional, Tuple
from concurrent.futures import ThreadPoolExecutor, as_completed

try:
    from scapy.all import rdpcap
    SCAPY_AVAILABLE = True
except ImportError:
    SCAPY_AVAILABLE = False

from .security import SecurityAnalyzer
from .performance import PerformanceAnalyzer
from .ml_engine import MLAnalyzer
from .reporters import ReportGenerator

logger = logging.getLogger('UnifiedAnalyzer')


class UnifiedAnalyzer:
    """
    One-click unified packet analysis engine.
    Runs ALL analysis modules in parallel and combines results.
    """
    
    def __init__(self, pcap_file: str, config: Optional[Dict] = None):
        self.pcap_file = pcap_file
        self.config = config or self._default_config()
        self.packets = []
        self.start_time = None
        self.end_time = None
        self.analysis_results = {}
        
        if SCAPY_AVAILABLE:
            try:
                self.packets = rdpcap(pcap_file)
                logger.info(f"✅ Loaded {len(self.packets)} packets")
            except Exception as e:
                logger.error(f"Failed to load PCAP: {e}")
                raise
    
    def _default_config(self) -> Dict:
        """Default configuration"""
        return {
            'enable_security': True,
            'enable_performance': True,
            'enable_ml': True,
            'enable_reports': True,
            'report_formats': ['json', 'html', 'csv'],
            'parallel_processing': True,
            'cache_enabled': False
        }
    
    def analyze(self) -> Tuple[Dict, float]:
        """
        Execute unified analysis. Returns (results, execution_time)
        
        Runs in this order (can be parallelized):
        1. Performance Analysis (fast)
        2. Security Analysis (medium)
        3. ML Analysis (slower)
        4. Report Generation (fast)
        """
        self.start_time = time.time()
        logger.info("🚀 Starting unified packet analysis...")
        
        if not self.packets:
            logger.error("No packets to analyze")
            return {}, 0
        
        try:
            if self.config['parallel_processing']:
                results = self._analyze_parallel()
            else:
                results = self._analyze_sequential()
            
            self.end_time = time.time()
            execution_time = self.end_time - self.start_time
            
            logger.info(f"✅ Analysis complete in {execution_time:.2f} seconds")
            return results, execution_time
            
        except Exception as e:
            logger.error(f"Analysis error: {e}")
            return {'error': str(e)}, 0
    
    def _analyze_parallel(self) -> Dict:
        """Run all analyzers in parallel"""
        logger.info("📊 Running analysis modules in parallel...")
        results = {}
        
        with ThreadPoolExecutor(max_workers=3) as executor:
            futures = {}
            
            # Submit all analysis tasks
            if self.config['enable_performance']:
                futures['performance'] = executor.submit(self._run_performance_analysis)
            
            if self.config['enable_security']:
                futures['security'] = executor.submit(self._run_security_analysis)
            
            if self.config['enable_ml']:
                futures['ml'] = executor.submit(self._run_ml_analysis)
            
            # Collect results as they complete
            for key, future in futures.items():
                try:
                    results[key] = future.result(timeout=60)
                    logger.info(f"✅ {key.capitalize()} analysis complete")
                except Exception as e:
                    logger.error(f"❌ {key.capitalize()} analysis failed: {e}")
                    results[key] = {'error': str(e)}
        
        return results
    
    def _analyze_sequential(self) -> Dict:
        """Run all analyzers sequentially"""
        logger.info("📊 Running analysis modules sequentially...")
        results = {}
        
        if self.config['enable_performance']:
            results['performance'] = self._run_performance_analysis()
            logger.info("✅ Performance analysis complete")
        
        if self.config['enable_security']:
            results['security'] = self._run_security_analysis()
            logger.info("✅ Security analysis complete")
        
        if self.config['enable_ml']:
            results['ml'] = self._run_ml_analysis()
            logger.info("✅ ML analysis complete")
        
        return results
    
    def _run_performance_analysis(self) -> Dict:
        """Execute performance analysis"""
        try:
            analyzer = PerformanceAnalyzer(self.packets, self.config)
            return analyzer.analyze_all()
        except Exception as e:
            logger.error(f"Performance analysis error: {e}")
            return {}
    
    def _run_security_analysis(self) -> Dict:
        """Execute security analysis"""
        try:
            analyzer = SecurityAnalyzer(self.packets, self.config)
            return analyzer.analyze_all()
        except Exception as e:
            logger.error(f"Security analysis error: {e}")
            return {}
    
    def _run_ml_analysis(self) -> Dict:
        """Execute ML analysis"""
        try:
            ml_config = {
                'anomaly_threshold': -0.5,
                'contamination': 0.1,
                'enable_ml': True
            }
            analyzer = MLAnalyzer(self.packets, ml_config)
            return analyzer.analyze_all()
        except Exception as e:
            logger.error(f"ML analysis error: {e}")
            return {}
    
    def get_results(self) -> Dict:
        """Get full analysis results"""
        return self.analysis_results
    
    def generate_reports(self, output_dir: str = 'reports') -> Dict:
        """Generate reports from analysis results"""
        if not self.analysis_results:
            logger.warning("No analysis results to report on")
            return {}
        
        try:
            reporter = ReportGenerator(self.analysis_results, self.pcap_file)
            reports = reporter.generate_all(output_dir)
            logger.info(f"✅ Generated {len(reports)} reports")
            return reports
        except Exception as e:
            logger.error(f"Report generation error: {e}")
            return {}
    
    def get_summary(self) -> Dict:
        """Get executive summary of analysis"""
        summary = {
            'file': self.pcap_file,
            'status': 'success' if self.analysis_results else 'pending',
            'execution_time_seconds': self.end_time - self.start_time if self.end_time else 0,
            'packets_analyzed': len(self.packets)
        }
        
        # Add key metrics
        if 'performance' in self.analysis_results:
            perf = self.analysis_results['performance'].get('traffic_statistics', {})
            summary['traffic'] = {
                'total_packets': perf.get('total_packets', 0),
                'throughput_mbps': perf.get('throughput_mbps', 0),
                'duration_seconds': perf.get('duration_seconds', 0)
            }
        
        if 'security' in self.analysis_results:
            sec = self.analysis_results['security']
            summary['security'] = {
                'threat_score': sec.get('threat_score', 0),
                'alerts_count': len(sec.get('alerts', []))
            }
        
        if 'ml' in self.analysis_results:
            ml = self.analysis_results['ml']
            if ml.get('anomaly_detection', {}).get('status') == 'success':
                summary['anomalies'] = {
                    'detected': ml['anomaly_detection'].get('anomalies_detected', 0),
                    'percentage': ml['anomaly_detection'].get('anomaly_percentage', 0)
                }
        
        return summary


# Convenience function
def auto_analyze(pcap_file: str, config: Optional[Dict] = None) -> Tuple[Dict, float, Dict]:
    """
    One-line analysis function.
    
    Usage:
        results, exec_time, summary = auto_analyze('capture.pcap')
    
    Returns:
        - results: Full analysis data
        - exec_time: Execution time in seconds
        - summary: Executive summary
    """
    analyzer = UnifiedAnalyzer(pcap_file, config)
    analyzer.analysis_results, exec_time = analyzer.analyze()
    summary = analyzer.get_summary()
    return analyzer.analysis_results, exec_time, summary
