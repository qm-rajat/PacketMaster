"""
Machine Learning Analysis Module - Anomaly detection, pattern recognition
"""
import logging
from typing import Dict, List, Optional
import numpy as np

try:
    from sklearn.ensemble import IsolationForest
    from sklearn.preprocessing import StandardScaler
    SKLEARN_AVAILABLE = True
except ImportError:
    SKLEARN_AVAILABLE = False

try:
    from scapy.all import IP, TCP, UDP
    SCAPY_AVAILABLE = True
except ImportError:
    SCAPY_AVAILABLE = False

logger = logging.getLogger('MLAnalyzer')


class MLAnalyzer:
    """Machine Learning based analysis"""
    
    def __init__(self, packets, config: Optional[Dict] = None):
        self.packets = packets
        self.config = config or self._default_config()
        self.anomalies = []
        self.models = {}
        
    def _default_config(self) -> Dict:
        return {
            'anomaly_threshold': -0.5,
            'contamination': 0.1,
            'enable_ml': SKLEARN_AVAILABLE
        }
    
    def analyze_all(self) -> Dict:
        """Run all ML-based analysis"""
        if not SKLEARN_AVAILABLE or not self.packets:
            return {'ml_available': False}
        
        return {
            'ml_available': True,
            'anomaly_detection': self.detect_anomalies(),
            'traffic_classification': self.classify_traffic(),
            'behavioral_analysis': self.behavioral_analysis()
        }
    
    def extract_packet_features(self) -> np.ndarray:
        """Extract numerical features from packets for ML"""
        if not SCAPY_AVAILABLE:
            return np.array([])
        
        features = []
        for pkt in self.packets[:min(1000, len(self.packets))]:  # Limit to 1000 for speed
            try:
                feature_vec = []
                
                # Packet size
                feature_vec.append(len(pkt))
                
                # Protocol info
                if IP in pkt:
                    feature_vec.append(pkt[IP].ttl)
                    feature_vec.append(pkt[IP].id)
                else:
                    feature_vec.extend([0, 0])
                
                # TCP/UDP info
                if TCP in pkt:
                    # Convert flags to int
                    flags = int(pkt[TCP].flags) if hasattr(pkt[TCP].flags, '__int__') else 0
                    feature_vec.append(flags)
                    feature_vec.append(pkt[TCP].dport % 256)  # Normalized port
                elif UDP in pkt:
                    feature_vec.append(0)
                    feature_vec.append(pkt[UDP].dport % 256)
                else:
                    feature_vec.extend([0, 0])
                
                features.append(feature_vec)
            except Exception as e:
                logger.debug(f"Feature extraction error: {e}")
                continue
        
        return np.array(features, dtype=np.float64) if features else np.array([])
    
    def detect_anomalies(self) -> Dict:
        """Detect anomalous packets using Isolation Forest"""
        if not SKLEARN_AVAILABLE or len(self.packets) < 10:
            return {'status': 'insufficient_data'}
        
        try:
            features = self.extract_packet_features()
            if features.shape[0] < 10:
                return {'status': 'insufficient_features'}
            
            # Standardize features
            scaler = StandardScaler()
            features_scaled = scaler.fit_transform(features)
            
            # Train Isolation Forest
            iso_forest = IsolationForest(
                contamination=self.config['contamination'],
                random_state=42
            )
            anomaly_labels = iso_forest.fit_predict(features_scaled)
            
            # Get anomaly scores
            anomaly_scores = iso_forest.score_samples(features_scaled)
            
            # Count anomalies
            anomalies = np.where(anomaly_labels == -1)[0]
            anomaly_percentage = len(anomalies) / len(features_scaled) * 100
            
            return {
                'status': 'success',
                'total_packets_analyzed': len(features_scaled),
                'anomalies_detected': int(len(anomalies)),
                'anomaly_percentage': round(anomaly_percentage, 2),
                'anomaly_threshold': self.config['anomaly_threshold'],
                'risk_level': self._assess_anomaly_risk(anomaly_percentage),
                'top_anomaly_scores': [
                    float(score) for score in sorted(anomaly_scores)[:5]
                ]
            }
        except Exception as e:
            logger.error(f"Anomaly detection error: {e}")
            return {'status': 'error', 'message': str(e)}
    
    def classify_traffic(self) -> Dict:
        """Classify traffic types based on packet patterns"""
        if not SCAPY_AVAILABLE:
            return {}
        
        traffic_types = {
            'web': 0,
            'dns': 0,
            'video_streaming': 0,
            'voip': 0,
            'p2p': 0,
            'unknown': 0
        }
        
        for pkt in self.packets[:min(500, len(self.packets))]:
            try:
                if TCP in pkt:
                    port = pkt[TCP].dport
                    if port in [80, 443, 8080]:
                        traffic_types['web'] += 1
                    elif port in [5060, 5061]:
                        traffic_types['voip'] += 1
                    else:
                        traffic_types['p2p'] += 1
                elif UDP in pkt:
                    port = pkt[UDP].dport
                    if port == 53:
                        traffic_types['dns'] += 1
                    elif port in [5004, 5005]:
                        traffic_types['voip'] += 1
                    else:
                        traffic_types['video_streaming'] += 1
            except:
                traffic_types['unknown'] += 1
        
        total = sum(traffic_types.values())
        classification = []
        for ttype, count in sorted(traffic_types.items(), key=lambda x: x[1], reverse=True):
            if count > 0:
                classification.append({
                    'type': ttype,
                    'packets': count,
                    'percentage': round(count / total * 100, 2)
                })
        
        return {'traffic_classification': classification}
    
    def behavioral_analysis(self) -> Dict:
        """Analyze network behavior patterns"""
        if not SCAPY_AVAILABLE or len(self.packets) < 20:
            return {}
        
        # Time-based patterns
        inter_arrival_times = []
        for i in range(1, min(100, len(self.packets))):
            inter_arrival = self.packets[i].time - self.packets[i-1].time
            if inter_arrival > 0:
                inter_arrival_times.append(inter_arrival)
        
        behavior = {
            'packet_consistency': 'regular' if np.std(inter_arrival_times) < np.mean(inter_arrival_times) * 0.5 else 'irregular',
            'burst_detection': 'yes' if any(t > 0.1 for t in inter_arrival_times) else 'no',
            'avg_inter_arrival_ms': round(np.mean(inter_arrival_times) * 1000, 2) if inter_arrival_times else 0
        }
        
        return behavior
    
    def _assess_anomaly_risk(self, anomaly_percentage: float) -> str:
        """Assess risk level based on anomaly percentage"""
        if anomaly_percentage > 20:
            return 'high'
        elif anomaly_percentage > 10:
            return 'medium'
        else:
            return 'low'
