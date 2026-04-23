// Analysis and Result Types
export interface Analysis {
  id: string;
  filename: string;
  status: 'pending' | 'running' | 'complete' | 'error';
  created_at: string;
  completed_at?: string;
  threat_score?: number;
  packets?: number;
  execution_time?: number;
}

export interface AnalysisResults {
  performance?: PerformanceData;
  security?: SecurityData;
  ml?: MLData;
}

// Performance Analysis
export interface PerformanceData {
  traffic_statistics?: {
    total_packets: number;
    total_bytes: number;
    duration_seconds: number;
    packets_per_second: number;
    average_packet_size: number;
    throughput_mbps: number;
    throughput_gbps: number;
  };
  protocol_breakdown?: ProtocolBreakdown[];
  top_talkers?: {
    top_source_ips?: TopIP[];
    top_dest_ips?: TopIP[];
  };
  tcp_analysis?: TCPAnalysis;
  packet_size_distribution?: PacketSizeStats;
}

export interface ProtocolBreakdown {
  protocol: string;
  packets: number;
  percentage: number;
  bytes: number;
}

export interface TopIP {
  ip: string;
  packets: number;
  bytes: number;
}

export interface TCPAnalysis {
  total_connections: number;
  established_connections: number;
  reset_connections: number;
  tcp_packets: number;
  syn_fin_ratio: number;
}

export interface PacketSizeStats {
  min_size: number;
  max_size: number;
  avg_size: number;
  median_size: number;
  std_dev: number;
}

// Security Analysis
export interface SecurityData {
  threat_score: number;
  alerts: Alert[];
  port_scan_detection?: PortScanInfo;
  ddos_detection?: DDosInfo;
  spoofing_detection?: SpoofingInfo;
  arp_poisoning?: ARPInfo;
  dns_tunneling?: DNSInfo;
  vulnerable_ports?: VulnerablePortInfo[];
}

export interface Alert {
  type: string;
  severity: 'high' | 'medium' | 'low';
  description: string;
  timestamp?: string;
  source?: string;
}

export interface PortScanInfo {
  syn_packet_count: number;
  suspicious_sources: Array<{
    source: string;
    port_count: number;
    severity: string;
  }>;
  risk_level: string;
}

export interface DDosInfo {
  high_volume_sources: Array<{
    source: string;
    packet_count: number;
    percentage: number;
  }>;
  risk_level: string;
}

export interface SpoofingInfo {
  spoofing_indicators: Array<{
    source: string;
    ttl_values: number[];
    inconsistency: number;
  }>;
  risk_level: string;
}

export interface ARPInfo {
  arp_anomalies: Array<{
    ip: string;
    mac_count: number;
    macs: string[];
  }>;
  risk_level: string;
}

export interface DNSInfo {
  suspicious_dns_queries: Array<{
    query: string;
    length: number;
    source: string;
  }>;
  risk_level: string;
}

export interface VulnerablePortInfo {
  port: number;
  packet_count: number;
  risk: string;
}

// ML Analysis
export interface MLData {
  ml_available: boolean;
  anomaly_detection?: {
    status: string;
    total_packets_analyzed: number;
    anomalies_detected: number;
    anomaly_percentage: number;
    risk_level: string;
  };
  traffic_classification?: TrafficClass[];
  behavioral_analysis?: {
    packet_consistency: string;
    burst_detection: string;
    avg_inter_arrival_ms: number;
  };
}

export interface TrafficClass {
  type: string;
  packets: number;
  percentage: number;
}

// Dashboard Summary
export interface DashboardData {
  statistics: {
    total_analyses: number;
    average_threat_score: number;
    completed: number;
    running: number;
  };
  recent_analyses: Analysis[];
}

// Upload and Job Management
export interface UploadResponse {
  success: boolean;
  analysis_id: string;
  filename: string;
}

export interface JobStatus {
  status: 'running' | 'complete' | 'error';
  created_at?: string;
  error?: string;
}

// Report Types
export interface Report {
  id: string;
  format: 'json' | 'html' | 'csv' | 'pdf';
  created_at: string;
  file_path?: string;
}

// API Response
export interface ApiResponse<T> {
  success: boolean;
  data?: T;
  error?: string;
  message?: string;
}
