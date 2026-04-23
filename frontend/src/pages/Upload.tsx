import React, { useState, useEffect } from 'react';
import { FileUpload } from '../components/FileUpload';
import { LoadingSpinner, AlertBox, StatusBadge, ThreatScoreBadge, SeverityBadge, MetricCard } from '../components/Common';
import apiClient from '../services/api';
import type { Analysis, AnalysisResults } from '../types';
import { Download, Eye, AlertTriangle, CheckCircle } from 'lucide-react';

export const Upload: React.FC = () => {
  const [file, setFile] = useState<File | null>(null);
  const [uploading, setUploading] = useState(false);
  const [analysisId, setAnalysisId] = useState<string | null>(null);
  const [analysis, setAnalysis] = useState<Analysis | null>(null);
  const [results, setResults] = useState<AnalysisResults | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [success, setSuccess] = useState<string | null>(null);

  // Poll analysis status
  useEffect(() => {
    if (!analysisId) return;

    const pollStatus = async () => {
      try {
        const analysis = await apiClient.getAnalysis(analysisId);
        setAnalysis(analysis);

        if (analysis.status === 'complete') {
          const results = await apiClient.getResults(analysisId);
          setResults(results);
          setSuccess('Analysis completed successfully!');
        } else if (analysis.status === 'error') {
          setError('Analysis failed');
        }
      } catch (err) {
        console.error('Poll error:', err);
      }
    };

    const interval = setInterval(pollStatus, 1000);
    return () => clearInterval(interval);
  }, [analysisId]);

  const handleFileSelect = async (selectedFile: File) => {
    setFile(selectedFile);
    setError(null);
    setSuccess(null);

    try {
      setUploading(true);
      const response = await apiClient.uploadFile(selectedFile);
      setAnalysisId(response.analysis_id);
      setSuccess(`File uploaded. Analysis ID: ${response.analysis_id}`);
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Upload failed');
      setFile(null);
    } finally {
      setUploading(false);
    }
  };

  const handleDownloadReport = async (format: 'json' | 'html' | 'csv') => {
    if (!analysisId) return;
    try {
      await apiClient.generateReport(analysisId, format);
      setSuccess(`Report generation started (${format.toUpperCase()})`);
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Report generation failed');
    }
  };

  return (
    <div className="space-y-6">
      {/* Page Header */}
      <div>
        <h1 className="text-3xl font-bold text-gray-900">Analyze PCAP File</h1>
        <p className="text-gray-600 mt-1">Upload a packet capture file to begin analysis</p>
      </div>

      {/* Error and Success Messages */}
      {error && <AlertBox type="error" message={error} onClose={() => setError(null)} />}
      {success && <AlertBox type="success" message={success} onClose={() => setSuccess(null)} />}

      {/* Upload Section */}
      {!analysisId ? (
        <div className="card">
          <FileUpload onFileSelect={handleFileSelect} isLoading={uploading} />
        </div>
      ) : (
        <div className="space-y-6">
          {/* Analysis Status */}
          <div className="card">
            <div className="flex items-center justify-between">
              <div>
                <h2 className="text-2xl font-bold text-gray-900">Analysis in Progress</h2>
                {analysis?.filename && (
                  <p className="text-gray-600 mt-2">File: {analysis.filename}</p>
                )}
              </div>
              {analysis && <StatusBadge status={analysis.status} />}
            </div>

            {analysis && analysis.status === 'running' && (
              <div className="mt-4 flex items-center gap-3">
                <LoadingSpinner size="sm" />
                <span className="text-gray-700">Analyzing packets... Please wait</span>
              </div>
            )}
          </div>

          {/* Results */}
          {analysis?.status === 'complete' && results && (
            <div className="space-y-6">
              {/* Summary Metrics */}
              {results.performance?.traffic_statistics && (
                <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4">
                  <MetricCard
                    title="Total Packets"
                    value={results.performance.traffic_statistics.total_packets.toLocaleString()}
                  />
                  <MetricCard
                    title="Duration"
                    value={`${results.performance.traffic_statistics.duration_seconds.toFixed(2)}s`}
                  />
                  <MetricCard
                    title="Throughput"
                    value={`${results.performance.traffic_statistics.throughput_mbps.toFixed(2)} Mbps`}
                  />
                  <MetricCard
                    title="Avg Packet Size"
                    value={`${results.performance.traffic_statistics.average_packet_size.toFixed(0)} B`}
                  />
                </div>
              )}

              {/* Security Results */}
              {results.security && (
                <div className="card">
                  <div className="flex items-center justify-between mb-4">
                    <h3 className="text-xl font-bold text-gray-900">🛡️ Security Analysis</h3>
                    <ThreatScoreBadge score={results.security.threat_score} />
                  </div>

                  {results.security.alerts && results.security.alerts.length > 0 && (
                    <div className="space-y-2">
                      <p className="text-sm text-gray-600 font-medium">
                        {results.security.alerts.length} Alerts Detected
                      </p>
                      <div className="space-y-2 max-h-64 overflow-y-auto">
                        {results.security.alerts.slice(0, 5).map((alert, idx) => (
                          <div key={idx} className="flex items-start gap-3 p-3 bg-gray-50 rounded-lg">
                            <AlertTriangle size={16} className="text-yellow-600 flex-shrink-0 mt-1" />
                            <div className="flex-1">
                              <p className="font-medium text-gray-900">{alert.type}</p>
                              <p className="text-sm text-gray-600">{alert.description}</p>
                            </div>
                            <SeverityBadge severity={alert.severity} />
                          </div>
                        ))}
                      </div>
                    </div>
                  )}
                </div>
              )}

              {/* ML Analysis */}
              {results.ml?.anomaly_detection?.status === 'success' && (
                <div className="card">
                  <h3 className="text-xl font-bold text-gray-900 mb-4">🤖 ML Analysis</h3>
                  <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
                    <MetricCard
                      title="Anomalies Detected"
                      value={results.ml.anomaly_detection.anomalies_detected}
                      variant="warning"
                    />
                    <MetricCard
                      title="Anomaly Rate"
                      value={`${results.ml.anomaly_detection.anomaly_percentage.toFixed(2)}%`}
                    />
                    <MetricCard
                      title="Risk Level"
                      value={results.ml.anomaly_detection.risk_level.toUpperCase()}
                      variant={
                        results.ml.anomaly_detection.risk_level === 'high'
                          ? 'danger'
                          : results.ml.anomaly_detection.risk_level === 'medium'
                          ? 'warning'
                          : 'success'
                      }
                    />
                  </div>
                </div>
              )}

              {/* Report Downloads */}
              <div className="card">
                <h3 className="text-xl font-bold text-gray-900 mb-4">📥 Generate Reports</h3>
                <div className="grid grid-cols-1 md:grid-cols-4 gap-3">
                  {['json', 'html', 'csv', 'pdf'].map((format) => (
                    <button
                      key={format}
                      onClick={() => handleDownloadReport(format as any)}
                      className="flex items-center justify-center gap-2 p-3 bg-primary text-white rounded-lg hover:bg-opacity-90 transition font-medium"
                    >
                      <Download size={18} />
                      {format.toUpperCase()}
                    </button>
                  ))}
                </div>
              </div>
            </div>
          )}

          {/* Error State */}
          {analysis?.status === 'error' && (
            <div className="card bg-red-50 border border-red-200">
              <div className="flex items-center gap-3">
                <AlertTriangle className="text-red-600" size={24} />
                <div>
                  <p className="font-bold text-red-900">Analysis Failed</p>
                  <p className="text-sm text-red-700">Unable to process the PCAP file</p>
                </div>
              </div>
            </div>
          )}

          {/* Upload Another */}
          <button
            onClick={() => {
              setAnalysisId(null);
              setFile(null);
              setResults(null);
              setError(null);
            }}
            className="btn-secondary w-full"
          >
            Upload Another File
          </button>
        </div>
      )}
    </div>
  );
};
