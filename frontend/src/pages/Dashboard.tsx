import React, { useEffect, useState } from 'react';
import { Activity, AlertTriangle, BarChart3, TrendingUp } from 'lucide-react';
import { MetricCard, LoadingSpinner, AlertBox } from '../components/Common';
import apiClient from '../services/api';
import type { DashboardData, Analysis } from '../types';

export const Dashboard: React.FC = () => {
  const [data, setData] = useState<DashboardData | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    loadDashboardData();
  }, []);

  const loadDashboardData = async () => {
    try {
      setLoading(true);
      const result = await apiClient.getDashboardData();
      setData(result);
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to load dashboard');
    } finally {
      setLoading(false);
    }
  };

  if (loading) {
    return (
      <div className="flex items-center justify-center h-full">
        <LoadingSpinner size="lg" />
      </div>
    );
  }

  return (
    <div className="space-y-6">
      {/* Page Header */}
      <div>
        <h1 className="text-3xl font-bold text-gray-900">Dashboard</h1>
        <p className="text-gray-600 mt-1">Welcome to PacketMaster Advanced</p>
      </div>

      {/* Error Message */}
      {error && <AlertBox type="error" message={error} />}

      {/* Statistics Grid */}
      {data && (
        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4">
          <MetricCard
            title="Total Analyses"
            value={data.statistics.total_analyses}
            icon={<BarChart3 size={24} />}
            variant="default"
          />
          <MetricCard
            title="Average Threat Score"
            value={data.statistics.average_threat_score.toFixed(1)}
            icon={<AlertTriangle size={24} />}
            variant={
              data.statistics.average_threat_score > 50
                ? 'danger'
                : data.statistics.average_threat_score > 25
                ? 'warning'
                : 'success'
            }
          />
          <MetricCard
            title="Completed"
            value={data.statistics.completed}
            icon={<Activity size={24} />}
            variant="success"
          />
          <MetricCard
            title="Running"
            value={data.statistics.running}
            icon={<TrendingUp size={24} />}
            variant="default"
          />
        </div>
      )}

      {/* Recent Analyses */}
      <div className="card">
        <h2 className="text-xl font-bold text-gray-900 mb-4">Recent Analyses</h2>

        {data && data.recent_analyses.length > 0 ? (
          <div className="overflow-x-auto">
            <table className="w-full">
              <thead>
                <tr className="border-b border-gray-200">
                  <th className="text-left py-3 px-4 font-semibold text-gray-700">File</th>
                  <th className="text-left py-3 px-4 font-semibold text-gray-700">Status</th>
                  <th className="text-left py-3 px-4 font-semibold text-gray-700">Threat Score</th>
                  <th className="text-left py-3 px-4 font-semibold text-gray-700">Created</th>
                </tr>
              </thead>
              <tbody>
                {data.recent_analyses.map((analysis: Analysis) => (
                  <tr key={analysis.id} className="border-b border-gray-100 hover:bg-gray-50 transition">
                    <td className="py-4 px-4 text-gray-900 font-medium truncate">
                      {analysis.filename}
                    </td>
                    <td className="py-4 px-4">
                      <span className={`px-3 py-1 rounded-full text-sm font-medium ${
                        analysis.status === 'complete'
                          ? 'bg-green-100 text-green-800'
                          : analysis.status === 'error'
                          ? 'bg-red-100 text-red-800'
                          : 'bg-blue-100 text-blue-800'
                      }`}>
                        {analysis.status.charAt(0).toUpperCase() + analysis.status.slice(1)}
                      </span>
                    </td>
                    <td className="py-4 px-4">
                      {analysis.threat_score !== undefined ? (
                        <span className={`font-bold ${
                          analysis.threat_score >= 75
                            ? 'text-red-600'
                            : analysis.threat_score >= 50
                            ? 'text-yellow-600'
                            : 'text-green-600'
                        }`}>
                          {analysis.threat_score.toFixed(0)}
                        </span>
                      ) : (
                        '-'
                      )}
                    </td>
                    <td className="py-4 px-4 text-gray-600 text-sm">
                      {new Date(analysis.created_at).toLocaleDateString()}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        ) : (
          <p className="text-center text-gray-500 py-8">No analyses yet. Start by uploading a PCAP file!</p>
        )}
      </div>

      {/* Quick Actions */}
      <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
        <div className="card-hover">
          <h3 className="font-bold text-gray-900 mb-2">🚀 Get Started</h3>
          <p className="text-gray-600 text-sm mb-4">
            Upload a PCAP file to begin analyzing your network traffic
          </p>
          <button className="btn-primary">Upload File</button>
        </div>

        <div className="card-hover">
          <h3 className="font-bold text-gray-900 mb-2">📚 Documentation</h3>
          <p className="text-gray-600 text-sm mb-4">
            Learn how to use PacketMaster's advanced features
          </p>
          <button className="btn-secondary">Read Docs</button>
        </div>
      </div>
    </div>
  );
};
