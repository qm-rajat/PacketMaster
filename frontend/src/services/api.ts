import axios, { AxiosInstance, AxiosError } from 'axios';
import type {
  Analysis,
  AnalysisResults,
  DashboardData,
  UploadResponse,
  ApiResponse,
} from '../types';

const API_BASE_URL = process.env.VITE_API_URL || '/api/v2';

class APIClient {
  private client: AxiosInstance;

  constructor() {
    this.client = axios.create({
      baseURL: API_BASE_URL,
      timeout: 30000,
      headers: {
        'Content-Type': 'application/json',
      },
    });

    // Add request interceptor
    this.client.interceptors.request.use((config) => {
      return config;
    });

    // Add response interceptor
    this.client.interceptors.response.use(
      (response) => response,
      (error: AxiosError) => {
        console.error('API Error:', error);
        return Promise.reject(error);
      }
    );
  }

  // Health Check
  async health(): Promise<boolean> {
    try {
      const response = await this.client.get('/health');
      return response.status === 200;
    } catch {
      return false;
    }
  }

  // Upload and start analysis
  async uploadFile(file: File): Promise<UploadResponse> {
    const formData = new FormData();
    formData.append('file', file);

    try {
      const response = await this.client.post<UploadResponse>('/analyze', formData, {
        headers: {
          'Content-Type': 'multipart/form-data',
        },
      });
      return response.data;
    } catch (error) {
      throw this.handleError(error);
    }
  }

  // Get analysis status and results
  async getAnalysis(analysisId: string): Promise<Analysis> {
    try {
      const response = await this.client.get<Analysis>(`/analyze/${analysisId}`);
      return response.data;
    } catch (error) {
      throw this.handleError(error);
    }
  }

  // Get full analysis results
  async getResults(analysisId: string): Promise<AnalysisResults> {
    try {
      const response = await this.client.get<AnalysisResults>(`/results/${analysisId}`);
      return response.data;
    } catch (error) {
      throw this.handleError(error);
    }
  }

  // Get performance results
  async getPerformanceResults(analysisId: string) {
    try {
      const response = await this.client.get(`/results/${analysisId}/performance`);
      return response.data;
    } catch (error) {
      throw this.handleError(error);
    }
  }

  // Get security results
  async getSecurityResults(analysisId: string) {
    try {
      const response = await this.client.get(`/results/${analysisId}/security`);
      return response.data;
    } catch (error) {
      throw this.handleError(error);
    }
  }

  // Get ML results
  async getMLResults(analysisId: string) {
    try {
      const response = await this.client.get(`/results/${analysisId}/ml`);
      return response.data;
    } catch (error) {
      throw this.handleError(error);
    }
  }

  // Get alerts
  async getAlerts(analysisId: string, severity?: string) {
    try {
      const params = severity ? { severity } : {};
      const response = await this.client.get(`/alerts/${analysisId}`, { params });
      return response.data;
    } catch (error) {
      throw this.handleError(error);
    }
  }

  // Acknowledge alert
  async acknowledgeAlert(alertId: string): Promise<boolean> {
    try {
      const response = await this.client.post(`/alerts/${alertId}/acknowledge`);
      return response.data.success;
    } catch (error) {
      throw this.handleError(error);
    }
  }

  // Get analysis history
  async getHistory(limit: number = 50): Promise<Analysis[]> {
    try {
      const response = await this.client.get('/history', {
        params: { limit },
      });
      return response.data.analyses || [];
    } catch (error) {
      throw this.handleError(error);
    }
  }

  // Generate report
  async generateReport(analysisId: string, format: 'json' | 'html' | 'csv' | 'pdf') {
    try {
      const response = await this.client.post(`/reports/${analysisId}/generate`, {
        format,
      });
      return response.data;
    } catch (error) {
      throw this.handleError(error);
    }
  }

  // Get dashboard data (legacy v1 endpoint)
  async getDashboardData(): Promise<DashboardData> {
    try {
      const response = await this.client.get<DashboardData>('/dashboard', {
        baseURL: '/api',
      });
      return response.data;
    } catch (error) {
      throw this.handleError(error);
    }
  }

  // Poll analysis status
  async pollAnalysisStatus(
    analysisId: string,
    maxAttempts: number = 60,
    intervalMs: number = 500
  ): Promise<Analysis> {
    let attempts = 0;

    while (attempts < maxAttempts) {
      try {
        const analysis = await this.getAnalysis(analysisId);
        if (analysis.status === 'complete' || analysis.status === 'error') {
          return analysis;
        }
        attempts++;
        await new Promise((resolve) => setTimeout(resolve, intervalMs));
      } catch (error) {
        attempts++;
        if (attempts >= maxAttempts) throw error;
        await new Promise((resolve) => setTimeout(resolve, intervalMs));
      }
    }

    throw new Error('Analysis polling timeout');
  }

  // Error handler
  private handleError(error: unknown): Error {
    if (axios.isAxiosError(error)) {
      if (error.response) {
        return new Error(error.response.data?.error || error.message);
      }
      return new Error(error.message);
    }
    return error instanceof Error ? error : new Error('Unknown error occurred');
  }
}

export const apiClient = new APIClient();
export default apiClient;
