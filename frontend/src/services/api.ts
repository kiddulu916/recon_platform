import axios, { AxiosError } from 'axios';
import type { AxiosInstance } from 'axios';
import type {
  Domain,
  Subdomain,
  ScanJob,
  ScanResults,
  Vulnerability,
  HTTPTraffic,
  TrafficFilter,
  Pattern,
  VulnerabilityChain,
  AttackGraph,
  PatternStatistics,
  GraphData,
  GraphFilters,
} from '../types';

const API_BASE_URL = import.meta.env.VITE_API_URL || 'http://localhost:8000';

class APIService {
  private client: AxiosInstance;

  constructor() {
    this.client = axios.create({
      baseURL: API_BASE_URL,
      headers: {
        'Content-Type': 'application/json',
      },
    });

    // Request interceptor for adding auth token
    this.client.interceptors.request.use(
      (config) => {
        const token = localStorage.getItem('auth_token');
        if (token) {
          config.headers.Authorization = `Bearer ${token}`;
        }
        return config;
      },
      (error) => Promise.reject(error)
    );

    // Response interceptor for error handling
    this.client.interceptors.response.use(
      (response) => response,
      (error: AxiosError) => {
        if (error.response?.status === 401) {
          // Handle unauthorized - clear token and redirect to login
          localStorage.removeItem('auth_token');
          window.location.href = '/login';
        }
        return Promise.reject(error);
      }
    );
  }

  // Domain Management
  async getDomains(): Promise<Domain[]> {
    const response = await this.client.get<{ domains: Domain[] }>('/api/domains');
    return response.data.domains;
  }

  async getDomain(id: number): Promise<Domain> {
    const response = await this.client.get<Domain>(`/api/domains/${id}`);
    return response.data;
  }

  async createDomain(data: {
    domain: string;
    is_authorized: boolean;
    scan_profile?: string;
  }): Promise<Domain> {
    const response = await this.client.post<Domain>('/api/domains', data);
    return response.data;
  }

  async deleteDomain(id: number): Promise<void> {
    await this.client.delete(`/api/domains/${id}`);
  }

  // Scan Management
  async startScan(data: {
    domain_id: number;
    scan_type: string;
    enable_recursion?: boolean;
  }): Promise<ScanJob> {
    const response = await this.client.post<ScanJob>('/api/scans/start', data);
    return response.data;
  }

  async getScanJob(jobId: number): Promise<ScanJob> {
    const response = await this.client.get<ScanJob>(`/api/scans/${jobId}`);
    return response.data;
  }

  async getScanJobs(domainId?: number): Promise<ScanJob[]> {
    const params = domainId ? { domain_id: domainId } : {};
    const response = await this.client.get<{ scans: ScanJob[]; total: number }>('/api/scans', { params });
    return response.data.scans;
  }

  async getScanResults(jobId: number): Promise<ScanResults> {
    const response = await this.client.get<ScanResults>(`/api/scans/${jobId}/results`);
    return response.data;
  }

  async cancelScan(jobId: number): Promise<void> {
    await this.client.post(`/api/scans/${jobId}/cancel`);
  }

  // Subdomain Management
  async getSubdomains(domainId: number): Promise<Subdomain[]> {
    const response = await this.client.get<{ subdomains: Subdomain[] }>(`/api/domains/${domainId}/subdomains`);
    return response.data.subdomains;
  }

  // Graph Visualization
  async getGraph(domainId: number, filters?: Partial<GraphFilters>): Promise<GraphData> {
    const params = {
      include_ips: filters?.include_ips ?? true,
      include_ports: filters?.include_ports ?? false,
      resolves_only: filters?.resolves_only ?? true,
    };
    const response = await this.client.get<GraphData>(`/api/domains/${domainId}/graph`, { params });
    return response.data;
  }

  // Vulnerability Management
  async getVulnerabilities(domainId: number): Promise<Vulnerability[]> {
    const response = await this.client.get<Vulnerability[]>(`/api/domains/${domainId}/vulnerabilities`);
    return response.data;
  }

  async getVulnerability(id: number): Promise<Vulnerability> {
    const response = await this.client.get<Vulnerability>(`/api/vulnerabilities/${id}`);
    return response.data;
  }

  async updateVulnerability(
    id: number,
    data: Partial<Vulnerability>
  ): Promise<Vulnerability> {
    const response = await this.client.patch<Vulnerability>(`/api/vulnerabilities/${id}`, data);
    return response.data;
  }

  async verifyVulnerability(
    id: number,
    data: { is_verified: boolean; verified_by: string; comments?: string }
  ): Promise<Vulnerability> {
    const response = await this.client.post<Vulnerability>(
      `/api/vulnerabilities/${id}/verify`,
      data
    );
    return response.data;
  }

  async markFalsePositive(
    id: number,
    data: { verified_by: string; comments?: string }
  ): Promise<Vulnerability> {
    const response = await this.client.post<Vulnerability>(
      `/api/vulnerabilities/${id}/false-positive`,
      data
    );
    return response.data;
  }

  // HTTP Traffic Management
  async getTraffic(subdomainId: number, filters?: TrafficFilter): Promise<HTTPTraffic[]> {
    const response = await this.client.get<HTTPTraffic[]>(
      `/api/subdomains/${subdomainId}/traffic`,
      { params: filters }
    );
    return response.data;
  }

  async getTrafficById(id: number): Promise<HTTPTraffic> {
    const response = await this.client.get<HTTPTraffic>(`/api/traffic/${id}`);
    return response.data;
  }

  async searchTraffic(domainId: number, query: string): Promise<HTTPTraffic[]> {
    const response = await this.client.get<HTTPTraffic[]>(
      `/api/domains/${domainId}/traffic/search`,
      { params: { q: query } }
    );
    return response.data;
  }

  // Pattern Recognition
  async analyzePatterns(
    domainId: number,
    options?: {
      enable_temporal?: boolean;
      enable_spatial?: boolean;
      enable_behavioral?: boolean;
      enable_chaining?: boolean;
    }
  ): Promise<any> {
    const response = await this.client.post(
      `/api/patterns/analyze/${domainId}`,
      null,
      { params: options }
    );
    return response.data;
  }

  async getTemporalPatterns(domainId: number): Promise<Pattern[]> {
    const response = await this.client.get<Pattern[]>(`/api/patterns/temporal/${domainId}`);
    return response.data;
  }

  async getSpatialPatterns(domainId: number): Promise<Pattern[]> {
    const response = await this.client.get<Pattern[]>(`/api/patterns/spatial/${domainId}`);
    return response.data;
  }

  async getBehavioralPatterns(domainId: number): Promise<Pattern[]> {
    const response = await this.client.get<Pattern[]>(`/api/patterns/behavioral/${domainId}`);
    return response.data;
  }

  async getVulnerabilityChains(domainId: number): Promise<VulnerabilityChain[]> {
    const response = await this.client.get<VulnerabilityChain[]>(`/api/patterns/chains/${domainId}`);
    return response.data;
  }

  async getVulnerabilityChain(domainId: number, chainId: number): Promise<VulnerabilityChain> {
    const response = await this.client.get<VulnerabilityChain>(
      `/api/patterns/chains/${domainId}/${chainId}`
    );
    return response.data;
  }

  async verifyChain(
    domainId: number,
    chainId: number,
    data: { verified: boolean; verified_by: string; notes?: string }
  ): Promise<VulnerabilityChain> {
    const response = await this.client.post<VulnerabilityChain>(
      `/api/patterns/chains/${domainId}/${chainId}/verify`,
      data
    );
    return response.data;
  }

  async getAttackGraph(domainId: number): Promise<AttackGraph> {
    const response = await this.client.get<AttackGraph>(`/api/patterns/attack-graph/${domainId}`);
    return response.data;
  }

  async getPatternStatistics(domainId: number): Promise<PatternStatistics> {
    const response = await this.client.get<PatternStatistics>(
      `/api/patterns/statistics/${domainId}`
    );
    return response.data;
  }

  // Tool Management
  async getToolStatus(): Promise<Record<string, boolean>> {
    const response = await this.client.get<Record<string, boolean>>('/api/tools/status');
    return response.data;
  }

  async installTools(): Promise<any> {
    const response = await this.client.post('/api/tools/install');
    return response.data;
  }
}

export const apiService = new APIService();
export default apiService;
