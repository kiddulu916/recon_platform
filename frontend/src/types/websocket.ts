// WebSocket message types
export type WebSocketMessageType =
  | 'scan_progress'
  | 'subdomain_discovered'
  | 'vulnerability_detected'
  | 'pattern_found'
  | 'scan_completed'
  | 'scan_failed'
  | 'connection_established'
  | 'error';

export interface WebSocketMessage<T = any> {
  type: WebSocketMessageType;
  data: T;
  timestamp: string;
}

export interface SubdomainDiscoveredMessage {
  domain_id: number;
  subdomain: string;
  subdomain_id: number;
  discovery_method: string;
  sources: string[];
}

export interface VulnerabilityDetectedMessage {
  domain_id: number;
  vulnerability_id: number;
  subdomain: string;
  vulnerability_type: string;
  severity: string;
  name: string;
}

export interface PatternFoundMessage {
  domain_id: number;
  pattern_id: number;
  pattern_type: string;
  pattern_name: string;
  risk_level: string;
}

export interface ScanCompletedMessage {
  job_id: number;
  domain_id: number;
  duration_seconds: number;
  summary: Record<string, any>;
}

export interface ScanFailedMessage {
  job_id: number;
  domain_id: number;
  error: string;
}
