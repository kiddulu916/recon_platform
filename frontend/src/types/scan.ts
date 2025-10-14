// Scan job types
export type ScanStatus =
  | 'pending'
  | 'running'
  | 'completed'
  | 'failed'
  | 'cancelled';

export type ScanPhase =
  | 'horizontal'
  | 'passive'
  | 'active'
  | 'probing'
  | 'web_discovery'
  | 'recursive';

export interface ScanJob {
  id: number;
  domain_id: number;
  scan_type: string;
  status: ScanStatus;
  current_phase: ScanPhase | null;
  progress_percentage: number;
  started_at: string | null;
  completed_at: string | null;
  errors: string[];
  warnings: string[];
  results_summary: Record<string, any> | null;
  enable_recursion: boolean;
  recursion_depth: number;
  created_at: string;
  updated_at: string;
}

export interface ScanProgress {
  job_id: number;
  status: ScanStatus;
  current_phase: ScanPhase | null;
  progress_percentage: number;
  phase_details: {
    phase: ScanPhase;
    status: string;
    items_processed: number;
    items_total: number;
  } | null;
  errors: string[];
  warnings: string[];
  timestamp: string;
}

export interface ScanResults {
  job_id: number;
  domain_id: number;
  summary: {
    total_subdomains: number;
    active_subdomains: number;
    total_ips: number;
    total_ports: number;
    total_vulnerabilities: number;
    critical_vulnerabilities: number;
    high_vulnerabilities: number;
  };
  subdomains: Subdomain[];
  vulnerabilities: Vulnerability[];
  patterns: Pattern[];
}

import { Subdomain } from './domain';
import { Vulnerability } from './vulnerability';
import { Pattern } from './pattern';
