// Pattern recognition types
export type PatternType =
  | 'temporal'
  | 'spatial'
  | 'behavioral';

export interface Pattern {
  id: number;
  domain_id: number;
  pattern_type: PatternType;
  pattern_name: string;
  description: string;
  risk_level: string;
  confidence_score: number;
  affected_assets: number[];
  pattern_data: Record<string, any>;
  created_at: string;
}

export interface VulnerabilityChain {
  id: number;
  domain_id: number;
  chain_name: string;
  description: string;
  severity: string;
  risk_score: number;
  feasibility: number;
  impact_score: number;
  chain_length: number;
  chain_steps: ChainStep[];
  exploitation_scenario: ExploitationScenario;
  is_verified: boolean;
  is_false_positive: boolean;
  verified_by: string | null;
  verified_at: string | null;
  created_at: string;
}

export interface ChainStep {
  step_number: number;
  vulnerability_id: number;
  vulnerability_type: string;
  action: string;
  expected_result: string;
  provides: string[];
  requires: string[];
}

export interface ExploitationScenario {
  description: string;
  required_skills: string;
  estimated_time: string;
  detection_difficulty: string;
  steps: ChainStep[];
}

export interface AttackGraph {
  nodes: AttackGraphNode[];
  edges: AttackGraphEdge[];
}

export interface AttackGraphNode {
  id: string;
  type: 'vulnerability' | 'asset' | 'pattern';
  label: string;
  severity?: string;
  risk_score?: number;
}

export interface AttackGraphEdge {
  source: string;
  target: string;
  relationship: string;
  weight: number;
}

export interface PatternStatistics {
  total_patterns: number;
  total_chains: number;
  pattern_by_category: Record<string, number>;
  pattern_by_risk: Record<string, number>;
  chains_by_severity: Record<string, number>;
}
