export interface GraphNode {
  id: string;
  label: string;
  type: 'domain' | 'subdomain' | 'ip' | 'asn' | 'port';
  data: {
    id?: number;
    [key: string]: any;
  };
}

export interface GraphEdge {
  id: string;
  source: string;
  target: string;
  type: 'contains' | 'resolves_to' | 'belongs_to' | 'has_port';
}

export interface GraphData {
  domain_id: number;
  nodes: GraphNode[];
  edges: GraphEdge[];
  statistics: {
    total_nodes: number;
    total_edges: number;
    subdomains: number;
    ips: number;
    asns: number;
    ports: number;
  };
}

export interface GraphFilters {
  include_ips: boolean;
  include_ports: boolean;
  resolves_only: boolean;
}
