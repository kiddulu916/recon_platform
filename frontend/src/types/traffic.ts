// HTTP traffic types
export interface HTTPTraffic {
  id: number;
  subdomain_id: number;
  method: string;
  url: string;
  request_headers: Record<string, string>;
  request_body: string | null;
  response_status: number;
  response_headers: Record<string, string>;
  response_body: string | null;
  content_type: string | null;
  response_time_ms: number;
  captured_at: string;
  context_tags: string[];
}

export interface APIEndpoint {
  id: number;
  subdomain_id: number;
  endpoint_path: string;
  http_method: string;
  api_type: string | null;
  parameters: string[];
  authentication_required: boolean;
  discovered_from: string;
  created_at: string;
}

export interface TrafficFilter {
  method?: string[];
  status_code?: number[];
  content_type?: string[];
  url_pattern?: string;
  body_search?: string;
  date_from?: string;
  date_to?: string;
  subdomain_id?: number;
}

export interface TrafficStatistics {
  total_requests: number;
  unique_urls: number;
  unique_endpoints: number;
  status_codes: Record<number, number>;
  methods: Record<string, number>;
  avg_response_time: number;
}
