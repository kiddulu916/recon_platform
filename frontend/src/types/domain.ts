// Domain and subdomain types
export interface Domain {
  id: number;
  domain: string;
  is_authorized: boolean;
  scan_profile: 'passive' | 'normal' | 'aggressive';
  created_at: string;
  updated_at: string;
}

export interface Subdomain {
  id: number;
  domain_id: number;
  subdomain: string;
  sources: string[];
  discovery_method: string;
  is_active: boolean;
  http_status: number | null;
  https_status: number | null;
  technologies: string[];
  created_at: string;
  updated_at: string;
}

export interface IPAddress {
  id: number;
  ip_address: string;
  asn_id: number | null;
  reverse_dns: string | null;
  is_public: boolean;
  created_at: string;
}

export interface Port {
  id: number;
  ip_address_id: number;
  port_number: number;
  protocol: string;
  service: string | null;
  version: string | null;
  state: string;
  created_at: string;
}

export interface ASN {
  id: number;
  asn: string;
  name: string;
  country: string | null;
  ip_ranges: string[];
  created_at: string;
}
