# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

Security Reconnaissance Platform - A comprehensive subdomain enumeration and reconnaissance platform that integrates 20+ external security tools for intelligent vulnerability discovery through horizontal and vertical enumeration techniques.

**IMPORTANT**: This is a defensive security tool. Only assist with authorized security testing. All modifications must respect ethical security practices.

## Getting Started

### Running the Application

```bash
# Activate virtual environment
source recon_env/bin/activate  # On Windows: recon_env\Scripts\activate

# Start the platform
python main.py
```

The application starts on `http://localhost:8000` with interactive API docs at `/docs`.

### Database Migrations

The platform uses SQLAlchemy with async support. Database is auto-initialized on startup.

### Installing External Tools

```bash
# After starting the application
curl -X POST http://localhost:8000/api/tools/install

# Check tool status
curl http://localhost:8000/api/tools/status
```

Required external tools include subfinder, assetfinder, naabu, httpx, dnsx, mapcidr, puredns, gotator, and others.

## Architecture

### Core Design Principles

1. **Tool-First Approach**: Leverage battle-tested external security tools via subprocess execution
2. **Async Orchestration**: AsyncIO-based coordination with rate limiting
3. **Modular Phases**: Each enumeration phase is independent (horizontal → passive → active → probing → recursive)
4. **Database-Centric**: Results persisted immediately for crash recovery
5. **Graceful Degradation**: Missing tools are logged; workflow continues with available tools

### Directory Structure

```
app/
├── core/                   # Core infrastructure
│   ├── config.py          # Configuration management (SecurityConfig, DatabaseConfig, ScannerConfig)
│   ├── database.py        # Async database connection pooling
│   ├── logging.py         # Structured logging with structlog
│   └── security.py        # API key encryption (Fernet)
│
├── models/                 # SQLAlchemy ORM models
│   ├── domain.py          # Domain, Subdomain, FaviconHash
│   ├── network.py         # ASN, IPAddress, Port, SubdomainIP
│   ├── company.py         # Company, CompanyAcquisition
│   ├── http_traffic.py    # HTTPTraffic, APIEndpoint
│   ├── vulnerability.py   # Vulnerability tracking (Phase 4)
│   └── scan.py           # ScanJob lifecycle tracking
│
├── scanner/                # Scanner modules
│   ├── engine.py          # Main orchestrator coordinating all scan phases
│   ├── job_manager.py     # Scan job lifecycle and background execution
│   ├── rate_limiter.py    # Token bucket rate limiting (global + per-domain)
│   ├── dedup.py           # Bloom filter deduplication
│   │
│   ├── horizontal/        # Horizontal enumeration (company → ASN → IP ranges)
│   │   ├── acquisitions.py    # Company acquisition discovery (WhoIsXMLAPI)
│   │   ├── asn_lookup.py      # ASN and IP range enumeration (bgp.he.net)
│   │   ├── reverse_dns.py     # PTR record enumeration (mapcidr + dnsx)
│   │   └── favicon_hash.py    # Favicon-based tech fingerprinting
│   │
│   ├── vertical/          # Vertical enumeration (subdomain discovery)
│   │   ├── passive/       # Passive subdomain enumeration
│   │   │   ├── subfinder.py   # Subfinder wrapper
│   │   │   ├── assetfinder.py # Assetfinder wrapper
│   │   │   ├── amass.py       # Amass passive mode
│   │   │   └── ct_logs.py     # Certificate Transparency (crt.sh, Censys, BufferOver)
│   │   └── active/        # Active subdomain enumeration
│   │       ├── dns_bruteforce.py  # PureDNS with wordlists
│   │       └── permutations.py    # GoTator permutation generation
│   │
│   ├── probing/           # Web probing and intelligent discovery
│   │   ├── port_scanner.py            # Naabu/Nmap port scanning
│   │   ├── http_prober.py             # Httpx HTTP probing
│   │   ├── intelligent_crawler.py     # Stateful web crawler with pattern learning
│   │   ├── directory_enumeration.py   # Context-aware directory/file enumeration
│   │   ├── api_discovery.py           # Multi-approach API endpoint discovery
│   │   └── web_discovery_orchestrator.py  # Coordinates all web discovery modules
│   │
│   ├── recursive/         # Recursive enumeration on newly discovered domains
│   │
│   ├── interception/      # Phase 3: HTTP traffic interception (mitmproxy)
│   │   ├── interceptor.py         # mitmproxy addon for traffic capture
│   │   ├── context_manager.py     # Thread-safe context tagging
│   │   ├── wal.py                 # Write-Ahead Log for resilient storage
│   │   ├── processor.py           # Background WAL → database processor
│   │   ├── storage_manager.py     # Batch database insertion
│   │   ├── stream_analyzer.py     # Real-time vulnerability pattern matching
│   │   ├── alerting.py            # Alert generation and webhook delivery
│   │   └── analyzers/
│   │       ├── url_extractor.py           # Extract URLs from HTML/JS/JSON
│   │       ├── api_detector.py            # Detect REST/GraphQL APIs
│   │       └── sensitive_data_scanner.py  # Pattern matching for secrets
│   │
│   └── tools/             # External tool management
│       ├── installer.py   # Tool installation and verification
│       └── base.py        # ToolWrapper abstract base class
│
└── api/                    # FastAPI routes
    ├── routes.py          # Domain, scan, results endpoints
    └── interception_routes.py  # HTTP traffic inspection endpoints
```

### Scan Workflow Phases

**Complete scan flow**: Horizontal → Passive → Active → Probing → Web Discovery → Recursive (optional)

1. **Horizontal Enumeration**: Company acquisitions → ASN lookup → Reverse DNS → Favicon hashing
2. **Passive Enumeration**: Subfinder, assetfinder, amass, Certificate Transparency logs
3. **Active Enumeration**: DNS brute-forcing (PureDNS + 3M wordlist), permutations (GoTator), JS scraping
4. **Web Probing**: Port scanning (Naabu + Nmap), HTTP probing (Httpx)
5. **Intelligent Web Discovery** (optional, enable with `ENABLE_WEB_DISCOVERY=true`):
   - **Intelligent Crawling**: Stateful application modeling, URL pattern recognition, smart parameter fuzzing
   - **Context-Aware Directory Enumeration**: Technology-specific wordlists, learning from discoveries
   - **Advanced API Discovery**: Static JS analysis, dynamic observation, documentation parsing, GraphQL introspection
6. **Recursive Enumeration**: Repeat workflow on newly discovered subdomains (configurable depth)

All phases use:
- **Deduplication**: Multi-level (Bloom filter + database queries)
- **Rate Limiting**: Token bucket algorithm with configurable profiles (passive, normal, aggressive)
- **Source Tracking**: Each subdomain tracks all discovery sources for confidence scoring

### Phase 3: HTTP Traffic Interception System

Uses mitmproxy for HTTPS interception with:
- **Write-Ahead Log (WAL)**: msgpack-serialized immediate persistence before structured storage
- **Background Processor**: Async queue processing WAL → database (100 records/batch)
- **Stream Analyzer**: Real-time vulnerability pattern matching (SQL injection, XSS, SSRF, command injection)
- **Content Analyzers**: URL extraction, API endpoint detection, sensitive data scanning
- **Alert Manager**: Deduplication, severity classification, webhook delivery

### Database Models

Key relationships:
```
Company → Domain → Subdomain → FaviconHash
                            → HTTPTraffic
                            → IPAddress → ASN
                                       → Port
ScanJob → Domain
```

All models use async SQLAlchemy. Connection pooling configured in `app/core/database.py`.

### Tool Integration Pattern

External tools run via subprocess with:
1. Path verification and installation check
2. Async subprocess execution with timeout
3. Stream parsing (line-by-line, no full buffering)
4. Result deduplication via Bloom filter
5. Batch database insertion
6. Error handling with graceful degradation

See `app/scanner/tools/base.py` for `ToolWrapper` abstract class.

## Configuration

Environment variables in `.env` (see `.env.example`):

**Critical settings**:
- `DATABASE_URL`: SQLite (dev) or PostgreSQL (production)
- `SCAN_PROFILE`: `passive`, `normal`, or `aggressive`
- `GLOBAL_RATE_LIMIT` / `DOMAIN_RATE_LIMIT`: Requests per second
- `JWT_SECRET_KEY`: Authentication (required)
- `ENCRYPTION_ENABLED`: Encrypt stored API keys (default: true)

**Scan profiles**:
| Profile | Global Rate | Domain Rate | Description |
|---------|-------------|-------------|-------------|
| passive | 1 req/s | 0.5 req/s | No direct target interaction |
| normal | 10 req/s | 5 req/s | Balanced scanning |
| aggressive | 50 req/s | 20 req/s | Fast scanning for authorized tests |

**Phase toggles**:
- `ENABLE_HORIZONTAL`, `ENABLE_PASSIVE`, `ENABLE_ACTIVE`, `ENABLE_WEB_PROBING`
- `ENABLE_RECURSION`, `RECURSION_DEPTH`
- `ENABLE_WEB_DISCOVERY`: Enable intelligent web discovery (crawling, directory enumeration, API discovery)

Advanced configuration via `config/default.yaml`.

## API Usage

### Starting a Scan

```bash
# 1. Add target domain
curl -X POST http://localhost:8000/api/domains \
  -H "Content-Type: application/json" \
  -d '{"domain": "example.com", "is_authorized": true, "scan_profile": "normal"}'

# 2. Start full scan
curl -X POST http://localhost:8000/api/scans/start \
  -H "Content-Type: application/json" \
  -d '{"domain_id": 1, "scan_type": "full", "enable_recursion": false}'

# 3. Check status
curl http://localhost:8000/api/scans/{job_id}

# 4. Get results
curl http://localhost:8000/api/scans/{job_id}/results
```

### Managing API Keys

```bash
# Store encrypted API key
curl -X POST http://localhost:8000/api/config/api-keys/whoisxml \
  -H "Content-Type: application/json" \
  -d '{"api_key": "your-api-key"}'

# List services with stored keys
curl http://localhost:8000/api/config/api-keys
```

API keys stored encrypted in `data/api_keys/` using Fernet symmetric encryption.

### WebSocket API for Real-Time Updates

The platform provides WebSocket support for real-time scan progress updates:

```bash
# Connect to WebSocket (global updates)
wscat -c ws://localhost:8000/ws

# Connect to WebSocket (domain-specific updates)
wscat -c "ws://localhost:8000/ws?domain_id=1"

# Check WebSocket connection statistics
curl http://localhost:8000/ws/status
```

**WebSocket Message Types**:

Clients receive JSON messages with the following structure:
```json
{
  "type": "message_type",
  "data": { /* message-specific data */ },
  "timestamp": "2025-10-14T10:00:00Z"
}
```

**Message Types Sent by Server**:

- `connection_established`: WebSocket connection confirmed
- `scan_progress`: Real-time scan progress updates (status, phase, percentage, errors, warnings)
- `subdomain_discovered`: New subdomain found during enumeration
- `vulnerability_detected`: New vulnerability detected
- `pattern_found`: Pattern recognition result
- `scan_completed`: Scan finished successfully with summary
- `scan_failed`: Scan encountered an error

**Frontend Integration**:

The WebSocket service (`app/api/websocket.py`) can be used from the scanner to broadcast updates:

```python
from app.api.websocket import ws_manager

# Broadcast scan progress
await ws_manager.broadcast_scan_progress(domain_id, {
    "job_id": scan_job.id,
    "status": "running",
    "current_phase": "passive",
    "progress_percentage": 45
})

# Broadcast subdomain discovery
await ws_manager.broadcast_subdomain_discovered(domain_id, {
    "subdomain": "api.example.com",
    "subdomain_id": 123,
    "discovery_method": "subfinder",
    "sources": ["crt.sh", "threatcrowd"]
})

# Broadcast vulnerability detection
await ws_manager.broadcast_vulnerability_detected(domain_id, {
    "vulnerability_id": 456,
    "subdomain": "admin.example.com",
    "vulnerability_type": "sql_injection",
    "severity": "critical",
    "name": "SQL Injection in /admin/search"
})
```

### Real-Time Scanning Dashboard

The platform includes a comprehensive real-time dashboard built with React and WebSocket integration for live monitoring of reconnaissance operations.

**Frontend Location**: `frontend/src/`

**Key Components**:

1. **useWebSocket Hook** (`frontend/src/hooks/useWebSocket.ts`):
   - Custom React hook for WebSocket connection management
   - Auto-connect/disconnect on component mount/unmount
   - Reconnection logic with exponential backoff
   - Subscribe/unsubscribe to message types
   - Connection status tracking

   ```typescript
   import { useWebSocket } from '../hooks/useWebSocket';

   const { isConnected, subscribe } = useWebSocket({
     domainId: 1,  // Optional: filter by domain
     autoConnect: true
   });

   useEffect(() => {
     const unsubscribe = subscribe('scan_progress', (data) => {
       console.log('Scan progress:', data);
     });
     return unsubscribe;
   }, [subscribe]);
   ```

2. **LiveStatsCards Component** (`frontend/src/components/dashboard/LiveStatsCards.tsx`):
   - Real-time statistics cards with animated updates
   - Tracks: Total subdomains, running scans, vulnerabilities, critical vulns
   - Visual pulse animation on new discoveries
   - Auto-increments counters based on WebSocket events

3. **LiveScanProgress Component** (`frontend/src/components/dashboard/LiveScanProgress.tsx`):
   - Displays all running scans with real-time progress
   - Progress bars with percentage and phase information
   - Phase-specific details (items processed, status)
   - Error and warning display
   - Links to scan detail pages
   - Connection status indicator

4. **LiveSubdomainFeed Component** (`frontend/src/components/dashboard/LiveSubdomainFeed.tsx`):
   - Live feed of subdomain discoveries as they happen
   - Displays subdomain, discovery method, and sources
   - Color-coded badges for different discovery methods
   - Smooth fade-in animations for new entries
   - Scrollable feed with configurable max items (default: 50)
   - Timestamps for each discovery

5. **LiveVulnerabilityFeed Component** (`frontend/src/components/dashboard/LiveVulnerabilityFeed.tsx`):
   - Real-time vulnerability detection alerts
   - Severity-based color coding (critical, high, medium, low)
   - Severity icons and gradient backgrounds
   - Shows vulnerability type, affected subdomain, and name
   - Critical and high severity counters in header
   - Links to vulnerability details
   - Scrollable feed with configurable max items (default: 20)

**Dashboard Page** (`frontend/src/pages/Dashboard.tsx`):
- Integrates all live components into a unified view
- Two-column layout for subdomain and vulnerability feeds
- Real-time statistics at the top
- Connection status indicators
- Responsive grid layout (mobile-friendly)

**WebSocket Message Handling**:

The dashboard automatically handles these WebSocket message types:

- `scan_progress`: Updates scan progress bars and status
- `subdomain_discovered`: Adds to live subdomain feed
- `vulnerability_detected`: Adds to vulnerability feed, updates counters
- `pattern_found`: Can be extended for pattern notifications
- `scan_completed`: Removes from running scans, updates statistics
- `scan_failed`: Removes from running scans, shows error

**Running the Frontend**:

```bash
cd frontend

# Install dependencies
npm install

# Start development server (with hot reload)
npm run dev

# Build for production
npm run build
```

Frontend runs on `http://localhost:5173` (Vite default) and proxies API/WebSocket requests to backend.

**Environment Configuration** (`frontend/.env`):
```bash
VITE_API_URL=http://localhost:8000
VITE_WS_URL=ws://localhost:8000
```

**Features**:
- ✅ Automatic WebSocket reconnection with exponential backoff
- ✅ Real-time progress tracking for all running scans
- ✅ Live subdomain discoveries with source attribution
- ✅ Instant vulnerability alerts with severity classification
- ✅ Smooth animations and visual feedback
- ✅ Responsive design (mobile, tablet, desktop)
- ✅ Dark mode support
- ✅ Connection status monitoring
- ✅ Error handling and graceful degradation

**Browser Compatibility**:
- Chrome/Edge 90+
- Firefox 88+
- Safari 14+
- Any modern browser with WebSocket support

### Infrastructure Graph Visualization

The platform includes an interactive network graph visualization to explore domain infrastructure, subdomains, IP addresses, ASNs, and their relationships using Cytoscape.js.

**Access**: Navigate to `/graph` or click "Infrastructure Graph" in the navigation menu.

**Backend API Endpoint** (`app/api/routes.py`):
```bash
# Get graph data for a domain
curl "http://localhost:8000/api/domains/{domain_id}/graph?include_ips=true&include_ports=false&resolves_only=true"
```

**Query Parameters**:
- `include_ips` (bool): Include IP address nodes (default: true)
- `include_ports` (bool): Include port nodes (default: false)
- `resolves_only` (bool): Only include resolving subdomains (default: true)

**Response Structure**:
```json
{
  "domain_id": 1,
  "nodes": [
    {
      "id": "domain-1",
      "label": "example.com",
      "type": "domain",
      "data": { "id": 1, "domain": "example.com", ... }
    },
    {
      "id": "subdomain-123",
      "label": "api.example.com",
      "type": "subdomain",
      "data": { "id": 123, "subdomain": "api.example.com", ... }
    },
    {
      "id": "ip-456",
      "label": "192.0.2.1",
      "type": "ip",
      "data": { "id": 456, "ip": "192.0.2.1", "asn": 15169, ... }
    }
  ],
  "edges": [
    {
      "id": "edge-domain-1-subdomain-123",
      "source": "domain-1",
      "target": "subdomain-123",
      "type": "contains"
    },
    {
      "id": "edge-subdomain-123-ip-456",
      "source": "subdomain-123",
      "target": "ip-456",
      "type": "resolves_to"
    }
  ],
  "statistics": {
    "total_nodes": 25,
    "total_edges": 32,
    "subdomains": 18,
    "ips": 5,
    "asns": 2,
    "ports": 0
  }
}
```

**Node Types**:
- **Domain** (blue, round-rectangle): Root domain node
- **Subdomain** (green, ellipse): Discovered subdomains
- **IP Address** (orange, rectangle): IP addresses resolved from subdomains
- **ASN** (purple, hexagon): Autonomous System Numbers
- **Port** (red, diamond): Open ports (when enabled)

**Edge Types**:
- **contains** (blue, solid): Domain → Subdomain relationship
- **resolves_to** (green, dashed): Subdomain → IP relationship
- **belongs_to** (purple, dotted): IP → ASN relationship
- **has_port** (red, solid): IP → Port relationship

**Frontend Components**:

1. **InfrastructureGraph Component** (`frontend/src/components/graph/InfrastructureGraph.tsx`):
   - Interactive Cytoscape.js graph visualization
   - Node selection with detailed info panel
   - Graph controls (Fit, Center, Reset zoom)
   - Color-coded nodes by type
   - Responsive canvas with dark mode support
   - Interactive node exploration with click events

2. **InfrastructureGraph Page** (`frontend/src/pages/InfrastructureGraph.tsx`):
   - Domain selector dropdown
   - Graph filters (include IPs, ports, resolving only)
   - Real-time statistics display
   - Empty state handling
   - Loading and error states

**Features**:
- ✅ Interactive pan and zoom
- ✅ Node click to view details
- ✅ Breadthfirst layout algorithm
- ✅ Visual node type differentiation
- ✅ Relationship type visualization
- ✅ Filter controls for customization
- ✅ Statistics dashboard
- ✅ Responsive design
- ✅ Dark mode support

**Usage**:

```typescript
// Frontend API call
import apiService from '../services/api';

const graphData = await apiService.getGraph(domainId, {
  include_ips: true,
  include_ports: false,
  resolves_only: true
});

// Use in component
<InfrastructureGraph
  data={graphData}
  height="700px"
  onNodeClick={(node) => console.log('Clicked:', node)}
/>
```

**Use Cases**:
- Visualize domain infrastructure at a glance
- Identify shared IP addresses across subdomains
- Explore ASN relationships and hosting patterns
- Discover infrastructure clusters
- Analyze subdomain distribution
- Identify potential takeover candidates (non-resolving subdomains)
- Map attack surface visually

**Dependencies**:
- Backend: No additional dependencies (uses existing SQLAlchemy models)
- Frontend: `cytoscape` and `@types/cytoscape` (installed via npm)

### Pattern Recognition and Vulnerability Chaining API

Phase 6 provides advanced pattern recognition and vulnerability chaining through dedicated API endpoints:

```bash
# Run complete pattern recognition analysis
curl -X POST "http://localhost:8000/api/patterns/analyze/1?enable_temporal=true&enable_spatial=true&enable_behavioral=true&enable_chaining=true" \
  -H "Content-Type: application/json"

# Get temporal patterns (time-based behaviors)
curl "http://localhost:8000/api/patterns/temporal/1?min_confidence=0.7&limit=50"

# Get spatial patterns (infrastructure relationships)
curl "http://localhost:8000/api/patterns/spatial/1?min_confidence=0.7"

# Get behavioral patterns (anomalies)
curl "http://localhost:8000/api/patterns/behavioral/1?pattern_type=response_time_anomaly"

# Get vulnerability chains
curl "http://localhost:8000/api/patterns/chains/1?severity=critical&min_risk_score=70"

# Get specific chain details
curl "http://localhost:8000/api/patterns/chains/1/5"

# Get predictive analysis (testing guidance)
curl "http://localhost:8000/api/patterns/predictions/1?min_priority=7"

# Get attack graph
curl "http://localhost:8000/api/patterns/attack-graph/1"

# Get comprehensive statistics
curl "http://localhost:8000/api/patterns/statistics/1"

# Verify a vulnerability chain
curl -X POST "http://localhost:8000/api/patterns/chains/1/5/verify" \
  -H "Content-Type: application/json" \
  -d '{"verified": true, "verified_by": "analyst@company.com", "notes": "Manually verified"}'

# Mark chain as false positive
curl -X POST "http://localhost:8000/api/patterns/chains/1/5/false-positive" \
  -H "Content-Type: application/json" \
  -d '{"is_false_positive": true, "verified_by": "analyst@company.com", "notes": "WAF blocking"}'
```

**Pattern Types**:

- **Temporal**: `auth_weakness_timing`, `rate_limit_variation`, `time_based_behavior`
- **Spatial**: `shared_authentication`, `shared_infrastructure`, `technology_cluster`, `shared_session`
- **Behavioral**: `response_time_anomaly`, `error_information_disclosure`, `input_reflection`, `status_code_anomaly`, `response_size_anomaly`, `security_header_misconfiguration`

**Chain Severities**: `critical`, `high`, `medium`, `low`

**Attack Goals**: `account_takeover`, `data_exfiltration`, `rce`, `privilege_escalation`, `infrastructure_compromise`

## Intelligent Web Discovery System

The platform includes advanced web discovery capabilities that go beyond simple crawling:

### Intelligent Crawler (`app/scanner/probing/intelligent_crawler.py`)

**Stateful Application Modeling**:
- Learns URL patterns and parameter structures (e.g., `/api/v1/users/123` → tries other IDs/versions)
- Identifies routing schemes (REST, MVC, GraphQL)
- Tracks authentication requirements per path
- Understands which parameters affect application behavior
- Generates smart variations based on discovered patterns

**Key Features**:
- Pattern recognition for IDs (numeric, UUID, hash, slug)
- API version detection and testing
- Resource relationship mapping
- Adaptive exploration strategy (learns what works, explores similar patterns)

**Usage**:
```python
from app.scanner.probing.intelligent_crawler import IntelligentCrawler

crawler = IntelligentCrawler(config, rate_limiter, http_session)
results = await crawler.crawl(db_session, base_url, subdomain_id, max_depth=5, max_pages=1000)
# Returns: URL patterns, routing scheme, API versions, auth-required paths
```

### Context-Aware Directory Enumeration (`app/scanner/probing/directory_enumeration.py`)

**Technology-Specific Wordlists**:
- Detects technologies (WordPress, Spring Boot, Django, Laravel, ASP.NET, Node.js, React)
- Uses technology-specific paths (e.g., `/actuator` for Spring Boot, `/wp-admin` for WordPress)
- Adapts wordlist based on detected frameworks

**Learning Engine**:
- Found `/admin`? Automatically tries `/administrator`, `/admin-console`, `/admin-panel`
- Found `/api/v1`? Tries `/api/v2`, `/api/v3`
- Found `/config.json`? Tries `/config.yaml`, `/config.xml`, `/config.bak`
- Learns patterns and generates related paths

**Built-in Technology Profiles**:
- WordPress: 20+ specific paths including plugins, themes, config files
- Spring Boot: Actuator endpoints, Swagger docs, API versions
- Django: Admin panels, API endpoints, static/media paths
- Laravel: Storage paths, .env files, telescope, horizon
- ASP.NET: Web.config, trace.axd, ViewState patterns
- Node.js: package.json, .env, API endpoints

**Usage**:
```python
from app.scanner.probing.directory_enumeration import ContextAwareDirectoryEnumerator

enumerator = ContextAwareDirectoryEnumerator(config, rate_limiter, http_session)
results = await enumerator.enumerate(db_session, base_url, subdomain_id, initial_paths=[])
# Returns: Discovered paths, detected technologies, learning statistics
```

### Advanced API Discovery (`app/scanner/probing/api_discovery.py`)

**Multi-Approach Discovery**:

1. **Static Analysis**: Parses JavaScript files for API calls
   - fetch(), axios, XMLHttpRequest patterns
   - URL patterns in strings
   - Import/require statements

2. **Dynamic Analysis**: Observes API calls during crawling
   - Monitors HTTP traffic
   - Identifies API patterns from content-type and responses

3. **Documentation Discovery**: Finds and parses API specs
   - OpenAPI/Swagger (JSON/YAML)
   - GraphQL endpoints and introspection
   - API documentation paths

4. **GraphQL Introspection**: Queries GraphQL schema
   - Discovers types, fields, mutations
   - Maps complete API surface

5. **Pattern Recognition**: Generates variations
   - Tests different API versions
   - Probes HTTP methods (GET, POST, PUT, DELETE, PATCH)
   - Generates resource-based endpoints

**API Documentation Paths Checked**:
- `/swagger`, `/swagger.json`, `/swagger-ui.html`
- `/openapi.json`, `/openapi.yaml`
- `/api-docs`, `/v2/api-docs`, `/v3/api-docs`
- `/graphql`, `/graphiql`
- `/redoc`, `/rapidoc`

**JavaScript Analysis**:
- Analyzes up to 50 JS files per subdomain
- Extracts API endpoints from common patterns
- Tests discovered endpoints for existence
- Probes HTTP methods on 405 responses

**Usage**:
```python
from app.scanner.probing.api_discovery import APIDiscoveryEngine

api_engine = APIDiscoveryEngine(config, rate_limiter, http_session)
results = await api_engine.discover(db_session, base_url, subdomain_id, observed_traffic=traffic)
# Returns: Discovered APIs with methods, types, parameters, auth requirements
```

### Web Discovery Orchestrator (`app/scanner/probing/web_discovery_orchestrator.py`)

Coordinates all web discovery modules in optimal order:

1. **Intelligent Crawling**: Maps application structure
2. **Directory Enumeration**: Uses findings from crawl to seed wordlist
3. **API Discovery**: Analyzes observed traffic + static analysis

**Usage**:
```python
from app.scanner.probing.web_discovery_orchestrator import WebDiscoveryOrchestrator

orchestrator = WebDiscoveryOrchestrator(config, rate_limiter)
results = await orchestrator.discover(
    db_session,
    subdomain_id,
    base_url,
    enable_crawling=True,
    enable_directory_enum=True,
    enable_api_discovery=True,
    max_crawl_depth=5,
    max_crawl_pages=1000
)
# Returns: Comprehensive discovery results with summary
```

**Integration with Scanner Engine**:

Web discovery is automatically enabled during the web probing phase if `ENABLE_WEB_DISCOVERY=true` is set. It runs on the top 10 subdomains with HTTP/HTTPS enabled, limiting to 3 depth and 500 pages per subdomain to prevent overwhelming targets.

## Phase 5: AI-Powered Vulnerability Intelligence

Transforms collected data into actionable security intelligence through machine learning and rule-based systems:

### Vulnerability Correlation Engine (`app/intelligence/correlation_engine.py`)

**Dual-Mode Detection**:

**Rule-Based Detector**:
- **Version-Based**: Matches product versions against CVE database (Apache < 2.4.50, OpenSSL Heartbleed, etc.)
- **Signature-Based**: Pattern matching for SQL injection, XSS, XXE, SSRF, LFI, RCE
- **Configuration Issues**: Debug mode, directory listing, stack traces, exposed sensitive files

**ML-Based Detector**:
- **Anomaly Detection**: Identifies unusual response times, sizes, status codes, headers
- **Baseline Learning**: Builds "normal" behavior model for each subdomain
- **Pattern Recognition**: Flags deviations that warrant investigation

**Usage**:
```python
from app.intelligence.correlation_engine import VulnerabilityCorrelationEngine

engine = VulnerabilityCorrelationEngine()
vulnerabilities = await engine.analyze_http_traffic(traffic, db_session)
# Returns: List of detected vulnerabilities with confidence scores
```

### Exploit Matching System (`app/intelligence/exploit_matcher.py`)

**Multi-Source Exploit Database**:
- Synchronized from ExploitDB, PacketStorm, Metasploit
- CVE-to-exploit mapping
- Platform, application, and version matching

**Intelligent Scoring**:
- **Reliability** (30%): Excellent, Good, Average, Low
- **Impact** (25%): RCE > Privilege Escalation > Info Disclosure
- **Complexity** (15%): Low complexity = higher score
- **Verification** (15%): Verified exploits score higher
- **Code Availability** (10%): Bonus for available exploit code
- **Platform Match** (5%): Matches target platform

**Prerequisite Analysis**:
- Checks authentication requirements
- Evaluates exploitation complexity
- Considers platform dependencies
- Reduces score for complex prerequisites

**Usage**:
```python
from app.intelligence.exploit_matcher import ExploitMatcher

matcher = ExploitMatcher(config)
exploits = await matcher.match_exploits(vulnerability, db_session)
# Returns: Scored exploits sorted by relevance and reliability

# Sync databases
stats = await matcher.sync_exploit_database(db_session)
cve_stats = await matcher.sync_cve_database(db_session)
```

### Intelligent Risk Scoring (`app/intelligence/risk_scorer.py`)

**Multi-Dimensional Scoring**:

**1. Technical Risk (40%)**:
- CVSS score (40%)
- Exploit availability (30%)
- Exploit reliability (20%)
- Attack complexity (10%)

**2. Environmental Risk (35%)**:
- Exposure (40%): Public internet vs internal network
- Asset criticality (35%): Production API vs development server
- Data sensitivity (25%): User data, payment info, credentials

**3. Contextual Risk (25%)**:
- Authentication requirements (penalty)
- Network access requirements
- User interaction requirements (penalty)
- Business impact
- Compliance/regulatory impact

**AI-Powered Adjustments**:
- Learns from user feedback
- Adjusts scores based on false positive rates
- Environment-specific calibration
- Confidence scoring based on historical accuracy

**Risk Categories**:
- Critical: 90-100
- High: 70-89
- Medium: 40-69
- Low: 0-39

**Usage**:
```python
from app.intelligence.risk_scorer import RiskScorer

scorer = RiskScorer(config)
risk_score = await scorer.calculate_risk(vulnerability, db_session)
# Returns: RiskScore with detailed scoring breakdown

# Recalculate all risks (after learning updates)
stats = await scorer.recalculate_all_risks(db_session, domain_id=None)
```

### Pattern Learning System (`app/intelligence/pattern_learner.py`)

**Learning from Feedback**:
- Tracks true positives vs false positives
- Automatically adjusts confidence thresholds
- Retrains patterns when enough feedback collected (min 20 samples)
- Calculates precision, recall, F1 scores

**Adaptive Thresholds**:
- High FP rate (< 60% precision) → Increase threshold
- High accuracy (> 90% precision) → Lower threshold to catch more
- Pattern-specific tuning

**Usage**:
```python
from app.intelligence.pattern_learner import PatternLearner

learner = PatternLearner()

# Process user feedback
feedback = await learner.process_feedback(
    vulnerability_id=123,
    is_true_positive=False,
    reviewed_by="analyst@company.com",
    db_session=db_session,
    comments="Not vulnerable - WAF blocking"
)

# Get pattern performance
performance = await learner.get_pattern_performance(db_session)
# Returns: Metrics for all patterns (accuracy, precision, recall, F1)
```

### Vulnerability Chaining Engine (`app/intelligence/pattern_recognition/chaining_engine.py`)

**Core Functionality**:
The vulnerability chaining engine combines multiple vulnerabilities into complete attack chains, showing how attackers can chain together seemingly minor issues for critical impact.

**Attack Graph Building**:
- **Nodes**: Vulnerabilities, patterns, assets
- **Edges**: Relationships (enables, requires, provides_access_to)
- Uses NetworkX for graph algorithms
- Analyzes vulnerability dependencies and infrastructure relationships

**Chain Discovery**:
- Finds all simple paths between vulnerabilities
- Identifies complete attack sequences from entry to goal
- Supports chains of 2-5 vulnerabilities (configurable)
- Deduplicates similar chains

**Attack Chain Types**:
1. **Account Takeover**: Info disclosure → user enumeration → weak auth → password reset flaw
2. **Data Exfiltration**: Auth bypass → IDOR → sensitive data access → mass extraction
3. **Remote Code Execution**: File upload → path traversal → code execution → shell access
4. **Privilege Escalation**: Session fixation → CSRF → admin access → full privileges
5. **Infrastructure Compromise**: Subdomain takeover → lateral movement → production access

**Feasibility Calculation**:
- Factors: Complexity, prerequisites, authentication requirements, skill level
- Formula: `feasibility = 1.0 / (complexity * prerequisites_count)`
- Adjusted for each step's exploitation complexity
- Penalties for authentication and high complexity

**Impact Calculation**:
- CIA triad (Confidentiality, Integrity, Availability)
- Data sensitivity and privilege level achieved
- Business impact and compliance implications
- Chain type multipliers (RCE=2.0, Data Exfiltration=1.8, etc.)

**Risk Scoring**:
- Risk = Feasibility × Impact × 100
- Severity: Critical (85+), High (70-84), Medium (40-69), Low (<40)
- Priority: 1-10 scale for remediation ordering

**Exploitation Scenarios**:
- Step-by-step attack instructions
- Required tools and prerequisites
- Expected results and detection difficulty
- Estimated time to exploit
- Required skill level (Beginner, Intermediate, Advanced, Expert)

**Usage**:
```python
from app.intelligence.pattern_recognition.chaining_engine import VulnerabilityChainingEngine

engine = VulnerabilityChainingEngine()

# Analyze domain for vulnerability chains
results = await engine.analyze_domain(
    domain_id=1,
    db_session=db_session,
    max_chain_length=5
)

# Results include:
# - vulnerabilities_analyzed: Total vulnerabilities considered
# - patterns_analyzed: Patterns used in analysis
# - graph_nodes: Nodes in attack graph
# - graph_edges: Edges in attack graph
# - chains_found: Number of complete attack chains
# - chains: Detailed chain information with exploitation scenarios
# - critical_chains: Count of critical severity chains
```

**Database Integration**:
- Saves chains to `vulnerability_chains` table
- Stores detailed exploitation steps
- Links vulnerabilities and patterns
- Tracks feasibility, impact, and risk scores

**Configuration**:
```env
VULN_CHAINING_ENABLED=true
VULN_CHAINING_MIN_CHAIN_LENGTH=2
VULN_CHAINING_MAX_CHAIN_LENGTH=5
VULN_CHAINING_MIN_RISK_SCORE=40
```

**Example Output**:
```json
{
  "domain_id": 1,
  "vulnerabilities_analyzed": 15,
  "chains_found": 3,
  "chains": [
    {
      "chain_name": "Remote Code Execution Chain",
      "severity": "Critical",
      "risk_score": 92.5,
      "chain_length": 3,
      "feasibility": 0.85,
      "impact": 1.0,
      "required_skills": "Intermediate",
      "estimated_time": "2.5 hours",
      "exploitation_scenario": {
        "description": "This attack chain combines 3 vulnerabilities...",
        "steps": [
          {
            "step_number": 1,
            "vulnerability_type": "file_upload",
            "action": "Upload malicious PHP file...",
            "expected_result": "File uploaded successfully",
            "provides": ["file_placement", "code_execution_prep"]
          },
          {
            "step_number": 2,
            "vulnerability_type": "path_traversal",
            "action": "Use path traversal to place file...",
            "expected_result": "File moved to web root",
            "requires": ["file_placement"]
          },
          {
            "step_number": 3,
            "vulnerability_type": "rce",
            "action": "Execute uploaded file via web request",
            "expected_result": "Remote shell established",
            "requires": ["file_placement"]
          }
        ]
      }
    }
  ]
}
```

### Pattern Recognition Orchestrator (`app/intelligence/pattern_recognition/orchestrator.py`)

**Purpose**:
The Pattern Recognition Orchestrator provides a unified interface for the entire pattern recognition system, coordinating all analyzers and generating comprehensive vulnerability intelligence reports.

**Complete Analysis Workflow**:
1. **Temporal Pattern Analysis** - Time-based behavior patterns
2. **Spatial Pattern Analysis** - Infrastructure relationship patterns
3. **Behavioral Pattern Analysis** - Anomalous response patterns
4. **Vulnerability Chaining** - Attack path construction
5. **Predictive Analysis** - Testing guidance (when available)
6. **Comprehensive Reporting** - Unified results and critical findings

**Key Features**:
- **Unified Interface**: Single entry point for all pattern recognition
- **Selective Execution**: Enable/disable specific analyzers
- **Error Handling**: Graceful degradation if components fail
- **Progress Tracking**: Detailed statistics and logging
- **Critical Findings Extraction**: Prioritizes high-risk findings
- **Comprehensive Statistics**: Aggregates metrics across all components

**Main Method - analyze_domain()**:
```python
from app.intelligence.pattern_recognition.orchestrator import PatternRecognitionOrchestrator

orchestrator = PatternRecognitionOrchestrator()

# Run complete analysis
results = await orchestrator.analyze_domain(
    domain_id=1,
    db_session=db_session,
    enable_temporal=True,
    enable_spatial=True,
    enable_behavioral=True,
    enable_chaining=True,
    enable_predictive=True,
    time_window_days=30,      # For temporal analysis
    lookback_days=7,          # For behavioral analysis
    max_chain_length=5        # For chaining
)
```

**Return Format**:
```python
{
    "domain_id": 1,
    "analysis_started_at": "2025-10-14T10:00:00Z",
    "analysis_completed_at": "2025-10-14T10:05:23Z",

    # Temporal patterns (time-based behaviors)
    "temporal_patterns": {
        "count": 5,
        "patterns": [
            {
                "pattern_name": "Reduced Authentication Enforcement During Hours: [2, 3, 4]",
                "pattern_type": "time_based_auth_weakness",
                "risk_level": "High",
                "anomaly_score": 0.7,
                "description": "Authentication failure rate drops significantly...",
                "affected_assets": [123, 456]
            }
        ]
    },

    # Spatial patterns (infrastructure relationships)
    "spatial_patterns": {
        "count": 8,
        "patterns": [
            {
                "pattern_name": "Shared Authentication System Across 12 Subdomains",
                "pattern_type": "shared_authentication",
                "risk_level": "Medium",
                "consistency": 0.85,
                "description": "Multiple subdomains share authentication..."
            }
        ]
    },

    # Behavioral patterns (anomalies)
    "behavioral_patterns": {
        "count": 12,
        "patterns": [
            {
                "pattern_name": "Response Time Anomaly: GET /api/users",
                "pattern_type": "timing_attack_indicator",
                "risk_level": "High",
                "anomaly_score": 0.8,
                "description": "Sporadic timing anomalies suggest timing attacks..."
            }
        ]
    },

    # Vulnerability chains (attack paths)
    "vulnerability_chains": {
        "count": 3,
        "critical_count": 1,
        "chains": [
            {
                "chain_name": "Remote Code Execution Chain",
                "severity": "Critical",
                "risk_score": 92.5,
                "chain_length": 3,
                "feasibility": 0.85,
                "impact_score": 1.0
            }
        ]
    },

    # Predictions (testing guidance)
    "predictions": {
        "count": 15,
        "high_priority_count": 3,
        "predictions": [
            {
                "prediction_name": "Likely SQL Injection in Admin Panel",
                "likelihood": 0.82,
                "confidence": 0.75,
                "priority": 9,
                "suggested_test_areas": ["/admin/search", "/admin/reports"]
            }
        ]
    },

    # Top critical findings (sorted by priority)
    "critical_findings": [
        {
            "type": "vulnerability_chain",
            "severity": "Critical",
            "name": "Remote Code Execution Chain",
            "risk_score": 92.5,
            "description": "Complete attack path from file upload to RCE..."
        },
        {
            "type": "temporal_pattern",
            "severity": "High",
            "name": "Time-Based Auth Weakness",
            "anomaly_score": 0.7,
            "description": "Authentication weakens during night hours..."
        }
    ],

    # Statistics
    "statistics": {
        "session_stats": {
            "temporal_patterns_found": 5,
            "spatial_patterns_found": 8,
            "behavioral_patterns_found": 12,
            "vulnerability_chains_found": 3,
            "predictions_generated": 15
        },
        "pattern_by_category": {
            "temporal": 5,
            "spatial": 8,
            "behavioral": 12
        },
        "pattern_by_risk": {
            "Critical": 2,
            "High": 8,
            "Medium": 10,
            "Low": 5
        },
        "chains_by_severity": {
            "Critical": 1,
            "High": 2
        },
        "total_patterns": 25,
        "total_chains": 3,
        "total_predictions": 15
    }
}
```

**Selective Analysis**:
```python
# Run only temporal and spatial analysis
results = await orchestrator.analyze_domain(
    domain_id=1,
    db_session=db_session,
    enable_temporal=True,
    enable_spatial=True,
    enable_behavioral=False,
    enable_chaining=False,
    enable_predictive=False
)

# Run only chaining on existing patterns
results = await orchestrator.analyze_domain(
    domain_id=1,
    db_session=db_session,
    enable_temporal=False,
    enable_spatial=False,
    enable_behavioral=False,
    enable_chaining=True
)
```

**Helper Methods**:
```python
# Run specific pattern analyzer
temporal_patterns = await orchestrator.run_pattern_analysis(
    domain_id=1,
    db_session=db_session,
    analyzer_type="temporal",
    time_window_days=30
)

spatial_patterns = await orchestrator.run_pattern_analysis(
    domain_id=1,
    db_session=db_session,
    analyzer_type="spatial"
)

behavioral_patterns = await orchestrator.run_pattern_analysis(
    domain_id=1,
    db_session=db_session,
    analyzer_type="behavioral",
    lookback_days=7
)

# Run vulnerability chaining
chain_results = await orchestrator.run_vulnerability_chaining(
    domain_id=1,
    db_session=db_session,
    max_chain_length=5
)

# Get critical findings only
critical = await orchestrator.get_critical_findings(
    domain_id=1,
    db_session=db_session,
    analysis_results=results
)

# Get statistics
stats = await orchestrator.get_statistics(
    domain_id=1,
    db_session=db_session
)
```

**Integration with Scanner**:
The orchestrator can be integrated into the main scanner workflow:

```python
from app.intelligence.pattern_recognition.orchestrator import PatternRecognitionOrchestrator

# After completing scan phases
if config.ENABLE_PATTERN_RECOGNITION:
    orchestrator = PatternRecognitionOrchestrator()

    pattern_results = await orchestrator.analyze_domain(
        domain_id=scan_job.domain_id,
        db_session=db_session
    )

    # Log critical findings
    for finding in pattern_results["critical_findings"]:
        logger.warning(
            "Critical pattern detected",
            type=finding["type"],
            name=finding["name"],
            severity=finding["severity"]
        )
```

**Configuration**:
```env
ENABLE_PATTERN_RECOGNITION=true
PATTERN_TEMPORAL_ENABLED=true
PATTERN_SPATIAL_ENABLED=true
PATTERN_BEHAVIORAL_ENABLED=true
PATTERN_CHAINING_ENABLED=true
PATTERN_PREDICTIVE_ENABLED=true

# Analysis parameters
PATTERN_TIME_WINDOW_DAYS=30
PATTERN_LOOKBACK_DAYS=7
PATTERN_MAX_CHAIN_LENGTH=5
PATTERN_MIN_CONFIDENCE=0.7
```

**Notes**:
- All analyzers run independently - failures in one don't affect others
- Predictive analysis is currently a placeholder awaiting full implementation
- Results are automatically saved to database by individual analyzers
- Critical findings are extracted and prioritized for immediate attention
- Statistics provide overview of entire pattern recognition system

**Key Features**:
- **Intelligent Chaining**: Understands vulnerability relationships and dependencies
- **Real Attack Paths**: Only suggests feasible, exploitable chains
- **Prioritization**: Ranks chains by risk to focus on critical paths
- **Detailed Scenarios**: Provides step-by-step exploitation instructions
- **Learning**: Improves chain detection based on discovered patterns

**Dependencies**:
- Requires NetworkX (`pip install networkx>=3.1`)

### Vulnerability Intelligence Orchestrator (`app/intelligence/orchestrator.py`)

**Complete Workflow Orchestration**:

1. **Correlation**: Detect vulnerabilities using rule-based + ML
2. **Exploit Matching**: Find available exploits with scoring
3. **Risk Scoring**: Calculate context-aware risk scores
4. **Learning**: Improve from feedback

**Usage**:
```python
from app.intelligence.orchestrator import VulnerabilityIntelligenceOrchestrator

intel = VulnerabilityIntelligenceOrchestrator(config)

# Analyze HTTP traffic
vulns = await intel.analyze_http_traffic(traffic, db_session)

# Analyze port/service
vulns = await intel.analyze_port_service(port, db_session)

# Sync threat intelligence
stats = await intel.sync_threat_intelligence(db_session)

# Process feedback
result = await intel.process_feedback(
    vulnerability_id=123,
    is_true_positive=True,
    reviewed_by="analyst",
    db_session=db_session
)

# Get statistics
stats = await intel.get_statistics(db_session)
```

**Integration with Scanner**:

Vulnerability intelligence is automatically integrated into the scanner workflow when `ENABLE_VULNERABILITY_INTELLIGENCE=true`:

1. After HTTP probing → Analyze traffic for vulnerabilities
2. After port scanning → Check for service version vulnerabilities
3. Continuous → Match exploits and calculate risk scores
4. User feedback → Automatic pattern learning and refinement

**Database Models**:

- `CVEDatabase`: Synchronized CVE data from NVD
- `ExploitDatabase`: Exploits from multiple sources
- `VulnerabilityPattern`: ML patterns and performance metrics
- `RiskScore`: Multi-dimensional risk scores
- `VulnerabilityFeedback`: User feedback for learning

**Configuration**:

```env
ENABLE_VULNERABILITY_INTELLIGENCE=true
VULN_CORRELATION_ENABLED=true
VULN_RULE_BASED_DETECTION=true
VULN_ML_DETECTION=true
EXPLOIT_MATCHING_ENABLED=true
RISK_SCORING_ENABLED=true
PATTERN_LEARNING_ENABLED=true
VULN_MIN_CONFIDENCE=0.6
RISK_CRITICAL_THRESHOLD=90
```

## Development Guidelines

### Adding a New Tool

1. Create wrapper in `app/scanner/tools/` or appropriate phase directory
2. Extend `ToolWrapper` base class from `app/scanner/tools/base.py`
3. Implement `run()` method with subprocess execution
4. Add tool to `ToolInstaller` in `app/scanner/tools/installer.py`
5. Parse output and yield results line-by-line (streaming, not buffering)
6. Handle missing tool gracefully (log warning, return empty results)

### Adding a New Scan Phase

1. Create module in appropriate directory (`horizontal/`, `vertical/`, `probing/`)
2. Integrate into `ScannerEngine.run_scan()` in `app/scanner/engine.py`
3. Update `ScanJob` progress tracking
4. Add phase-specific configuration to `ScannerConfig`
5. Ensure rate limiting is applied via `rate_limiter.acquire()`

### Database Schema Changes

The platform uses SQLAlchemy ORM. To modify schema:
1. Update model in `app/models/`
2. Database auto-creates tables on startup via `DatabaseManager.initialize()`
3. For production, generate Alembic migrations

### Logging

Uses `structlog` for structured logging. All loggers should:
```python
import structlog
logger = structlog.get_logger()
logger.info("message", key1=value1, key2=value2)
```

Logs written to `logs/` directory with rotation.

### Rate Limiting

All external requests must use rate limiter:
```python
from app.scanner.rate_limiter import RateLimiter

rate_limiter = RateLimiter(config.scanner)
async with rate_limiter.acquire():
    # Make external request
    ...
```

### Error Handling

Follow graceful degradation pattern:
- Log errors to `ScanJob.errors` (JSON array)
- Log warnings to `ScanJob.warnings`
- Continue workflow despite individual tool failures
- Never fail entire scan due to single tool error

## Testing

Test files should be placed in `tests/` directory:
```bash
pytest tests/
```

## Security Considerations

- **Authorization**: Always verify `is_authorized=true` flag before scanning
- **Rate Limiting**: Respect configured scan profiles to avoid overwhelming targets
- **API Key Storage**: Keys encrypted using Fernet; master key in `data/master.key` (0600 permissions)
- **HTTPS Interception**: mitmproxy CA cert in `data/certs/`; must be installed in tools for Phase 3
- **Sensitive Data**: Pattern matches logged to database; masked in application logs

## Common Issues

**Tool not found in PATH**:
- Ensure Go tools installed: `export PATH=$PATH:$GOPATH/bin`
- Check tool status: `curl http://localhost:8000/api/tools/status`

**Permission denied for port scanning**:
```bash
sudo setcap cap_net_raw+ep $(which naabu)
```

**Database locked errors**:
- SQLite has limited concurrency
- Use PostgreSQL for production: `DATABASE_URL=postgresql+asyncpg://user:pass@host/db`

**Rate limiting errors**:
- Reduce to `passive` or `normal` profile
- Lower `GLOBAL_RATE_LIMIT` and `DOMAIN_RATE_LIMIT` in `.env`
