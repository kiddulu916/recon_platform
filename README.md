# Security Reconnaissance Platform

A comprehensive subdomain enumeration and reconnaissance platform that integrates 20+ security tools for intelligent vulnerability discovery through horizontal and vertical enumeration techniques.

## Features

### Core Capabilities
- **Horizontal Enumeration**: Company acquisitions, ASN lookup, reverse DNS, favicon hashing
- **Passive Enumeration**: CT logs, subfinder, assetfinder, amass
- **Active Enumeration**: DNS brute-forcing, permutations, JS scraping
- **Web Probing**: Port scanning, HTTP probing, technology detection
- **Recursive Discovery**: Automatic enumeration of newly discovered subdomains
- **HTTP Traffic Logging**: Complete request/response capture for vulnerability analysis

### Key Features
- ✅ 20+ integrated security tools
- ✅ Async-first architecture for maximum performance
- ✅ Intelligent rate limiting (passive, normal, aggressive profiles)
- ✅ Bloom filter deduplication
- ✅ Comprehensive API with FastAPI
- ✅ Database persistence with SQLAlchemy
- ✅ Structured logging with structlog
- ✅ Encrypted API key storage
- ✅ Scan job management with progress tracking

## Quick Start

### Prerequisites

**Required:**
- Python 3.9+ (3.12+ recommended)
- Git

**Recommended:**
- Go 1.19+ (for Go-based tools)
- Make/GCC (for building some tools from source)

### Automated Installation (Recommended)

**Linux/macOS:**
```bash
# Clone repository
git clone <repository-url>
cd recon

# Run automated installer
chmod +x install.sh
./install.sh
```

**Windows (PowerShell as Administrator):**
```powershell
# Clone repository
git clone <repository-url>
cd recon

# Run automated installer
.\install.ps1
```

The installation script will:
- ✅ Check system requirements
- ✅ Set up Python virtual environment
- ✅ Install Python dependencies
- ✅ Install 15+ Go-based security tools
- ✅ Download DNS wordlists and resolvers
- ✅ Verify all installations

### Manual Installation

If you prefer manual installation or the automated script fails:

1. **Clone the repository**
```bash
git clone <repository-url>
cd recon
```

2. **Create and activate virtual environment**
```bash
python3 -m venv recon_env
source recon_env/bin/activate  # On Windows: recon_env\Scripts\activate
```

3. **Install Python dependencies**
```bash
pip install -r requirements.txt
```

4. **Set up environment variables**
```bash
cp .env.example .env  # Create if it doesn't exist
# Edit .env with your configuration
```

Required environment variables:
```env
JWT_SECRET_KEY=your-secure-jwt-secret-key
DATABASE_URL=sqlite+aiosqlite:///./data/recon.db
SCAN_PROFILE=normal
GLOBAL_RATE_LIMIT=10
DOMAIN_RATE_LIMIT=5
```

5. **Install external security tools**

**Option A: Automated (Recommended)**
```bash
# Check current tool status
python main.py --check-tools

# Install all tools
python main.py --install-tools

# Download wordlists and resolvers
python main.py --download-resources

# Verify installation
python main.py --tool-status
```

**Option B: Manual Installation**
```bash
# Set up Go environment
export GOPATH=$HOME/go
export PATH=$PATH:$GOPATH/bin

# Install Go tools
go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
go install github.com/projectdiscovery/httpx/cmd/httpx@latest
go install github.com/projectdiscovery/naabu/v2/cmd/naabu@latest
go install github.com/projectdiscovery/dnsx/cmd/dnsx@latest
go install github.com/projectdiscovery/mapcidr/cmd/mapcidr@latest
go install github.com/Josue87/gotator@latest
# ... see docs/TOOL_INSTALLATION.md for complete list

# Download resources
cd tools
curl -O https://raw.githubusercontent.com/n0kovo/n0kovo_subdomains/main/n0kovo_subdomains_huge.txt
curl -O https://raw.githubusercontent.com/trickest/resolvers/main/resolvers.txt
cd ..
```

**📚 Detailed installation instructions:** See [docs/TOOL_INSTALLATION.md](docs/TOOL_INSTALLATION.md)

### Tool Installation CLI Commands

The platform provides convenient CLI commands for tool management:

```bash
# Display installation guide
python main.py --tool-guide

# Check which tools are available
python main.py --check-tools

# Show detailed status with versions
python main.py --tool-status

# Install all tools automatically
python main.py --install-tools

# Install a specific tool
python main.py --install-tool subfinder

# Download required resources (wordlists, resolvers)
python main.py --download-resources

# Get help
python main.py --help
```

## Usage

### Starting the Platform

```bash
python main.py
```

The platform will start on `http://localhost:8000`

### API Documentation

Interactive API documentation is available at:
- Swagger UI: `http://localhost:8000/docs`
- ReDoc: `http://localhost:8000/redoc`

### Basic Workflow

#### 1. Add a Target Domain

```bash
curl -X POST http://localhost:8000/api/domains \
  -H "Content-Type: application/json" \
  -d '{
    "domain": "example.com",
    "is_authorized": true,
    "scan_profile": "normal",
    "notes": "Test target"
  }'
```

Response:
```json
{
  "id": 1,
  "domain": "example.com",
  "message": "Domain created successfully"
}
```

#### 2. Start a Scan

```bash
curl -X POST http://localhost:8000/api/scans/start \
  -H "Content-Type: application/json" \
  -d '{
    "domain_id": 1,
    "scan_type": "full",
    "scan_profile": "normal",
    "enable_recursion": false,
    "recursion_depth": 2
  }'
```

Response:
```json
{
  "job_id": "550e8400-e29b-41d4-a716-446655440000",
  "status": "running",
  "message": "Scan started successfully"
}
```

#### 3. Check Scan Status

```bash
curl http://localhost:8000/api/scans/550e8400-e29b-41d4-a716-446655440000
```

Response:
```json
{
  "job_id": "550e8400-e29b-41d4-a716-446655440000",
  "status": "running",
  "progress": 45,
  "current_phase": "active_enumeration",
  "started_at": "2025-10-08T00:00:00",
  "subdomains_found": 127,
  "ips_discovered": 23,
  "ports_found": 156
}
```

#### 4. Get Scan Results

```bash
curl http://localhost:8000/api/scans/550e8400-e29b-41d4-a716-446655440000/results
```

#### 5. List Discovered Subdomains

```bash
curl "http://localhost:8000/api/domains/1/subdomains?limit=100&resolves_only=true"
```

### Scan Types

- **full**: Complete workflow (horizontal + passive + active + probing + recursive)
- **subdomain**: Subdomain enumeration only (horizontal + passive + active)
- **port**: Port scanning on discovered IPs
- **web**: HTTP probing on discovered services

### Scan Profiles

| Profile | Global Rate | Domain Rate | Description |
|---------|-------------|-------------|-------------|
| passive | 1 req/s | 0.5 req/s | No direct target interaction |
| normal | 10 req/s | 5 req/s | Balanced scanning with rate limits |
| aggressive | 50 req/s | 20 req/s | Fast scanning for authorized tests |

### API Key Management (Optional)

API keys are **entirely optional** and provide enhanced features like higher rate limits and additional data sources. The platform works perfectly without them.

**CLI Management (Recommended):**
```bash
# Set an API key (interactive, input hidden)
python main.py --set-api-key whoisxml YOUR_KEY

# List configured services
python main.py --list-api-keys

# Test an API key
python main.py --test-api-key whoisxml

# Remove an API key
python main.py --remove-api-key whoisxml
```

**Via API:**
```bash
# Store API key
curl -X POST http://localhost:8000/api/config/api-keys/whoisxml \
  -H "Content-Type: application/json" \
  -d '{"api_key": "your-api-key"}'

# List configured services (doesn't show actual keys)
curl http://localhost:8000/api/config/api-keys
```

**Supported Services:**
- WhoIsXMLAPI - Company acquisition discovery
- Censys - Certificate transparency and scanning
- Shodan - Internet-wide device discovery
- SecurityTrails - Historical DNS data
- VirusTotal - Subdomain discovery
- GitHub - Code search (requires token)
- GitLab - Repository search (requires token)

**📚 Detailed API key guide:** See [docs/API_KEYS.md](docs/API_KEYS.md)

## Architecture

### Scan Workflow

```
1. Horizontal Enumeration
   ├── Company Acquisitions (WhoIsXMLAPI)
   ├── ASN Lookup (bgp.he.net)
   ├── Reverse DNS (Mapcidr + Dnsx)
   └── Favicon Hashing (favUp.py)

2. Passive Enumeration
   ├── Subfinder
   ├── Assetfinder
   ├── Amass (passive)
   └── Certificate Transparency
       ├── crt.sh
       ├── tls.bufferover.run
       └── Censys

3. Active Enumeration
   ├── DNS Brute-forcing (PureDNS + 3M wordlist)
   ├── Permutations (GoTator)
   ├── JS/Source Scraping (Gospider + httpx)
   ├── VHOST Discovery (HostHunter + gobuster)
   └── TLS/CSP/CNAME Probing

4. Web Probing
   ├── Port Scanning (Naabu + Nmap)
   └── HTTP Probing (Httpx)

5. Recursive Enumeration (optional)
   └── Repeat workflow on new subdomains
```

### Database Schema

- **Domain**: Root domains being scanned
- **Subdomain**: Discovered subdomains with metadata
- **Company**: Companies and acquisitions
- **ASN**: Autonomous System Numbers and IP ranges
- **IPAddress**: Discovered IP addresses
- **Port**: Open ports and services
- **HTTPTraffic**: Request/response pairs
- **ScanJob**: Scan execution tracking

See `.cursor/rules/architecture.mdc` for detailed architecture documentation.

## Configuration

### Environment Variables

```env
# Database
DATABASE_URL=sqlite+aiosqlite:///./data/recon.db

# Security
JWT_SECRET_KEY=your-secret-key
ENCRYPTION_ENABLED=true

# Rate Limiting
GLOBAL_RATE_LIMIT=10
DOMAIN_RATE_LIMIT=5
SCAN_PROFILE=normal

# Tools
TOOLS_DIRECTORY=./tools
ENABLE_RECURSION=false
RECURSION_DEPTH=2
```

### Custom Configuration

Edit `config/default.yaml` for advanced configuration.

## Development

### Project Structure

```
recon/
├── app/
│   ├── core/              # Core functionality
│   ├── models/            # Database models
│   ├── api/               # API routes
│   └── scanner/           # Scanner modules
│       ├── tools/         # Tool integration
│       ├── horizontal/    # Horizontal enumeration
│       ├── vertical/      # Vertical enumeration
│       └── probing/       # Port and HTTP probing
├── config/                # Configuration files
├── data/                  # Database files
├── logs/                  # Log files
├── tools/                 # External tools
└── main.py               # Application entry point
```

### Running Tests

```bash
pytest tests/
```

### Contributing

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Add tests
5. Submit a pull request

## Troubleshooting

### Common Issues

**Tool not found in PATH**
```bash
export PATH=$PATH:$GOPATH/bin
```

**Permission denied for port scanning**
```bash
# Grant capabilities to naabu
sudo setcap cap_net_raw+ep $(which naabu)
```

**Rate limiting errors**
- Reduce scan profile to "passive" or "normal"
- Adjust GLOBAL_RATE_LIMIT and DOMAIN_RATE_LIMIT

**Database locked errors**
- SQLite has limited concurrency
- Consider PostgreSQL for production: `DATABASE_URL=postgresql+asyncpg://user:pass@host/db`

## Security Considerations

⚠️ **Important**: This platform is designed for authorized security testing only.

- Always obtain explicit permission before scanning any domain
- Set `is_authorized=true` only for domains you own or have permission to test
- Respect rate limits to avoid overwhelming targets
- Review and comply with all applicable laws and regulations

## License

This project integrates multiple open-source tools, each with their own licenses. See individual tool repositories for license information.

## Acknowledgments

### Integrated Tools
- ProjectDiscovery: subfinder, httpx, naabu, dnsx, mapcidr
- TomNomNom: assetfinder, unfurl, anew, waybackurls
- OWASP Amass
- PureDNS by d3mondev
- GoTator by Josue87
- And many more amazing security tools from the community

### Wordlists
- n0kovo_subdomains by n0kovo
- Trickest resolvers list

## Support

For issues, questions, or contributions:
- Open an issue on GitHub
- Check documentation in `.cursor/rules/`
- Review API docs at `/docs`

## Roadmap

### Phase 3 (Planned)
- Vulnerability detection (XSS, SQLi, SSRF)
- AI-powered pattern recognition
- Advanced fuzzing capabilities
- Automated exploitation framework
- Reporting and export functionality

