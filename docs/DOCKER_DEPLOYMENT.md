# Docker Deployment Guide

Complete guide for deploying the Security Reconnaissance Platform using Docker.

## Table of Contents

- [Introduction](#introduction)
- [Prerequisites](#prerequisites)
- [Architecture Overview](#architecture-overview)
- [Development Deployment](#development-deployment)
- [Production Deployment](#production-deployment)
- [Configuration Reference](#configuration-reference)
- [Container Management](#container-management)
- [Data Management](#data-management)
- [Networking](#networking)
- [Troubleshooting](#troubleshooting)
- [Security Best Practices](#security-best-practices)
- [Advanced Topics](#advanced-topics)
- [Reference](#reference)

---

## Introduction

This guide covers everything you need to deploy the Security Reconnaissance Platform using Docker. The platform uses a multi-container architecture with Docker Compose, optimized for both development and production environments.

**What this guide covers:**
- Step-by-step deployment instructions for development and production
- Configuration and environment setup
- Container management and monitoring
- Data backup and restoration
- Troubleshooting common issues
- Security best practices

**Before you begin:**
- This is a defensive security tool for authorized testing only
- Ensure you have proper authorization before scanning any targets
- Review the main [CLAUDE.md](../CLAUDE.md) for project architecture details

---

## Prerequisites

### System Requirements

**Minimum (Development):**
- CPU: 4 cores
- RAM: 8GB
- Storage: 20GB free space
- OS: Linux, macOS, or Windows with WSL2

**Recommended (Production):**
- CPU: 8+ cores
- RAM: 16GB+
- Storage: 50GB+ SSD
- OS: Linux (Ubuntu 20.04+ or Debian 11+)

### Required Software

**Docker & Docker Compose:**
```bash
# Verify Docker installation
docker --version
# Should output: Docker version 20.10.0 or higher

# Verify Docker Compose installation
docker-compose --version
# Should output: Docker Compose version 2.0.0 or higher
```

**Installation instructions:**
- Docker: https://docs.docker.com/get-docker/
- Docker Compose: https://docs.docker.com/compose/install/

**Optional tools:**
```bash
# For generating secure credentials
openssl

# For testing WebSocket connections
npm install -g wscat

# For JSON formatting
apt install jq  # Debian/Ubuntu
brew install jq  # macOS
```

### Network Requirements

**Outbound access required for:**
- Docker Hub (image pulls)
- GitHub (tool downloads during build)
- External security tool repositories (subfinder, httpx, etc.)

**Inbound ports (configurable):**
- 5173: Frontend (React UI)
- 8000: Backend API
- 8080: Mitmproxy web interface

---

## Architecture Overview

### Container Architecture

```
┌─────────────┐     ┌─────────────┐     ┌─────────────┐
│  Frontend   │────▶│   Backend   │────▶│  PostgreSQL │
│   (React)   │     │  (FastAPI)  │     │ (prod only) │
│  Port 5173  │     │  Port 8000  │     │  Port 5432  │
└─────────────┘     └──────┬──────┘     └─────────────┘
                           │
                    ┌──────┴──────┬─────────────┐
                    ▼             ▼             ▼
              ┌──────────┐  ┌──────────┐ ┌──────────┐
              │  Tools   │  │ mitmproxy│ │ SQLite   │
              │Container │  │Port 8080 │ │(dev only)│
              └──────────┘  └──────────┘ └──────────┘
```

### Container Descriptions

| Container | Purpose | Base Image | Exposed Ports |
|-----------|---------|------------|---------------|
| **tools** | Pre-built security tools (20+ tools) | golang:1.21-alpine → python:3.11-alpine | None (shared volumes) |
| **backend** | FastAPI application server | python:3.11-slim | 8000 |
| **frontend** | React UI (Vite dev/Nginx prod) | node:20-alpine / nginx:alpine | 5173 |
| **mitmproxy** | HTTP/HTTPS traffic interception | python:3.11-slim | 8080 |
| **postgres** | PostgreSQL database (prod only) | postgres:16-alpine | 5432 (internal) |

### Key Features

**Development Mode:**
- SQLite database (no separate DB container)
- Hot reload for code changes
- Bind mounts for easy file access
- Simplified configuration

**Production Mode:**
- PostgreSQL database with persistence
- Nginx-served static frontend
- Docker volumes for data isolation
- Resource limits and health checks
- Optimized builds

---

## Development Deployment

### Quick Start

**1. Clone the repository:**
```bash
git clone <repository-url>
cd recon
```

**2. Start all services:**
```bash
# Using helper script (recommended)
./scripts/dev-start.sh

# Or manually
docker-compose up --build
```

**3. Access the platform:**
- Frontend: http://localhost:5173
- Backend API: http://localhost:8000
- API Documentation: http://localhost:8000/docs
- Mitmproxy: http://localhost:8080

### Step-by-Step Setup

**1. Verify Docker is running:**
```bash
docker info
# Should display Docker system information
```

**2. Create environment file:**
```bash
# Copy example configuration
cp .env.example .env

# Review and customize (optional for development)
nano .env
```

The `.env` file contains default development settings. For development, the defaults are usually sufficient.

**3. Build and start containers:**
```bash
# Start in foreground (see logs in real-time)
docker-compose up --build

# Or start in background
docker-compose up -d --build
```

**First-time build takes 15-20 minutes** to compile all security tools. Subsequent builds use cache and are much faster.

**4. Verify services are running:**
```bash
docker-compose ps

# Should show 4 containers running:
# - recon-tools
# - recon-backend
# - recon-frontend
# - recon-mitmproxy
```

**5. Check service health:**
```bash
# Backend health check
curl http://localhost:8000/health

# Should return: {"status": "healthy"}

# Frontend (should load React app)
curl http://localhost:5173

# API docs (interactive Swagger UI)
open http://localhost:8000/docs
```

### Development Workflow

**Hot Reload:**
- **Backend:** Edit files in `app/` → Backend auto-reloads
- **Frontend:** Edit files in `frontend/src/` → Vite hot-reloads instantly

**Viewing Logs:**
```bash
# All services
docker-compose logs -f

# Specific service
docker-compose logs -f backend

# Last 100 lines
docker-compose logs --tail=100 -f
```

**Executing Commands:**
```bash
# Access backend shell
docker-compose exec backend bash

# Check installed tools
docker-compose exec backend subfinder -version
docker-compose exec backend httpx -version

# Run Python commands
docker-compose exec backend python -c "print('Hello from container!')"

# Check database
docker-compose exec backend ls -la /app/data/recon.db
```

**Restarting Services:**
```bash
# Restart specific service
docker-compose restart backend

# Restart all services
docker-compose restart

# Stop all services
docker-compose down

# Stop and remove all data (WARNING: deletes volumes!)
docker-compose down -v
```

### Common Development Tasks

**Adding a new Python dependency:**
```bash
# Edit requirements.txt
echo "new-package==1.0.0" >> requirements.txt

# Rebuild backend
docker-compose build backend
docker-compose restart backend
```

**Adding a new frontend dependency:**
```bash
# Access frontend container
docker-compose exec frontend sh

# Install package
npm install new-package

# Or from host (if node_modules is mounted)
cd frontend
npm install new-package
```

**Resetting the database:**
```bash
# Stop backend
docker-compose stop backend

# Remove database file
rm ./data/recon.db

# Restart backend (database will be recreated)
docker-compose start backend
```

**Checking tool installation:**
```bash
# List all available tools
docker-compose exec backend ls -la /tools/bin

# Verify specific tool
docker-compose exec backend which subfinder
docker-compose exec backend subfinder -version

# Check Python tools
docker-compose exec backend ls -la /tools/python-tools
```

---

## Production Deployment

### Pre-Deployment Checklist

- [ ] Server meets minimum requirements (8+ cores, 16GB+ RAM)
- [ ] Docker and Docker Compose installed
- [ ] Firewall configured (allow ports 5173, 8000, 8080 if external access needed)
- [ ] SSL/TLS certificates ready (if using reverse proxy)
- [ ] Backup strategy planned
- [ ] Monitoring solution ready (optional)

### Production Setup

**1. Create production environment file:**
```bash
# Copy production template
cp .env.production.example .env.production

# Edit with secure credentials
nano .env.production
```

**2. Generate secure credentials:**
```bash
# Generate database password
DB_PASSWORD=$(openssl rand -base64 32)
echo "DB_PASSWORD=$DB_PASSWORD"

# Generate JWT secret
JWT_SECRET=$(openssl rand -base64 64)
echo "JWT_SECRET_KEY=$JWT_SECRET"

# Save these securely!
```

**3. Update .env.production:**
```bash
# Required changes:
DATABASE_URL=postgresql+asyncpg://recon:${DB_PASSWORD}@postgres:5432/recon
DB_PASSWORD=<your-generated-password>
JWT_SECRET_KEY=<your-generated-secret>

# Recommended changes:
SCAN_PROFILE=normal  # or passive/aggressive based on authorization
GLOBAL_RATE_LIMIT=50
DOMAIN_RATE_LIMIT=20
LOG_LEVEL=INFO
```

**4. Secure environment file:**
```bash
chmod 600 .env.production

# Verify permissions
ls -la .env.production
# Should show: -rw------- (only owner can read/write)
```

**5. Start production services:**
```bash
# Using helper script (recommended)
./scripts/prod-start.sh

# Or manually
docker-compose -f docker-compose.yaml -f docker-compose.prod.yaml up -d --build
```

**6. Wait for services to initialize:**
```bash
# Check service status
docker-compose -f docker-compose.yaml -f docker-compose.prod.yaml ps

# Wait for all containers to show "Up (healthy)"
# PostgreSQL health check takes ~30 seconds
```

**7. Verify deployment:**
```bash
# Check backend health
curl http://localhost:8000/health

# Check comprehensive health (includes database)
curl http://localhost:8000/api/health/comprehensive | jq

# Should return database status, tool availability, etc.
```

**8. Install security tools (first time only):**
```bash
# Note: Tools are pre-built in the tools container
# This step verifies they're accessible to backend

docker-compose -f docker-compose.yaml -f docker-compose.prod.yaml exec backend python main.py --check-tools
```

### Verification Steps

**Test database connection:**
```bash
# From backend container
docker-compose -f docker-compose.yaml -f docker-compose.prod.yaml exec backend python -c "
from sqlalchemy import create_engine, text
import os
engine = create_engine(os.getenv('DATABASE_URL').replace('+asyncpg', ''))
with engine.connect() as conn:
    result = conn.execute(text('SELECT version()'))
    print('PostgreSQL version:', result.fetchone()[0])
"
```

**Test API endpoints:**
```bash
# List domains
curl http://localhost:8000/api/domains

# Check WebSocket
wscat -c ws://localhost:8000/ws

# Test tool status
curl http://localhost:8000/api/tools/status | jq
```

**Test frontend:**
```bash
# Frontend should be served by Nginx
curl -I http://localhost:5173

# Should return: Server: nginx
```

### Post-Deployment Tasks

**1. Configure external API keys (optional):**
```bash
# Via API
curl -X POST http://localhost:8000/api/config/api-keys/whoisxml \
  -H "Content-Type: application/json" \
  -d '{"api_key": "your-whoisxml-api-key"}'

# Verify
curl http://localhost:8000/api/config/api-keys
```

**2. Setup backup schedule:**
```bash
# Add to crontab
crontab -e

# Daily backup at 2 AM
0 2 * * * cd /path/to/recon && ./scripts/backup.sh >> /var/log/recon-backup.log 2>&1
```

**3. Configure log rotation (already configured in Docker):**
```bash
# Check current log settings
docker inspect recon-backend | jq '.[0].HostConfig.LogConfig'

# Logs are already configured with:
# - max-size: 50m (production) / 10m (development)
# - max-file: 5 (production) / 3 (development)
```

**4. Monitor resource usage:**
```bash
# Real-time monitoring
docker stats

# Check specific container
docker stats recon-backend
```

---

## Configuration Reference

### Environment Variables

#### Security (Required)

| Variable | Description | Default | Example |
|----------|-------------|---------|---------|
| `JWT_SECRET_KEY` | JWT authentication secret | None | `openssl rand -base64 64` |
| `DB_PASSWORD` | PostgreSQL password (prod) | None | `openssl rand -base64 32` |
| `ENCRYPTION_ENABLED` | Encrypt stored API keys | `true` | `true` or `false` |
| `RECON_MASTER_KEY` | Master encryption key | Auto-generated | `openssl rand -base64 32` |

#### Database

| Variable | Description | Development | Production |
|----------|-------------|-------------|------------|
| `DATABASE_URL` | Database connection string | `sqlite+aiosqlite:///./data/recon.db` | `postgresql+asyncpg://recon:${DB_PASSWORD}@postgres:5432/recon` |
| `DB_POOL_SIZE` | Connection pool size | `10` | `20` |
| `DB_MAX_OVERFLOW` | Max overflow connections | `20` | `40` |
| `DB_POOL_TIMEOUT` | Pool timeout (seconds) | `30` | `30` |
| `DB_ECHO` | Echo SQL queries (debug) | `false` | `false` |

#### Scanning Configuration

| Variable | Description | Options | Default |
|----------|-------------|---------|---------|
| `SCAN_PROFILE` | Scan aggressiveness | `passive`, `normal`, `aggressive` | `normal` |
| `GLOBAL_RATE_LIMIT` | Global requests/sec | Number | `50` |
| `DOMAIN_RATE_LIMIT` | Per-domain requests/sec | Number | `20` |
| `DNS_TIMEOUT` | DNS query timeout (sec) | Number | `5` |
| `PORT_SCAN_TIMEOUT` | Port scan timeout (sec) | Number | `2` |
| `HTTP_TIMEOUT` | HTTP request timeout (sec) | Number | `10` |

**Scan Profile Details:**

| Profile | Global Rate | Domain Rate | Use Case |
|---------|-------------|-------------|----------|
| `passive` | 1 req/s | 0.5 req/s | No direct target interaction, stealth |
| `normal` | 10 req/s | 5 req/s | Balanced scanning, recommended |
| `aggressive` | 50 req/s | 20 req/s | Fast scanning, authorized penetration tests only |

#### Phase Toggles

| Variable | Description | Default |
|----------|-------------|---------|
| `ENABLE_HORIZONTAL` | Enable horizontal enumeration (ASN, acquisitions) | `true` |
| `ENABLE_PASSIVE` | Enable passive subdomain enumeration | `true` |
| `ENABLE_ACTIVE` | Enable active subdomain enumeration (DNS bruteforce) | `true` |
| `ENABLE_WEB_PROBING` | Enable port scanning and HTTP probing | `true` |
| `ENABLE_RECURSION` | Enable recursive enumeration | `false` |
| `RECURSION_DEPTH` | Recursion depth (if enabled) | `2` |

#### Web Discovery Settings

| Variable | Description | Default |
|----------|-------------|---------|
| `ENABLE_WEB_DISCOVERY` | Enable intelligent web discovery | `false` |
| `CRAWLER_MAX_DEPTH` | Max crawl depth | `5` |
| `CRAWLER_MAX_PAGES` | Max pages to crawl per subdomain | `1000` |
| `DIRECTORY_ENUM_ENABLED` | Enable directory enumeration | `true` |
| `DIRECTORY_ENUM_LEARNING` | Learn patterns from discoveries | `true` |
| `API_DISCOVERY_ENABLED` | Enable API discovery | `true` |
| `API_DISCOVERY_JS_ANALYSIS` | Analyze JavaScript for APIs | `true` |
| `API_DISCOVERY_GRAPHQL_INTROSPECTION` | GraphQL introspection | `true` |
| `WEB_DISCOVERY_RATE_LIMIT` | Web discovery requests/sec | `5` |
| `WEB_DISCOVERY_MAX_SUBDOMAINS` | Max subdomains for web discovery | `10` |

#### Vulnerability Intelligence Settings

| Variable | Description | Default |
|----------|-------------|---------|
| `ENABLE_VULNERABILITY_INTELLIGENCE` | Enable AI-powered vulnerability detection | `true` |
| `VULN_CORRELATION_ENABLED` | Enable vulnerability correlation | `true` |
| `VULN_RULE_BASED_DETECTION` | Enable rule-based detection | `true` |
| `VULN_ML_DETECTION` | Enable ML-based anomaly detection | `true` |
| `EXPLOIT_MATCHING_ENABLED` | Enable exploit matching | `true` |
| `RISK_SCORING_ENABLED` | Enable risk scoring | `true` |
| `PATTERN_LEARNING_ENABLED` | Enable pattern learning from feedback | `true` |
| `VULN_MIN_CONFIDENCE` | Minimum confidence to report vulnerability | `0.6` |
| `RISK_CRITICAL_THRESHOLD` | Risk score threshold for critical | `90` |

#### Pattern Recognition Settings

| Variable | Description | Default |
|----------|-------------|---------|
| `ENABLE_PATTERN_RECOGNITION` | Enable unified pattern recognition | `true` |
| `PATTERN_TEMPORAL_ENABLED` | Enable temporal pattern analysis | `true` |
| `PATTERN_SPATIAL_ENABLED` | Enable spatial pattern analysis | `true` |
| `PATTERN_BEHAVIORAL_ENABLED` | Enable behavioral pattern analysis | `true` |
| `PATTERN_CHAINING_ENABLED` | Enable vulnerability chaining | `true` |
| `VULN_CHAINING_MIN_CHAIN_LENGTH` | Minimum vulnerabilities in chain | `2` |
| `VULN_CHAINING_MAX_CHAIN_LENGTH` | Maximum vulnerabilities in chain | `5` |
| `PATTERN_TIME_WINDOW_DAYS` | Time window for temporal analysis | `30` |
| `PATTERN_MIN_CONFIDENCE` | Minimum confidence for patterns | `0.7` |

#### External API Keys (Optional)

| Variable | Service | Registration URL |
|----------|---------|------------------|
| `WHOISXML_API_KEY` | Company acquisition discovery | https://whoisxmlapi.com/ |
| `CENSYS_API_ID` | Certificate Transparency logs | https://censys.io/ |
| `CENSYS_API_SECRET` | Certificate Transparency logs | https://censys.io/ |
| `BUFFEROVER_API_KEY` | CT log scanning | https://tls.bufferover.run/ |
| `GITHUB_TOKEN` | GitHub subdomain enumeration | https://github.com/settings/tokens |
| `SECURITYTRAILS_API_KEY` | Historical DNS data | https://securitytrails.com/ |
| `SHODAN_API_KEY` | Port scanning data | https://www.shodan.io/ |
| `VIRUSTOTAL_API_KEY` | Threat intelligence | https://www.virustotal.com/ |

#### Logging

| Variable | Description | Options | Default |
|----------|-------------|---------|---------|
| `LOG_LEVEL` | Application log level | `DEBUG`, `INFO`, `WARNING`, `ERROR`, `CRITICAL` | `INFO` |

#### Application

| Variable | Description | Development | Production |
|----------|-------------|-------------|------------|
| `HOST` | Server bind address | `127.0.0.1` | `0.0.0.0` |
| `PORT` | Server port | `8000` | `8000` |
| `RELOAD` | Enable hot reload | `true` | `false` |

### Database Configuration

#### SQLite (Development)

**Advantages:**
- No separate container needed
- Simple setup
- File-based (easy to backup)
- Fast for small datasets

**Limitations:**
- Single writer (limited concurrency)
- Not recommended for production
- Performance degrades with large datasets

**Configuration:**
```bash
DATABASE_URL=sqlite+aiosqlite:///./data/recon.db
```

**Location:** `./data/recon.db`

#### PostgreSQL (Production)

**Advantages:**
- High concurrency
- Better performance at scale
- ACID compliance
- Advanced features (JSON, full-text search)

**Configuration:**
```bash
DATABASE_URL=postgresql+asyncpg://recon:${DB_PASSWORD}@postgres:5432/recon
DB_PASSWORD=<strong-password>
```

**Connection pooling (recommended for production):**
```bash
DB_POOL_SIZE=20
DB_MAX_OVERFLOW=40
DB_POOL_TIMEOUT=30
```

---

## Container Management

### Starting and Stopping Services

**Development:**
```bash
# Start all services (foreground)
docker-compose up

# Start all services (background)
docker-compose up -d

# Start specific service
docker-compose up backend

# Stop all services (keeps containers)
docker-compose stop

# Stop and remove containers
docker-compose down

# Stop and remove containers + volumes (WARNING: deletes data!)
docker-compose down -v
```

**Production:**
```bash
# Start all services
docker-compose -f docker-compose.yaml -f docker-compose.prod.yaml up -d

# Stop all services
docker-compose -f docker-compose.yaml -f docker-compose.prod.yaml down

# Restart specific service
docker-compose -f docker-compose.yaml -f docker-compose.prod.yaml restart backend
```

**Helper scripts (recommended):**
```bash
# Development
./scripts/dev-start.sh

# Production
./scripts/prod-start.sh
```

### Viewing Logs

**All services:**
```bash
# Development
docker-compose logs -f

# Production
docker-compose -f docker-compose.yaml -f docker-compose.prod.yaml logs -f
```

**Specific service:**
```bash
docker-compose logs -f backend
docker-compose logs -f frontend
docker-compose logs -f mitmproxy
docker-compose logs -f postgres  # Production only
```

**With filters:**
```bash
# Last 100 lines
docker-compose logs --tail=100 backend

# Since specific time
docker-compose logs --since 2025-10-14T10:00:00 backend

# Follow only errors
docker-compose logs -f backend 2>&1 | grep -i error
```

### Executing Commands in Containers

**Backend:**
```bash
# Access bash shell
docker-compose exec backend bash

# Run Python command
docker-compose exec backend python -c "print('Hello')"

# Check tool availability
docker-compose exec backend subfinder -version
docker-compose exec backend httpx -version

# Run database migrations (if needed)
docker-compose exec backend python -c "
from app.core.database import DatabaseManager
import asyncio
asyncio.run(DatabaseManager.initialize())
"

# Check environment variables
docker-compose exec backend env | grep DATABASE_URL
```

**Frontend:**
```bash
# Access shell
docker-compose exec frontend sh

# Install npm package (development)
docker-compose exec frontend npm install package-name

# Build frontend manually
docker-compose exec frontend npm run build
```

**PostgreSQL (production):**
```bash
# Access PostgreSQL console
docker-compose exec postgres psql -U recon recon

# Run SQL query
docker-compose exec postgres psql -U recon recon -c "SELECT COUNT(*) FROM domains;"

# Dump database
docker-compose exec postgres pg_dump -U recon recon > backup.sql
```

**Tools container:**
```bash
# List installed tools
docker-compose exec tools ls -la /tools/bin

# Test a tool
docker-compose exec tools /tools/bin/subfinder -version
```

### Scaling Services

**Note:** Most services should run as single instances. Only stateless services can be scaled.

```bash
# Scale backend (not recommended without load balancer)
docker-compose up -d --scale backend=3

# Check scaled instances
docker-compose ps
```

**For true horizontal scaling, use Docker Swarm or Kubernetes** (see [Advanced Topics](#advanced-topics)).

### Resource Limits

**View resource usage:**
```bash
# Real-time stats
docker stats

# Specific container
docker stats recon-backend

# JSON format
docker stats --no-stream --format "{{json .}}" | jq
```

**Resource limits are configured in `docker-compose.prod.yaml`:**

| Container | CPU Limit | Memory Limit |
|-----------|-----------|--------------|
| backend | 4 CPUs | 4GB |
| postgres | 2 CPUs | 2GB |
| frontend | 1 CPU | 512MB |
| mitmproxy | 2 CPUs | 1GB |
| tools | 1 CPU | 512MB |

**Adjust limits:**
```yaml
# Edit docker-compose.prod.yaml
deploy:
  resources:
    limits:
      cpus: '4'
      memory: 4G
```

### Container Health Checks

**View health status:**
```bash
docker-compose ps

# Detailed health info
docker inspect --format='{{json .State.Health}}' recon-backend | jq
```

**Health check endpoints:**
- Backend: `GET /health` (simple) or `GET /api/health/comprehensive` (detailed)
- PostgreSQL: `pg_isready -U recon`

**Health check configuration (docker-compose.yaml):**
```yaml
healthcheck:
  test: ["CMD", "curl", "-f", "http://localhost:8000/health"]
  interval: 30s
  timeout: 10s
  retries: 3
  start_period: 40s
```

---

## Data Management

### Volume Structure

#### Development Volumes (Bind Mounts)

| Host Path | Container Path | Purpose |
|-----------|----------------|---------|
| `./data` | `/app/data` | SQLite database, API keys, certificates |
| `./logs` | `/app/logs` | Application logs |
| `./config` | `/app/config` | Configuration files |
| `./app` | `/app/app` | Backend code (hot reload) |
| `./frontend` | `/app` | Frontend code (hot reload) |

#### Production Volumes (Docker Volumes)

| Volume Name | Purpose | Size (typical) |
|-------------|---------|----------------|
| `recon_postgres_data` | PostgreSQL database files | 10-100GB |
| `recon_backend_data` | API keys, certificates | 100MB |
| `recon_backend_logs` | Application logs | 1-5GB |
| `recon_backend_config` | Configuration | 10MB |
| `recon_mitmproxy_certs` | SSL certificates | 10MB |
| `recon_mitmproxy_wal` | Traffic write-ahead log | 1-10GB |

#### Shared Volumes (All Environments)

| Volume Name | Purpose | Size |
|-------------|---------|------|
| `recon_tools_bin` | Security tool binaries (Go, C) | 500MB |
| `recon_tools_python` | Python security tools | 200MB |

**List volumes:**
```bash
docker volume ls | grep recon
```

**Inspect volume:**
```bash
docker volume inspect recon_postgres_data
```

**Volume sizes:**
```bash
docker system df -v | grep recon
```

### Backup Strategies

#### Automated Backup (Recommended)

**Using backup script:**
```bash
# Manual backup
./scripts/backup.sh

# Backup to custom location
./scripts/backup.sh /path/to/backups

# Schedule daily backups (crontab)
crontab -e
# Add: 0 2 * * * cd /path/to/recon && ./scripts/backup.sh >> /var/log/recon-backup.log 2>&1
```

**What gets backed up:**
- **PostgreSQL:** SQL dump + data volume tar.gz
- **SQLite:** Database file copy
- **Application data:** API keys, certificates, config
- **Logs:** Recent application logs

**Backup retention strategy:**
```bash
# Example backup rotation script
#!/bin/bash
BACKUP_DIR=./backups

# Keep 7 daily backups
find $BACKUP_DIR -name "postgres_*.sql" -mtime +7 -delete

# Keep 4 weekly backups (Sundays)
if [ $(date +%u) -eq 7 ]; then
    cp $BACKUP_DIR/postgres_$(date +%Y%m%d)_*.sql $BACKUP_DIR/weekly/
fi

# Keep 12 monthly backups (1st of month)
if [ $(date +%d) -eq 01 ]; then
    cp $BACKUP_DIR/postgres_$(date +%Y%m%d)_*.sql $BACKUP_DIR/monthly/
fi
```

#### Manual Backup

**PostgreSQL (production):**
```bash
# SQL dump
docker-compose -f docker-compose.yaml -f docker-compose.prod.yaml exec -T postgres \
  pg_dump -U recon recon > backup_$(date +%Y%m%d).sql

# Volume backup
docker run --rm \
  -v recon_postgres_data:/data \
  -v $(pwd)/backups:/backup \
  alpine tar czf /backup/postgres_data_$(date +%Y%m%d).tar.gz -C / data
```

**SQLite (development):**
```bash
# Simple file copy
cp ./data/recon.db ./backups/recon_$(date +%Y%m%d).db

# Or use SQLite backup command
docker-compose exec backend sqlite3 /app/data/recon.db ".backup /app/data/backup.db"
```

**Application data:**
```bash
# Backup all data directories
tar czf backup_data_$(date +%Y%m%d).tar.gz ./data ./logs ./config
```

### Restore Procedures

#### Using Restore Script

```bash
# List available backups
./scripts/restore.sh

# Restore specific backup
./scripts/restore.sh 20251014_120000

# Restore from custom location
./scripts/restore.sh 20251014_120000 /path/to/backups
```

#### Manual Restore

**PostgreSQL:**
```bash
# Stop services using database
docker-compose -f docker-compose.yaml -f docker-compose.prod.yaml stop backend mitmproxy

# Restore from SQL dump
cat backup_20251014.sql | docker-compose -f docker-compose.yaml -f docker-compose.prod.yaml \
  exec -T postgres psql -U recon recon

# Restart services
docker-compose -f docker-compose.yaml -f docker-compose.prod.yaml start backend mitmproxy
```

**SQLite:**
```bash
# Stop services
docker-compose stop

# Restore database file
cp ./backups/recon_20251014.db ./data/recon.db

# Restart services
docker-compose start
```

### Database Migrations

**The platform uses auto-migrations** - database schema is automatically created and updated on startup.

**Manual migration (if needed):**
```bash
docker-compose exec backend python -c "
from app.core.database import DatabaseManager
import asyncio
asyncio.run(DatabaseManager.initialize())
"
```

**For production with Alembic (future):**
```bash
# Generate migration
docker-compose exec backend alembic revision --autogenerate -m "description"

# Apply migrations
docker-compose exec backend alembic upgrade head

# Rollback
docker-compose exec backend alembic downgrade -1
```

### Log Rotation

**Docker log rotation is configured automatically:**

```yaml
# Development: 10MB max, 3 files
# Production: 50MB max, 5 files
logging:
  driver: "json-file"
  options:
    max-size: "50m"
    max-file: "5"
```

**Manual log cleanup (if needed):**
```bash
# Truncate container logs
: > $(docker inspect --format='{{.LogPath}}' recon-backend)

# Clean up Docker logs system-wide
docker system prune -a
```

### Data Cleanup

**Remove old scan data:**
```bash
# Via API (recommended)
curl -X DELETE http://localhost:8000/api/scans/{scan_id}

# Direct database (use with caution)
docker-compose exec postgres psql -U recon recon -c "
DELETE FROM scan_jobs WHERE status = 'completed' AND created_at < NOW() - INTERVAL '30 days';
"
```

**Clean Docker system:**
```bash
# Remove unused containers
docker container prune

# Remove unused images
docker image prune -a

# Remove unused volumes (WARNING: data loss!)
docker volume prune

# Full cleanup (WARNING: removes everything!)
docker system prune -a --volumes
```

---

## Networking

### Port Mappings

| Host Port | Container Port | Service | Protocol | Purpose |
|-----------|----------------|---------|----------|---------|
| 5173 | 5173 | frontend | HTTP | React UI (dev) / Nginx (prod) |
| 8000 | 8000 | backend | HTTP | FastAPI application |
| 8000 | 8000 | backend | WebSocket | Real-time updates |
| 8080 | 8080 | mitmproxy | HTTP | Mitmproxy web interface |
| - | 5432 | postgres | PostgreSQL | Database (internal only) |

**Default port mapping (docker-compose.yaml):**
```yaml
ports:
  - "8000:8000"  # backend
  - "5173:5173"  # frontend
  - "8080:8080"  # mitmproxy
```

**Change port mappings:**
```yaml
# Edit docker-compose.yaml
ports:
  - "8001:8000"  # Use host port 8001 instead of 8000
```

### Container Networking

**Network name:** `recon-network` (bridge driver)

**All containers** are on the same Docker network and can communicate using container names:

```bash
# From backend to postgres (production)
DATABASE_URL=postgresql+asyncpg://recon:password@postgres:5432/recon

# From frontend to backend (production)
VITE_API_URL=http://backend:8000

# From backend to tools (always uses shared volumes, not network)
```

**Network inspection:**
```bash
# List networks
docker network ls | grep recon

# Inspect network
docker network inspect recon-network

# Test connectivity between containers
docker-compose exec frontend wget -O- http://backend:8000/health
```

### Exposing Services

#### Local Development (Default)

Services bound to `localhost` - only accessible from host machine:
```yaml
environment:
  - HOST=127.0.0.1  # Backend only accessible locally
```

#### External Access

**Option 1: Change host binding (simple, not recommended for production)**
```yaml
environment:
  - HOST=0.0.0.0  # Backend accessible from network
```

**Option 2: Use reverse proxy (recommended for production)**

See [Reverse Proxy Setup](#reverse-proxy-setup) section below.

### Reverse Proxy Setup

**Nginx reverse proxy example:**

```nginx
# /etc/nginx/sites-available/recon

server {
    listen 80;
    server_name recon.example.com;

    # Redirect to HTTPS
    return 301 https://$server_name$request_uri;
}

server {
    listen 443 ssl http2;
    server_name recon.example.com;

    ssl_certificate /etc/letsencrypt/live/recon.example.com/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/recon.example.com/privkey.pem;

    # Frontend
    location / {
        proxy_pass http://localhost:5173;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
    }

    # Backend API
    location /api/ {
        proxy_pass http://localhost:8000/api/;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
    }

    # WebSocket
    location /ws {
        proxy_pass http://localhost:8000/ws;
        proxy_http_version 1.1;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection "upgrade";
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
    }
}
```

**Traefik reverse proxy (Docker labels):**

```yaml
# docker-compose.yaml additions
services:
  backend:
    labels:
      - "traefik.enable=true"
      - "traefik.http.routers.backend.rule=Host(`recon.example.com`) && PathPrefix(`/api`)"
      - "traefik.http.routers.backend.entrypoints=websecure"
      - "traefik.http.routers.backend.tls.certresolver=letsencrypt"

  frontend:
    labels:
      - "traefik.enable=true"
      - "traefik.http.routers.frontend.rule=Host(`recon.example.com`)"
      - "traefik.http.routers.frontend.entrypoints=websecure"
      - "traefik.http.routers.frontend.tls.certresolver=letsencrypt"
```

### TLS/SSL Configuration

**Using Let's Encrypt with Certbot:**

```bash
# Install Certbot
apt install certbot python3-certbot-nginx

# Obtain certificate
certbot --nginx -d recon.example.com

# Auto-renewal (already set up by certbot)
certbot renew --dry-run
```

**Using self-signed certificates (development):**

```bash
# Generate self-signed cert
openssl req -x509 -nodes -days 365 -newkey rsa:2048 \
  -keyout nginx-selfsigned.key \
  -out nginx-selfsigned.crt \
  -subj "/CN=localhost"

# Use in Nginx config
ssl_certificate /etc/nginx/ssl/nginx-selfsigned.crt;
ssl_certificate_key /etc/nginx/ssl/nginx-selfsigned.key;
```

---

## Troubleshooting

### Common Issues and Solutions

#### Port Conflicts

**Error:**
```
Error: Bind for 0.0.0.0:8000 failed: port is already allocated
```

**Solution:**
```bash
# Find process using the port
sudo lsof -i :8000
# Or on Linux
sudo netstat -tulpn | grep :8000

# Kill the process
kill -9 <PID>

# Or change port in docker-compose.yaml
ports:
  - "8001:8000"  # Use different host port
```

#### Tools Not Accessible in Backend

**Symptoms:** Backend can't find security tools (subfinder, httpx, etc.)

**Diagnosis:**
```bash
# Check tools container is running
docker-compose ps tools

# Verify tools are built
docker-compose exec tools ls -la /tools/bin

# Check backend can see tools
docker-compose exec backend ls -la /tools/bin
docker-compose exec backend which subfinder

# Check PATH
docker-compose exec backend echo $PATH
# Should include: /tools/bin
```

**Solution:**
```bash
# Rebuild tools container
docker-compose build --no-cache tools
docker-compose restart backend

# Verify volume is mounted
docker inspect recon-backend | jq '.[0].Mounts' | grep tools_bin
```

#### Volume Permission Issues

**Error:**
```
Permission denied: '/app/data/recon.db'
```

**Solution:**
```bash
# Fix ownership on host
sudo chown -R $USER:$USER ./data ./logs ./config

# Set permissions
chmod -R 755 ./data ./logs ./config

# Or run containers with your UID (add to docker-compose.yaml)
user: "${UID}:${GID}"
```

**For production volumes:**
```bash
# Create directories with correct permissions
docker-compose -f docker-compose.yaml -f docker-compose.prod.yaml up -d
docker-compose -f docker-compose.yaml -f docker-compose.prod.yaml exec backend chown -R app:app /app/data
```

#### Database Connection Issues

**SQLite (Development):**

```bash
# Check database file exists and is writable
ls -la ./data/recon.db

# Check permissions
chmod 644 ./data/recon.db

# Verify DATABASE_URL
docker-compose exec backend env | grep DATABASE_URL

# Test connection
docker-compose exec backend python -c "
from sqlalchemy import create_engine
engine = create_engine('sqlite:///./data/recon.db')
print('Connection successful!')
"
```

**PostgreSQL (Production):**

```bash
# Check postgres container is healthy
docker-compose -f docker-compose.yaml -f docker-compose.prod.yaml ps postgres
# Should show: Up (healthy)

# Check postgres logs
docker-compose -f docker-compose.yaml -f docker-compose.prod.yaml logs postgres

# Test connection from backend
docker-compose -f docker-compose.yaml -f docker-compose.prod.yaml exec backend python -c "
from sqlalchemy import create_engine, text
import os
engine = create_engine(os.getenv('DATABASE_URL').replace('+asyncpg', ''))
with engine.connect() as conn:
    result = conn.execute(text('SELECT version()'))
    print('Connected:', result.fetchone()[0])
"

# Verify DATABASE_URL is correct
docker-compose -f docker-compose.yaml -f docker-compose.prod.yaml exec backend env | grep DATABASE_URL
# Should be: postgresql+asyncpg://recon:${DB_PASSWORD}@postgres:5432/recon
```

#### Container Health Check Failures

**Diagnosis:**
```bash
# Check health status
docker-compose ps

# View health check logs
docker inspect --format='{{json .State.Health}}' recon-backend | jq

# Check container logs
docker-compose logs backend
```

**Common causes:**
- Application failed to start (check logs)
- Health check endpoint not responding (network issue)
- Dependencies not ready (postgres not healthy)
- Resource exhaustion (CPU, memory)

**Solution:**
```bash
# Restart container
docker-compose restart backend

# Rebuild if code changes
docker-compose up -d --build backend

# Check dependencies
docker-compose ps postgres  # Should be healthy

# Increase startup time (docker-compose.yaml)
healthcheck:
  start_period: 60s  # Increase from 40s
```

#### Out of Memory

**Symptoms:** Containers crashing, "Killed" messages, slow performance

**Diagnosis:**
```bash
# Check current usage
docker stats

# Check Docker Desktop memory limit
# Docker Desktop → Settings → Resources → Memory
```

**Solution:**
```bash
# Increase Docker Desktop memory (macOS/Windows)
# Recommended: 8GB minimum, 16GB for production workloads

# Adjust container memory limits (docker-compose.prod.yaml)
deploy:
  resources:
    limits:
      memory: 4G  # Increase as needed

# Or reduce limits for less critical services
```

#### Build Failures

**Common errors:**
- Network timeouts downloading tools
- Disk space issues
- Cache corruption

**Solutions:**
```bash
# Clear Docker build cache
docker builder prune -a

# Remove old images
docker-compose down --rmi all

# Check disk space
df -h
docker system df

# Rebuild from scratch
docker-compose build --no-cache

# If tools container fails (common due to network):
# Retry the build - Go tool downloads can timeout
docker-compose build --no-cache tools

# Build with increased timeout
DOCKER_BUILDKIT=1 BUILDKIT_PROGRESS=plain docker-compose build --no-cache tools
```

#### Frontend Can't Reach Backend

**Diagnosis:**
```bash
# Check environment variables
docker-compose exec frontend env | grep VITE

# Development should be:
# VITE_API_URL=http://localhost:8000
# Production should be:
# VITE_API_URL=http://backend:8000

# Verify containers are on same network
docker network inspect recon-network

# Test connectivity
docker-compose exec frontend wget -O- http://backend:8000/health
```

**Solution:**
```bash
# Development: Use localhost
VITE_API_URL=http://localhost:8000

# Production: Use container name
VITE_API_URL=http://backend:8000

# Rebuild frontend if environment changed
docker-compose build frontend
docker-compose restart frontend
```

#### Logs Too Large

**Docker logs consuming disk space:**

```bash
# Already configured with log rotation:
# Development: max-size: 10m, max-file: 3
# Production: max-size: 50m, max-file: 5

# Manual cleanup if needed
docker-compose down
docker system prune -a

# Truncate specific container logs
: > $(docker inspect --format='{{.LogPath}}' recon-backend)

# Check log sizes
docker system df -v | grep logs
```

#### Mitmproxy Certificate Issues

**Symptoms:** HTTPS interception not working, SSL errors

**Solution:**
```bash
# Regenerate certificates
rm -rf ./data/certs/*
docker-compose restart mitmproxy

# Certificates regenerated at: ./data/certs/mitmproxy-ca-cert.pem

# Export CA certificate
docker-compose exec mitmproxy cat /root/.mitmproxy/mitmproxy-ca-cert.pem > mitmproxy-ca.pem

# Install CA certificate system-wide

# Ubuntu/Debian:
sudo cp mitmproxy-ca.pem /usr/local/share/ca-certificates/mitmproxy-ca.crt
sudo update-ca-certificates

# macOS:
sudo security add-trusted-cert -d -r trustRoot -k /Library/Keychains/System.keychain mitmproxy-ca.pem

# Windows:
certutil -addstore -f "ROOT" mitmproxy-ca.pem
```

### Debugging Techniques

**Enable debug logging:**
```bash
# Edit .env or .env.production
LOG_LEVEL=DEBUG

# Restart backend
docker-compose restart backend

# View debug logs
docker-compose logs -f backend
```

**Interactive debugging:**
```bash
# Access backend shell
docker-compose exec backend bash

# Run Python REPL
docker-compose exec backend python

# Import modules and test
>>> from app.core.database import DatabaseManager
>>> from app.core.config import get_settings
>>> settings = get_settings()
>>> print(settings.database_url)
```

**Network debugging:**
```bash
# Install network tools in container
docker-compose exec backend apt update
docker-compose exec backend apt install -y curl netcat dnsutils

# Test connectivity
docker-compose exec backend curl http://postgres:5432
docker-compose exec backend nc -zv postgres 5432

# DNS resolution
docker-compose exec backend nslookup postgres
```

**Database debugging:**
```bash
# SQLite
docker-compose exec backend sqlite3 /app/data/recon.db "SELECT * FROM domains LIMIT 5;"

# PostgreSQL
docker-compose exec postgres psql -U recon recon -c "SELECT * FROM domains LIMIT 5;"

# Check connections
docker-compose exec postgres psql -U recon recon -c "SELECT count(*) FROM pg_stat_activity;"
```

### Log Analysis

**Search logs for errors:**
```bash
# All error logs
docker-compose logs | grep -i error

# Specific service errors
docker-compose logs backend | grep -i error

# With context (5 lines before/after)
docker-compose logs backend | grep -i -C 5 error
```

**Follow logs with filters:**
```bash
# Only HTTP requests
docker-compose logs -f backend | grep "HTTP"

# Only database queries
docker-compose logs -f backend | grep "SELECT\|INSERT\|UPDATE"

# Only errors and warnings
docker-compose logs -f backend | grep -E "ERROR|WARNING"
```

**Structured log parsing:**
```bash
# If using JSON logging
docker-compose logs backend | jq 'select(.level == "error")'

# Extract specific fields
docker-compose logs backend | jq '{time: .timestamp, message: .message, level: .level}'
```

### Performance Issues

**Slow API responses:**
```bash
# Check resource usage
docker stats

# Check database performance
docker-compose exec postgres psql -U recon recon -c "
SELECT pid, query, state, query_start
FROM pg_stat_activity
WHERE state != 'idle'
ORDER BY query_start;
"

# Enable query logging (PostgreSQL)
# Add to docker-compose.prod.yaml:
environment:
  - POSTGRES_LOG_STATEMENT=all
  - POSTGRES_LOG_MIN_DURATION_STATEMENT=1000  # Log queries > 1s
```

**High memory usage:**
```bash
# Check memory by container
docker stats --no-stream

# Backend memory profiling
docker-compose exec backend python -c "
import tracemalloc
tracemalloc.start()
# Your code here
snapshot = tracemalloc.take_snapshot()
top_stats = snapshot.statistics('lineno')
for stat in top_stats[:10]:
    print(stat)
"
```

---

## Security Best Practices

### Credential Management

**Never commit secrets:**
```bash
# Add to .gitignore (already included)
.env.production
.env.local
*.key
*.pem
data/api_keys/
```

**Generate strong credentials:**
```bash
# Database password (32+ characters)
openssl rand -base64 32

# JWT secret (64+ characters)
openssl rand -base64 64

# Master encryption key (32+ characters)
openssl rand -base64 32
```

**Secure environment files:**
```bash
# Set restrictive permissions
chmod 600 .env.production
chmod 600 data/master.key

# Verify
ls -la .env.production
# Should show: -rw------- (only owner can read/write)
```

**Use secrets management (production):**

- Docker Secrets (Swarm mode)
- HashiCorp Vault
- AWS Secrets Manager
- Azure Key Vault
- Google Secret Manager

**Example with Docker Secrets:**
```yaml
# docker-compose.prod.yaml
secrets:
  db_password:
    external: true

services:
  backend:
    secrets:
      - db_password
    environment:
      - DB_PASSWORD_FILE=/run/secrets/db_password
```

### Network Security

**Firewall configuration:**
```bash
# Ubuntu/Debian (ufw)
sudo ufw allow 22/tcp    # SSH
sudo ufw allow 80/tcp    # HTTP (if using reverse proxy)
sudo ufw allow 443/tcp   # HTTPS (if using reverse proxy)
sudo ufw enable

# For internal-only deployment, don't expose Docker ports
# Access via SSH tunnel or VPN
```

**Restrict container access:**
```yaml
# docker-compose.yaml - only expose needed ports
ports:
  - "127.0.0.1:8000:8000"  # Only accessible from localhost
  # Not: - "8000:8000"  # Accessible from network
```

**Network isolation:**
```yaml
# Separate networks for different tiers
networks:
  frontend-network:
  backend-network:
  database-network:

services:
  frontend:
    networks:
      - frontend-network
  backend:
    networks:
      - frontend-network
      - backend-network
      - database-network
  postgres:
    networks:
      - database-network
```

### Volume Permissions

**Set correct ownership:**
```bash
# Development (bind mounts)
chown -R $USER:$USER ./data ./logs ./config

# Production (volumes)
# Let Docker manage permissions, or use named user in Dockerfile
```

**Avoid running as root:**
```dockerfile
# Dockerfile.backend
RUN groupadd -r app && useradd -r -g app app
USER app
```

### Container Security

**Scan images for vulnerabilities:**
```bash
# Using Docker Scout
docker scout cves recon-backend

# Using Trivy
trivy image recon-backend:latest
```

**Keep images updated:**
```bash
# Pull latest base images
docker-compose pull

# Rebuild with latest
docker-compose build --no-cache --pull
```

**Use minimal base images:**
```dockerfile
# Use alpine where possible
FROM python:3.11-alpine  # vs python:3.11 (much smaller)
```

**Read-only containers (where possible):**
```yaml
services:
  backend:
    read_only: true
    tmpfs:
      - /tmp
      - /app/.cache
```

### Regular Updates

**Update Docker:**
```bash
# Check for updates
apt update && apt upgrade docker-ce docker-ce-cli containerd.io

# Or use Docker Desktop auto-update
```

**Update application:**
```bash
# Pull latest code
git pull

# Rebuild containers
docker-compose -f docker-compose.yaml -f docker-compose.prod.yaml up -d --build

# Check for issues
docker-compose -f docker-compose.yaml -f docker-compose.prod.yaml logs -f
```

**Update dependencies:**
```bash
# Update Python packages
docker-compose exec backend pip list --outdated

# Update requirements.txt
# Then rebuild
docker-compose build backend
```

### Secrets Rotation

**Rotate database password:**
```bash
# Generate new password
NEW_PASSWORD=$(openssl rand -base64 32)

# Update PostgreSQL
docker-compose exec postgres psql -U recon recon -c "ALTER USER recon PASSWORD '$NEW_PASSWORD';"

# Update .env.production
sed -i "s/DB_PASSWORD=.*/DB_PASSWORD=$NEW_PASSWORD/" .env.production

# Restart backend
docker-compose restart backend
```

**Rotate JWT secret:**
```bash
# Generate new secret
NEW_SECRET=$(openssl rand -base64 64)

# Update .env.production
sed -i "s/JWT_SECRET_KEY=.*/JWT_SECRET_KEY=$NEW_SECRET/" .env.production

# Restart backend (will invalidate all existing tokens)
docker-compose restart backend
```

### Audit Logging

**Enable comprehensive logging:**
```bash
# .env.production
LOG_LEVEL=INFO  # Or WARNING for production

# Enable Docker logging driver
# docker-compose.prod.yaml
logging:
  driver: "json-file"
  options:
    max-size: "50m"
    max-file: "5"
    labels: "production"
```

**Centralized logging (recommended for production):**

- ELK Stack (Elasticsearch, Logstash, Kibana)
- Graylog
- Splunk
- Datadog
- Papertrail

**Example: Forward logs to syslog:**
```yaml
logging:
  driver: syslog
  options:
    syslog-address: "tcp://syslog-server:514"
    tag: "{{.Name}}/{{.ID}}"
```

---

## Advanced Topics

### Custom Tool Installation

**Adding a new Go tool:**

```dockerfile
# docker/Dockerfile.tools

# Add to Go tools section
RUN go install -v github.com/author/newtool/cmd/newtool@latest
```

**Adding a new Python tool:**

```dockerfile
# docker/Dockerfile.tools

# In Python tools section
RUN git clone https://github.com/author/newtool /tools/python-tools/newtool
```

**Rebuild tools container:**
```bash
docker-compose build --no-cache tools
docker-compose restart backend
```

### Multi-Host Deployment (Docker Swarm)

**Initialize Swarm:**
```bash
# On manager node
docker swarm init --advertise-addr <MANAGER-IP>

# On worker nodes (run output command from above)
docker swarm join --token <TOKEN> <MANAGER-IP>:2377
```

**Deploy stack:**
```bash
# Convert docker-compose to stack
docker stack deploy -c docker-compose.yaml -c docker-compose.prod.yaml recon

# Check services
docker service ls

# Scale services
docker service scale recon_backend=3

# Update service
docker service update --image recon-backend:latest recon_backend
```

**Stack-specific compose file (docker-compose.swarm.yaml):**
```yaml
version: '3.8'

services:
  backend:
    deploy:
      replicas: 3
      update_config:
        parallelism: 1
        delay: 10s
      restart_policy:
        condition: on-failure
        max_attempts: 3
      placement:
        constraints:
          - node.role == worker
```

### Kubernetes Migration Path

**Generate Kubernetes manifests:**
```bash
# Using Kompose
kompose convert -f docker-compose.yaml -f docker-compose.prod.yaml

# Or manually create manifests
```

**Example Kubernetes deployment:**
```yaml
# backend-deployment.yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: recon-backend
spec:
  replicas: 3
  selector:
    matchLabels:
      app: recon-backend
  template:
    metadata:
      labels:
        app: recon-backend
    spec:
      containers:
      - name: backend
        image: recon-backend:latest
        ports:
        - containerPort: 8000
        env:
        - name: DATABASE_URL
          valueFrom:
            secretKeyRef:
              name: recon-secrets
              key: database-url
        volumeMounts:
        - name: tools-bin
          mountPath: /tools/bin
      volumes:
      - name: tools-bin
        persistentVolumeClaim:
          claimName: tools-bin-pvc
```

### CI/CD Integration

**GitHub Actions example:**

```yaml
# .github/workflows/deploy.yaml
name: Deploy to Production

on:
  push:
    branches: [main]

jobs:
  deploy:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3

      - name: Build images
        run: docker-compose -f docker-compose.yaml -f docker-compose.prod.yaml build

      - name: Push to registry
        run: |
          docker tag recon-backend:latest registry.example.com/recon-backend:${{ github.sha }}
          docker push registry.example.com/recon-backend:${{ github.sha }}

      - name: Deploy to server
        uses: appleboy/ssh-action@master
        with:
          host: ${{ secrets.SERVER_HOST }}
          username: ${{ secrets.SERVER_USER }}
          key: ${{ secrets.SSH_PRIVATE_KEY }}
          script: |
            cd /opt/recon
            git pull
            docker-compose -f docker-compose.yaml -f docker-compose.prod.yaml pull
            docker-compose -f docker-compose.yaml -f docker-compose.prod.yaml up -d
```

**GitLab CI example:**

```yaml
# .gitlab-ci.yml
stages:
  - build
  - test
  - deploy

build:
  stage: build
  script:
    - docker-compose build
    - docker-compose push

test:
  stage: test
  script:
    - docker-compose run --rm backend pytest

deploy:
  stage: deploy
  script:
    - ssh user@server "cd /opt/recon && docker-compose pull && docker-compose up -d"
  only:
    - main
```

### Monitoring Stack Integration

**Prometheus + Grafana setup:**

```yaml
# docker-compose.monitoring.yaml
version: '3.8'

services:
  prometheus:
    image: prom/prometheus:latest
    volumes:
      - ./prometheus.yml:/etc/prometheus/prometheus.yml
      - prometheus_data:/prometheus
    ports:
      - "9090:9090"
    networks:
      - recon-network

  grafana:
    image: grafana/grafana:latest
    volumes:
      - grafana_data:/var/lib/grafana
    ports:
      - "3000:3000"
    environment:
      - GF_SECURITY_ADMIN_PASSWORD=admin
    networks:
      - recon-network

  node-exporter:
    image: prom/node-exporter:latest
    ports:
      - "9100:9100"
    networks:
      - recon-network

volumes:
  prometheus_data:
  grafana_data:
```

**Prometheus configuration:**
```yaml
# prometheus.yml
global:
  scrape_interval: 15s

scrape_configs:
  - job_name: 'docker'
    static_configs:
      - targets: ['node-exporter:9100']

  - job_name: 'backend'
    static_configs:
      - targets: ['backend:8000']
    metrics_path: '/metrics'
```

**Start monitoring:**
```bash
docker-compose -f docker-compose.yaml -f docker-compose.prod.yaml -f docker-compose.monitoring.yaml up -d

# Access Grafana: http://localhost:3000
# Default credentials: admin/admin
```

---

## Reference

### File Structure Overview

```
recon/
├── docker/                          # Docker build files
│   ├── Dockerfile.backend          # Backend container
│   ├── Dockerfile.frontend         # Frontend container (multi-stage)
│   ├── Dockerfile.mitmproxy        # Mitmproxy container
│   └── Dockerfile.tools            # Security tools container
│
├── scripts/                         # Helper scripts
│   ├── dev-start.sh               # Start development environment
│   ├── prod-start.sh              # Start production environment
│   ├── backup.sh                  # Backup databases and data
│   └── restore.sh                 # Restore from backup
│
├── docker-compose.yaml             # Base compose file (development)
├── docker-compose.prod.yaml        # Production overrides
│
├── .env.example                    # Development environment template
├── .env.production.example         # Production environment template
│
├── app/                            # Backend application code
├── frontend/                       # Frontend application code
│
├── data/                           # Data directory (development)
│   ├── recon.db                   # SQLite database
│   ├── api_keys/                  # Encrypted API keys
│   └── certs/                     # SSL certificates
│
├── logs/                           # Application logs (development)
├── config/                         # Configuration files
└── backups/                        # Backup storage (created by scripts)
```

### Helper Scripts Quick Reference

| Script | Purpose | Usage |
|--------|---------|-------|
| `dev-start.sh` | Start development environment | `./scripts/dev-start.sh` |
| `prod-start.sh` | Start production environment | `./scripts/prod-start.sh` |
| `backup.sh` | Create backup of database and data | `./scripts/backup.sh [backup_dir]` |
| `restore.sh` | Restore from backup | `./scripts/restore.sh <timestamp> [backup_dir]` |

### Docker Compose Commands Cheat Sheet

**Development:**
```bash
# Start all services
docker-compose up

# Start in background
docker-compose up -d

# Start with rebuild
docker-compose up --build

# Stop services
docker-compose stop

# Stop and remove
docker-compose down

# View logs
docker-compose logs -f

# Execute command
docker-compose exec backend bash

# Restart service
docker-compose restart backend
```

**Production:**
```bash
# All commands use both compose files
COMPOSE_CMD="docker-compose -f docker-compose.yaml -f docker-compose.prod.yaml"

# Start
$COMPOSE_CMD up -d --build

# Stop
$COMPOSE_CMD down

# Logs
$COMPOSE_CMD logs -f

# Execute
$COMPOSE_CMD exec backend bash

# Service status
$COMPOSE_CMD ps
```

### Environment Variables Reference Table

| Category | Variable | Development Default | Production Default |
|----------|----------|---------------------|-------------------|
| **Database** | `DATABASE_URL` | `sqlite+aiosqlite:///./data/recon.db` | `postgresql+asyncpg://recon:${DB_PASSWORD}@postgres:5432/recon` |
| | `DB_PASSWORD` | N/A | Required (generate) |
| **Security** | `JWT_SECRET_KEY` | Generated | Required (generate) |
| | `ENCRYPTION_ENABLED` | `true` | `true` |
| **Scanning** | `SCAN_PROFILE` | `normal` | `normal` |
| | `GLOBAL_RATE_LIMIT` | `1000` | `50` |
| | `DOMAIN_RATE_LIMIT` | `5` | `20` |
| **Application** | `HOST` | `127.0.0.1` | `0.0.0.0` |
| | `PORT` | `8000` | `8000` |
| | `RELOAD` | `true` | `false` |
| | `LOG_LEVEL` | `INFO` | `INFO` |
| **Features** | `ENABLE_WEB_DISCOVERY` | `false` | `true` |
| | `ENABLE_VULNERABILITY_INTELLIGENCE` | `true` | `true` |
| | `ENABLE_PATTERN_RECOGNITION` | `true` | `true` |

### Port Mapping Table

| Service | Internal Port | Host Port (Dev) | Host Port (Prod) | Purpose |
|---------|---------------|-----------------|------------------|---------|
| Backend | 8000 | 8000 | 8000 | API + WebSocket |
| Frontend | 5173 (dev) / 80 (prod) | 5173 | 5173 | Web UI |
| Mitmproxy | 8080 | 8080 | 8080 | Web interface |
| PostgreSQL | 5432 | - | - (internal) | Database |

### Volume Mapping Table

**Development (Bind Mounts):**

| Host Path | Container Path | Service | Purpose |
|-----------|----------------|---------|---------|
| `./data` | `/app/data` | backend, mitmproxy | SQLite, API keys, certs |
| `./logs` | `/app/logs` | backend | Application logs |
| `./config` | `/app/config` | backend | Configuration files |
| `./app` | `/app/app` | backend | Code (hot reload) |
| `./frontend` | `/app` | frontend | Code (hot reload) |

**Production (Docker Volumes):**

| Volume Name | Container Path | Service | Purpose |
|-------------|----------------|---------|---------|
| `recon_postgres_data` | `/var/lib/postgresql/data` | postgres | Database files |
| `recon_backend_data` | `/app/data` | backend | API keys, certs |
| `recon_backend_logs` | `/app/logs` | backend | Application logs |
| `recon_backend_config` | `/app/config` | backend | Configuration |
| `recon_mitmproxy_certs` | `/root/.mitmproxy` | mitmproxy | SSL certificates |
| `recon_mitmproxy_wal` | `/app/wal` | mitmproxy | Traffic WAL |

**Shared (All Environments):**

| Volume Name | Container Path | Shared By | Purpose |
|-------------|----------------|-----------|---------|
| `recon_tools_bin` | `/tools/bin` | tools, backend | Security tool binaries |
| `recon_tools_python` | `/tools/python-tools` | tools, backend | Python tools |

---

## Quick Reference

### Essential Commands

**Development:**
```bash
# Start
./scripts/dev-start.sh

# Stop
docker-compose down

# Logs
docker-compose logs -f backend

# Access backend
docker-compose exec backend bash

# Restart
docker-compose restart backend
```

**Production:**
```bash
# Start
./scripts/prod-start.sh

# Stop
docker-compose -f docker-compose.yaml -f docker-compose.prod.yaml down

# Logs
docker-compose -f docker-compose.yaml -f docker-compose.prod.yaml logs -f

# Backup
./scripts/backup.sh

# Access backend
docker-compose -f docker-compose.yaml -f docker-compose.prod.yaml exec backend bash
```

### Getting Help

**Documentation:**
- Main documentation: [CLAUDE.md](../CLAUDE.md)
- API documentation: http://localhost:8000/docs (when running)
- Tool installation: [docs/TOOL_INSTALLATION.md](./TOOL_INSTALLATION.md)
- API keys: [docs/API_KEYS.md](./API_KEYS.md)

**Container logs:**
```bash
docker-compose logs backend
docker-compose logs frontend
docker-compose logs mitmproxy
docker-compose logs postgres  # Production
```

**Health checks:**
```bash
# Quick health check
curl http://localhost:8000/health

# Comprehensive health check
curl http://localhost:8000/api/health/comprehensive | jq
```

**Community:**
- GitHub Issues: <repository-url>/issues
- Documentation: <repository-url>/wiki

---

## Summary

This guide has covered:

✅ **Prerequisites** - System requirements and Docker installation
✅ **Architecture** - Multi-container design and component overview
✅ **Development Deployment** - Quick start and development workflow
✅ **Production Deployment** - Secure production setup with PostgreSQL
✅ **Configuration** - Comprehensive environment variable reference
✅ **Container Management** - Starting, stopping, and monitoring services
✅ **Data Management** - Backups, restores, and volume management
✅ **Networking** - Port mappings, reverse proxy, and TLS setup
✅ **Troubleshooting** - Common issues and debugging techniques
✅ **Security** - Best practices for credentials, networking, and updates
✅ **Advanced Topics** - Swarm, Kubernetes, CI/CD, and monitoring
✅ **Reference** - Quick lookup tables and command cheatsheets

**Next Steps:**

1. **Development**: Run `./scripts/dev-start.sh` to get started
2. **Production**: Follow the production deployment checklist
3. **Customize**: Adjust environment variables for your use case
4. **Monitor**: Set up backups and log monitoring
5. **Scale**: Consider Docker Swarm or Kubernetes for multi-host deployment

**Remember:**
- Always use strong credentials in production
- Set up regular backups
- Monitor resource usage
- Keep Docker and dependencies updated
- Only scan authorized targets

For more information, see [CLAUDE.md](../CLAUDE.md) for the complete project documentation.
