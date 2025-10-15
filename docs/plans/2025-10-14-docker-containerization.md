# Docker Containerization Implementation Plan

> **For Claude:** Use `${SUPERPOWERS_SKILLS_ROOT}/skills/collaboration/executing-plans/SKILL.md` to implement this plan task-by-task.

**Goal:** Containerize the Security Reconnaissance Platform using Docker Compose with separate containers for backend, frontend, database, tools, and mitmproxy, supporting both development and production deployments.

**Architecture:** Multi-container architecture with tools container sharing binaries via Docker volumes, flexible database (SQLite for dev, PostgreSQL for prod), development-first base compose file with production overrides, and hybrid persistence strategy (volumes for database, bind mounts for logs/config).

**Tech Stack:** Docker, Docker Compose, PostgreSQL 16, Nginx (for frontend), Python 3.11, Node 20, Go 1.21, Alpine Linux

---

## Task 1: Create Docker Directory Structure

**Files:**
- Create: `docker/Dockerfile.tools`
- Create: `docker/Dockerfile.backend`
- Create: `docker/Dockerfile.frontend`
- Create: `docker/Dockerfile.mitmproxy`
- Create: `docker/nginx.conf`

**Step 1: Create docker directory**

```bash
mkdir -p docker
```

**Step 2: Create tools Dockerfile**

Create `docker/Dockerfile.tools`:

```dockerfile
# Stage 1: Build all tools
FROM golang:1.21-alpine AS go-builder

# Install build dependencies
RUN apk add --no-cache \
    git \
    build-base \
    make \
    libpcap-dev \
    python3 \
    py3-pip

WORKDIR /build

# Set GOPATH
ENV GOPATH=/build

# Install Go tools
RUN go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest && \
    go install -v github.com/tomnomnom/assetfinder@latest && \
    go install -v github.com/lc/gau/v2/cmd/gau@latest && \
    go install -v github.com/tomnomnom/waybackurls@latest && \
    go install -v github.com/gwen001/github-subdomains@latest && \
    go install -v github.com/gwen001/gitlab-subdomains@latest && \
    go install -v github.com/Josue87/gotator@latest && \
    go install -v github.com/jaeles-project/gospider@latest && \
    go install -v github.com/tomnomnom/unfurl@latest && \
    go install -v github.com/OJ/gobuster/v3@latest && \
    go install -v github.com/tomnomnom/anew@latest && \
    go install -v github.com/projectdiscovery/dnsx/cmd/dnsx@latest && \
    go install -v github.com/projectdiscovery/mapcidr/cmd/mapcidr@latest && \
    go install -v github.com/projectdiscovery/naabu/v2/cmd/naabu@latest && \
    go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest

# Clone and build massdns
RUN git clone https://github.com/blechschmidt/massdns.git /massdns && \
    cd /massdns && \
    make

# Clone and build puredns
RUN git clone https://github.com/d3mondev/puredns /puredns && \
    cd /puredns && \
    go install

# Clone Python tools
RUN mkdir -p /python-tools && \
    git clone https://github.com/UnaPibaGeek/ctfr.git /python-tools/ctfr && \
    git clone https://github.com/pielco11/fav-up.git /python-tools/favup && \
    git clone https://github.com/m4ll0k/SecretFinder.git /python-tools/secretfinder && \
    git clone https://github.com/SpiderLabs/HostHunter.git /python-tools/hosthunter

# Install Python tool dependencies
RUN cd /python-tools/ctfr && pip3 install --break-system-packages -r requirements.txt || true && \
    cd /python-tools/favup && pip3 install --break-system-packages -r requirements.txt || true && \
    cd /python-tools/secretfinder && pip3 install --break-system-packages -r requirements.txt || true && \
    cd /python-tools/hosthunter && pip3 install --break-system-packages -r requirements.txt || true

# Stage 2: Final runtime image
FROM python:3.11-alpine

# Install runtime dependencies
RUN apk add --no-cache \
    nmap \
    nmap-scripts \
    git \
    make \
    libpcap \
    ca-certificates

# Create directories
RUN mkdir -p /tools/bin /tools/python-tools

# Copy Go binaries from builder
COPY --from=go-builder /build/bin/* /tools/bin/

# Copy massdns binary
COPY --from=go-builder /massdns/bin/massdns /tools/bin/

# Copy Python tools (entire directories with dependencies)
COPY --from=go-builder /python-tools /tools/python-tools

# Symlink system tools to /tools/bin
RUN ln -s /usr/bin/nmap /tools/bin/nmap && \
    ln -s /usr/bin/git /tools/bin/git && \
    ln -s /usr/bin/make /tools/bin/make

# Make all binaries executable
RUN chmod +x /tools/bin/*

# Keep container running
CMD ["tail", "-f", "/dev/null"]
```

**Step 3: Verify Dockerfile syntax**

```bash
docker build -f docker/Dockerfile.tools --no-cache --target go-builder -t test-tools-builder . 2>&1 | head -20
```

Expected: Build starts (may take time, can Ctrl+C after verification)

**Step 4: Commit tools Dockerfile**

```bash
git add docker/Dockerfile.tools
git commit -m "feat: add tools container Dockerfile with 20+ security tools"
```

---

## Task 2: Create Backend Dockerfile

**Files:**
- Create: `docker/Dockerfile.backend`

**Step 1: Create backend Dockerfile**

Create `docker/Dockerfile.backend`:

```dockerfile
# Stage 1: Builder - install Python dependencies
FROM python:3.11-slim AS builder

WORKDIR /app

# Copy requirements
COPY requirements.txt .

# Install dependencies to user directory
RUN pip install --no-cache-dir --user -r requirements.txt

# Stage 2: Runtime
FROM python:3.11-slim

WORKDIR /app

# Copy Python dependencies from builder
COPY --from=builder /root/.local /root/.local

# Copy application code
COPY app ./app
COPY main.py .
COPY config ./config

# Add tools to PATH and PYTHONPATH
ENV PATH=/tools/bin:/tools/python-tools:/root/.local/bin:$PATH
ENV PYTHONPATH=/tools/python-tools:$PYTHONPATH
ENV PYTHONUNBUFFERED=1

# Create necessary directories
RUN mkdir -p data logs config

# Expose port
EXPOSE 8000

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
  CMD python -c "import urllib.request; urllib.request.urlopen('http://localhost:8000/health')" || exit 1

# Run application
CMD ["python", "main.py", "--host", "0.0.0.0", "--port", "8000", "--no-reload"]
```

**Step 2: Verify Dockerfile syntax**

```bash
docker build -f docker/Dockerfile.backend --target builder -t test-backend-builder . 2>&1 | grep -E "(Step|Successfully)" | head -10
```

Expected: Build progresses through steps

**Step 3: Commit backend Dockerfile**

```bash
git add docker/Dockerfile.backend
git commit -m "feat: add backend container Dockerfile"
```

---

## Task 3: Create Frontend Dockerfile and Nginx Config

**Files:**
- Create: `docker/Dockerfile.frontend`
- Create: `docker/nginx.conf`

**Step 1: Create frontend Dockerfile**

Create `docker/Dockerfile.frontend`:

```dockerfile
# Stage 1: Development
FROM node:20-alpine AS development

WORKDIR /app

# Copy package files
COPY frontend/package*.json ./

# Install dependencies
RUN npm ci

# Expose Vite dev server port
EXPOSE 5173

# Run dev server
CMD ["npm", "run", "dev", "--", "--host", "0.0.0.0"]

# Stage 2: Build for production
FROM node:20-alpine AS builder

WORKDIR /app

# Copy package files
COPY frontend/package*.json ./

# Install dependencies
RUN npm ci

# Copy source code
COPY frontend/ .

# Build for production
RUN npm run build

# Stage 3: Production runtime with Nginx
FROM nginx:alpine AS production

# Copy built assets from builder
COPY --from=builder /app/dist /usr/share/nginx/html

# Copy nginx configuration
COPY docker/nginx.conf /etc/nginx/conf.d/default.conf

EXPOSE 5173

HEALTHCHECK --interval=30s --timeout=5s --start-period=5s --retries=3 \
  CMD wget --quiet --tries=1 --spider http://localhost:5173 || exit 1

CMD ["nginx", "-g", "daemon off;"]
```

**Step 2: Create nginx configuration**

Create `docker/nginx.conf`:

```nginx
server {
    listen 5173;
    server_name _;
    root /usr/share/nginx/html;
    index index.html;

    # Enable gzip compression
    gzip on;
    gzip_types text/plain text/css application/json application/javascript text/xml application/xml application/xml+rss text/javascript;

    # SPA routing - all requests to index.html
    location / {
        try_files $uri $uri/ /index.html;
    }

    # Cache static assets
    location ~* \.(js|css|png|jpg|jpeg|gif|ico|svg|woff|woff2|ttf|eot)$ {
        expires 1y;
        add_header Cache-Control "public, immutable";
    }

    # Security headers
    add_header X-Frame-Options "SAMEORIGIN" always;
    add_header X-Content-Type-Options "nosniff" always;
    add_header X-XSS-Protection "1; mode=block" always;
}
```

**Step 3: Verify Dockerfile syntax**

```bash
docker build -f docker/Dockerfile.frontend --target development -t test-frontend-dev . 2>&1 | grep -E "(Step|Successfully)" | head -5
```

Expected: Build starts successfully

**Step 4: Commit frontend Dockerfile and nginx config**

```bash
git add docker/Dockerfile.frontend docker/nginx.conf
git commit -m "feat: add frontend Dockerfile with dev and prod stages, nginx config"
```

---

## Task 4: Create Mitmproxy Dockerfile

**Files:**
- Create: `docker/Dockerfile.mitmproxy`

**Step 1: Create mitmproxy Dockerfile**

Create `docker/Dockerfile.mitmproxy`:

```dockerfile
FROM python:3.11-slim

# Install mitmproxy
RUN pip install --no-cache-dir mitmproxy==10.1.5

# Create directories for certificates and addons
RUN mkdir -p /root/.mitmproxy /app/addons /app/wal

# Install addon dependencies
RUN pip install --no-cache-dir \
    aiofiles==23.2.1 \
    msgpack==1.0.7 \
    sqlalchemy==2.0.23 \
    structlog==23.2.0 \
    aiosqlite==0.19.0 \
    asyncpg==0.29.0

# Copy mitmproxy addons and interception code
COPY app/scanner/interception/*.py /app/addons/
COPY app/models/*.py /app/models/
COPY app/core/logging.py /app/core/logging.py
COPY app/core/database.py /app/core/database.py
COPY app/core/config.py /app/core/config.py

# Set Python path
ENV PYTHONPATH=/app:$PYTHONPATH

EXPOSE 8080

HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
  CMD netstat -an | grep 8080 > /dev/null; if [ 0 != $? ]; then exit 1; fi;

# Run mitmproxy with interceptor addon
CMD ["mitmdump", "-s", "/app/addons/interceptor.py", "--set", "confdir=/root/.mitmproxy", "--listen-port", "8080"]
```

**Step 2: Verify Dockerfile syntax**

```bash
docker build -f docker/Dockerfile.mitmproxy -t test-mitmproxy . 2>&1 | grep -E "(Step|Successfully)" | head -5
```

Expected: Build starts successfully

**Step 3: Commit mitmproxy Dockerfile**

```bash
git add docker/Dockerfile.mitmproxy
git commit -m "feat: add mitmproxy container Dockerfile"
```

---

## Task 5: Create Base Docker Compose Configuration

**Files:**
- Create: `docker-compose.yaml`

**Step 1: Create base docker-compose.yaml**

Create `docker-compose.yaml`:

```yaml
version: '3.8'

services:
  # Tools container - builds all security tools
  tools:
    build:
      context: .
      dockerfile: docker/Dockerfile.tools
    container_name: recon-tools
    volumes:
      - tools_bin:/tools/bin
      - tools_python:/tools/python-tools
    command: tail -f /dev/null
    restart: unless-stopped
    networks:
      - recon-network

  # Backend API
  backend:
    build:
      context: .
      dockerfile: docker/Dockerfile.backend
    container_name: recon-backend
    ports:
      - "8000:8000"
    volumes:
      - tools_bin:/tools/bin:ro
      - tools_python:/tools/python-tools:ro
      - ./data:/app/data
      - ./logs:/app/logs
      - ./config:/app/config
      - ./app:/app/app:ro
    environment:
      - DATABASE_URL=sqlite+aiosqlite:///./data/recon.db
      - PYTHONUNBUFFERED=1
    env_file:
      - .env
    depends_on:
      - tools
    restart: unless-stopped
    networks:
      - recon-network
    logging:
      driver: "json-file"
      options:
        max-size: "10m"
        max-file: "3"

  # Frontend
  frontend:
    build:
      context: .
      dockerfile: docker/Dockerfile.frontend
      target: development
    container_name: recon-frontend
    ports:
      - "5173:5173"
    volumes:
      - ./frontend:/app:ro
      - /app/node_modules
    environment:
      - VITE_API_URL=http://localhost:8000
      - VITE_WS_URL=ws://localhost:8000
    depends_on:
      - backend
    restart: unless-stopped
    networks:
      - recon-network
    logging:
      driver: "json-file"
      options:
        max-size: "10m"
        max-file: "3"

  # Mitmproxy for HTTP interception
  mitmproxy:
    build:
      context: .
      dockerfile: docker/Dockerfile.mitmproxy
    container_name: recon-mitmproxy
    ports:
      - "8080:8080"
    volumes:
      - ./data/certs:/root/.mitmproxy
      - ./data/wal:/app/wal
    environment:
      - DATABASE_URL=sqlite+aiosqlite:///./data/recon.db
    env_file:
      - .env
    depends_on:
      - backend
    restart: unless-stopped
    networks:
      - recon-network
    logging:
      driver: "json-file"
      options:
        max-size: "10m"
        max-file: "3"

volumes:
  tools_bin:
    name: recon_tools_bin
  tools_python:
    name: recon_tools_python

networks:
  recon-network:
    name: recon-network
    driver: bridge
```

**Step 2: Verify YAML syntax**

```bash
docker-compose config 2>&1 | head -20
```

Expected: YAML parses successfully, shows merged config

**Step 3: Commit base docker-compose**

```bash
git add docker-compose.yaml
git commit -m "feat: add base docker-compose.yaml for development"
```

---

## Task 6: Create Production Docker Compose Override

**Files:**
- Create: `docker-compose.prod.yaml`

**Step 1: Create production override file**

Create `docker-compose.prod.yaml`:

```yaml
version: '3.8'

services:
  # PostgreSQL database (production only)
  postgres:
    image: postgres:16-alpine
    container_name: recon-postgres
    environment:
      POSTGRES_DB: recon
      POSTGRES_USER: recon
      POSTGRES_PASSWORD: ${DB_PASSWORD}
    volumes:
      - postgres_data:/var/lib/postgresql/data
    healthcheck:
      test: ["CMD-SHELL", "pg_isready -U recon"]
      interval: 10s
      timeout: 5s
      retries: 5
    restart: always
    networks:
      - recon-network
    deploy:
      resources:
        limits:
          cpus: '2'
          memory: 2G
    logging:
      driver: "json-file"
      options:
        max-size: "50m"
        max-file: "5"

  # Backend overrides for production
  backend:
    build:
      context: .
      dockerfile: docker/Dockerfile.backend
    volumes:
      - tools_bin:/tools/bin:ro
      - tools_python:/tools/python-tools:ro
      - backend_data:/app/data
      - backend_logs:/app/logs
      - backend_config:/app/config
    environment:
      - DATABASE_URL=postgresql+asyncpg://recon:${DB_PASSWORD}@postgres:5432/recon
      - PYTHONUNBUFFERED=1
      - SCAN_PROFILE=normal
    depends_on:
      postgres:
        condition: service_healthy
      tools:
        condition: service_started
    restart: always
    deploy:
      resources:
        limits:
          cpus: '4'
          memory: 4G
    logging:
      driver: "json-file"
      options:
        max-size: "50m"
        max-file: "5"

  # Frontend overrides for production
  frontend:
    build:
      context: .
      dockerfile: docker/Dockerfile.frontend
      target: production
    volumes: []
    environment:
      - VITE_API_URL=http://backend:8000
      - VITE_WS_URL=ws://backend:8000
    restart: always
    deploy:
      resources:
        limits:
          cpus: '1'
          memory: 512M
    logging:
      driver: "json-file"
      options:
        max-size: "50m"
        max-file: "5"

  # Mitmproxy overrides for production
  mitmproxy:
    volumes:
      - mitmproxy_certs:/root/.mitmproxy
      - mitmproxy_wal:/app/wal
    environment:
      - DATABASE_URL=postgresql+asyncpg://recon:${DB_PASSWORD}@postgres:5432/recon
    restart: always
    deploy:
      resources:
        limits:
          cpus: '2'
          memory: 1G
    logging:
      driver: "json-file"
      options:
        max-size: "50m"
        max-file: "5"

  # Tools container production settings
  tools:
    restart: always
    deploy:
      resources:
        limits:
          cpus: '1'
          memory: 512M

volumes:
  postgres_data:
    name: recon_postgres_data
  backend_data:
    name: recon_backend_data
  backend_logs:
    name: recon_backend_logs
  backend_config:
    name: recon_backend_config
  mitmproxy_certs:
    name: recon_mitmproxy_certs
  mitmproxy_wal:
    name: recon_mitmproxy_wal
```

**Step 2: Verify production config merge**

```bash
docker-compose -f docker-compose.yaml -f docker-compose.prod.yaml config 2>&1 | head -30
```

Expected: Merged config shows postgres service and production overrides

**Step 3: Commit production docker-compose**

```bash
git add docker-compose.prod.yaml
git commit -m "feat: add production docker-compose override with PostgreSQL"
```

---

## Task 7: Create .dockerignore File

**Files:**
- Create: `.dockerignore`

**Step 1: Create .dockerignore**

Create `.dockerignore`:

```
# Python
__pycache__
*.pyc
*.pyo
*.pyd
*.egg-info
.pytest_cache
.coverage

# Virtual environments
recon_env/
venv/
env/

# Data and logs
data/
logs/
*.db
*.db-shm
*.db-wal

# Tools (will be installed in tools container)
tools/

# Git
.git
.gitignore
.gitattributes

# IDE
.vscode/
.cursor/
.idea/
*.swp
*.swo

# Environment files (copied separately)
.env
.env.production

# Documentation (not needed in containers)
*.md
docs/

# Tests (not needed in production)
tests/

# Frontend node_modules (built separately)
node_modules/
frontend/node_modules/
frontend/dist/

# OS
.DS_Store
Thumbs.db

# Worktrees
.worktrees/

# Examples
examples/
```

**Step 2: Verify .dockerignore works**

```bash
cat .dockerignore | wc -l
```

Expected: File has content (45+ lines)

**Step 3: Commit .dockerignore**

```bash
git add .dockerignore
git commit -m "feat: add .dockerignore to exclude unnecessary files from builds"
```

---

## Task 8: Create Helper Scripts

**Files:**
- Create: `scripts/dev-start.sh`
- Create: `scripts/prod-start.sh`
- Create: `scripts/backup.sh`
- Create: `scripts/restore.sh`

**Step 1: Create scripts directory and dev start script**

```bash
mkdir -p scripts
```

Create `scripts/dev-start.sh`:

```bash
#!/bin/bash
set -e

echo "🚀 Starting Security Reconnaissance Platform (Development Mode)"
echo "=================================================="

# Check if .env exists
if [ ! -f .env ]; then
    echo "⚠️  .env file not found. Copying from .env.example..."
    cp .env.example .env
    echo "✅ Created .env file. Please review and update if needed."
fi

# Start services
echo "📦 Building and starting Docker containers..."
docker-compose up --build

echo ""
echo "✅ Development environment started!"
echo "   Frontend: http://localhost:5173"
echo "   Backend API: http://localhost:8000"
echo "   API Docs: http://localhost:8000/docs"
echo "   Mitmproxy: http://localhost:8080"
```

**Step 2: Create production start script**

Create `scripts/prod-start.sh`:

```bash
#!/bin/bash
set -e

echo "🚀 Starting Security Reconnaissance Platform (Production Mode)"
echo "=================================================="

# Check if .env.production exists
if [ ! -f .env.production ]; then
    echo "❌ Error: .env.production file not found!"
    echo "   Please create .env.production with production settings."
    echo "   See .env.example for reference."
    exit 1
fi

# Validate required environment variables
source .env.production
if [ -z "$DB_PASSWORD" ]; then
    echo "❌ Error: DB_PASSWORD not set in .env.production"
    exit 1
fi

if [ -z "$JWT_SECRET_KEY" ]; then
    echo "❌ Error: JWT_SECRET_KEY not set in .env.production"
    exit 1
fi

echo "✅ Environment validation passed"

# Set permissions on .env.production
chmod 600 .env.production

# Start services
echo "📦 Building and starting Docker containers..."
docker-compose -f docker-compose.yaml -f docker-compose.prod.yaml up -d --build

echo ""
echo "⏳ Waiting for services to be healthy..."
sleep 10

# Check service health
docker-compose -f docker-compose.yaml -f docker-compose.prod.yaml ps

echo ""
echo "✅ Production environment started!"
echo "   Frontend: http://localhost:5173"
echo "   Backend API: http://localhost:8000"
echo "   API Docs: http://localhost:8000/docs"
echo "   Mitmproxy: http://localhost:8080"
echo ""
echo "📝 Next steps:"
echo "   1. Install security tools: docker-compose exec backend python main.py --install-tools"
echo "   2. Check logs: docker-compose logs -f"
echo "   3. Monitor health: docker-compose ps"
```

**Step 3: Create backup script**

Create `scripts/backup.sh`:

```bash
#!/bin/bash
set -e

BACKUP_DIR="./backups"
TIMESTAMP=$(date +%Y%m%d_%H%M%S)

echo "💾 Backup Script for Security Reconnaissance Platform"
echo "=================================================="

mkdir -p "$BACKUP_DIR"

# Check if running production or development
if docker ps | grep -q recon-postgres; then
    echo "📦 Backing up PostgreSQL database..."
    docker-compose exec -T postgres pg_dump -U recon recon > "$BACKUP_DIR/postgres_$TIMESTAMP.sql"
    echo "✅ PostgreSQL backup saved to: $BACKUP_DIR/postgres_$TIMESTAMP.sql"

    # Backup volumes
    echo "📦 Backing up Docker volumes..."
    docker run --rm \
        -v recon_postgres_data:/data \
        -v "$(pwd)/$BACKUP_DIR":/backup \
        alpine tar czf /backup/postgres_data_$TIMESTAMP.tar.gz /data
    echo "✅ Volume backup saved to: $BACKUP_DIR/postgres_data_$TIMESTAMP.tar.gz"
else
    echo "📦 Backing up SQLite database..."
    if [ -f ./data/recon.db ]; then
        cp ./data/recon.db "$BACKUP_DIR/recon_$TIMESTAMP.db"
        echo "✅ SQLite backup saved to: $BACKUP_DIR/recon_$TIMESTAMP.db"
    else
        echo "⚠️  No SQLite database found at ./data/recon.db"
    fi
fi

# Backup logs and config
echo "📦 Backing up logs and config..."
tar czf "$BACKUP_DIR/logs_config_$TIMESTAMP.tar.gz" logs/ config/ 2>/dev/null || true
echo "✅ Logs and config backed up to: $BACKUP_DIR/logs_config_$TIMESTAMP.tar.gz"

echo ""
echo "✅ Backup completed successfully!"
echo "   Location: $BACKUP_DIR/"
```

**Step 4: Create restore script**

Create `scripts/restore.sh`:

```bash
#!/bin/bash
set -e

BACKUP_DIR="./backups"

echo "♻️  Restore Script for Security Reconnaissance Platform"
echo "=================================================="

if [ -z "$1" ]; then
    echo "Usage: $0 <backup_timestamp>"
    echo ""
    echo "Available backups:"
    ls -1 "$BACKUP_DIR" | grep -E "\.sql$|\.db$|\.tar\.gz$" | sort -r | head -10
    exit 1
fi

TIMESTAMP=$1

# Check if running production or development
if docker ps | grep -q recon-postgres; then
    echo "📦 Restoring PostgreSQL database..."

    if [ ! -f "$BACKUP_DIR/postgres_$TIMESTAMP.sql" ]; then
        echo "❌ Backup file not found: $BACKUP_DIR/postgres_$TIMESTAMP.sql"
        exit 1
    fi

    # Stop backend to avoid connection issues
    docker-compose stop backend mitmproxy

    # Restore database
    cat "$BACKUP_DIR/postgres_$TIMESTAMP.sql" | docker-compose exec -T postgres psql -U recon recon

    # Restart services
    docker-compose start backend mitmproxy

    echo "✅ PostgreSQL database restored from: $BACKUP_DIR/postgres_$TIMESTAMP.sql"
else
    echo "📦 Restoring SQLite database..."

    if [ ! -f "$BACKUP_DIR/recon_$TIMESTAMP.db" ]; then
        echo "❌ Backup file not found: $BACKUP_DIR/recon_$TIMESTAMP.db"
        exit 1
    fi

    # Stop services
    docker-compose stop

    # Restore database
    cp "$BACKUP_DIR/recon_$TIMESTAMP.db" ./data/recon.db

    # Restart services
    docker-compose start

    echo "✅ SQLite database restored from: $BACKUP_DIR/recon_$TIMESTAMP.db"
fi

echo ""
echo "✅ Restore completed successfully!"
```

**Step 5: Make scripts executable**

```bash
chmod +x scripts/*.sh
```

**Step 6: Verify scripts exist and are executable**

```bash
ls -lh scripts/*.sh
```

Expected: All scripts show with -rwxr-xr-x permissions

**Step 7: Commit helper scripts**

```bash
git add scripts/
git commit -m "feat: add helper scripts for dev, prod, backup, and restore"
```

---

## Task 9: Create Production Environment Template

**Files:**
- Create: `.env.production.example`

**Step 1: Create production env template**

Create `.env.production.example`:

```bash
# Database Configuration (Production)
DATABASE_URL=postgresql+asyncpg://recon:${DB_PASSWORD}@postgres:5432/recon
DB_PASSWORD=CHANGE_ME_GENERATE_STRONG_PASSWORD

# Security
JWT_SECRET_KEY=CHANGE_ME_GENERATE_RANDOM_STRING
ENCRYPTION_ENABLED=true

# Scanning Configuration
SCAN_PROFILE=normal
GLOBAL_RATE_LIMIT=50
DOMAIN_RATE_LIMIT=20

# Phase Toggles
ENABLE_HORIZONTAL=true
ENABLE_PASSIVE=true
ENABLE_ACTIVE=true
ENABLE_WEB_PROBING=true
ENABLE_WEB_DISCOVERY=true
ENABLE_RECURSION=true
RECURSION_DEPTH=3

# Vulnerability Intelligence
ENABLE_VULNERABILITY_INTELLIGENCE=true
VULN_CORRELATION_ENABLED=true
VULN_RULE_BASED_DETECTION=true
VULN_ML_DETECTION=true
EXPLOIT_MATCHING_ENABLED=true
RISK_SCORING_ENABLED=true
PATTERN_LEARNING_ENABLED=true

# Pattern Recognition
ENABLE_PATTERN_RECOGNITION=true
PATTERN_TEMPORAL_ENABLED=true
PATTERN_SPATIAL_ENABLED=true
PATTERN_BEHAVIORAL_ENABLED=true
PATTERN_CHAINING_ENABLED=true
PATTERN_PREDICTIVE_ENABLED=true

# API URLs (Internal Docker Network)
VITE_API_URL=http://backend:8000
VITE_WS_URL=ws://backend:8000

# Logging
LOG_LEVEL=INFO

# Tool Paths
TOOLS_DIRECTORY=/tools/bin

# Generate strong passwords with:
# DB_PASSWORD: openssl rand -base64 32
# JWT_SECRET_KEY: openssl rand -base64 64
```

**Step 2: Verify template is valid**

```bash
cat .env.production.example | grep -c "CHANGE_ME"
```

Expected: 2 (DB_PASSWORD and JWT_SECRET_KEY need changing)

**Step 3: Commit production env template**

```bash
git add .env.production.example
git commit -m "feat: add production environment template"
```

---

## Task 10: Update CLAUDE.md with Docker Information

**Files:**
- Modify: `CLAUDE.md`

**Step 1: Add Docker section to CLAUDE.md**

Add the following section after the "Getting Started" section in `CLAUDE.md`:

```markdown
### Running with Docker (Recommended)

The platform is fully containerized with Docker Compose for both development and production deployments.

**Quick Start - Development:**
```bash
# Start all services (backend, frontend, tools, mitmproxy)
./scripts/dev-start.sh

# Or manually:
docker-compose up --build

# Access the platform:
# - Frontend: http://localhost:5173
# - Backend API: http://localhost:8000/docs
# - Mitmproxy: http://localhost:8080
```

**Quick Start - Production:**
```bash
# 1. Create production environment file
cp .env.production.example .env.production

# 2. Edit .env.production and set secure credentials
nano .env.production

# 3. Start production services
./scripts/prod-start.sh

# 4. Install security tools in backend container
docker-compose exec backend python main.py --install-tools
```

**Container Architecture:**
- `tools`: Pre-built container with 20+ security tools (Go, Python, C binaries)
- `backend`: FastAPI application with Python dependencies
- `frontend`: React application (Vite dev server or Nginx for production)
- `mitmproxy`: HTTP interception proxy for traffic analysis
- `postgres`: PostgreSQL database (production only, dev uses SQLite)

**Useful Commands:**
```bash
# View logs
docker-compose logs -f backend

# Execute commands in backend container
docker-compose exec backend python main.py --check-tools

# Backup database
./scripts/backup.sh

# Restore database
./scripts/restore.sh <timestamp>

# Stop all services
docker-compose down

# Stop and remove volumes (clean slate)
docker-compose down -v
```

**Data Persistence:**
- Development: Uses bind mounts (`./data`, `./logs`, `./config`)
- Production: Uses Docker volumes for database, bind mounts for logs/config

**See `docs/DOCKER_DEPLOYMENT.md` for detailed deployment guide.**
```

**Step 2: Verify CLAUDE.md has the section**

```bash
grep -A 5 "Running with Docker" CLAUDE.md
```

Expected: Shows the newly added section

**Step 3: Commit CLAUDE.md update**

```bash
git add CLAUDE.md
git commit -m "docs: add Docker deployment section to CLAUDE.md"
```

---

## Task 11: Create Docker Deployment Documentation

**Files:**
- Create: `docs/DOCKER_DEPLOYMENT.md`

**Step 1: Create comprehensive Docker documentation**

Create `docs/DOCKER_DEPLOYMENT.md`:

```markdown
# Docker Deployment Guide

Complete guide for deploying the Security Reconnaissance Platform using Docker and Docker Compose.

## Table of Contents

- [Prerequisites](#prerequisites)
- [Architecture Overview](#architecture-overview)
- [Development Deployment](#development-deployment)
- [Production Deployment](#production-deployment)
- [Container Details](#container-details)
- [Data Persistence](#data-persistence)
- [Backup and Restore](#backup-and-restore)
- [Troubleshooting](#troubleshooting)

## Prerequisites

**Required:**
- Docker 20.10+
- Docker Compose 2.0+
- 8GB RAM minimum (16GB recommended for production)
- 20GB free disk space (tools container is ~2GB)

**Install Docker:**
```bash
# Ubuntu/Debian
curl -fsSL https://get.docker.com | sh
sudo usermod -aG docker $USER

# macOS
brew install docker docker-compose

# Windows
# Download Docker Desktop from docker.com
```

## Architecture Overview

### Container Structure

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

### Services

| Service | Purpose | Ports | Dependencies |
|---------|---------|-------|--------------|
| **tools** | 20+ security tools (subfinder, naabu, httpx, etc.) | - | None |
| **backend** | FastAPI API server | 8000 | tools |
| **frontend** | React UI (Vite/Nginx) | 5173 | backend |
| **mitmproxy** | HTTP traffic interception | 8080 | backend |
| **postgres** | Database (prod only) | 5432 | None |

### Volumes

**Development (Bind Mounts):**
- `./data` → `/app/data` (SQLite, API keys, certs)
- `./logs` → `/app/logs` (Application logs)
- `./config` → `/app/config` (Configuration files)

**Production (Docker Volumes):**
- `recon_postgres_data` → PostgreSQL data
- `recon_backend_data` → Application data
- `recon_backend_logs` → Logs (bind mount alternative available)
- `recon_mitmproxy_certs` → SSL certificates

**Shared (All Environments):**
- `recon_tools_bin` → Shared Go/C tool binaries
- `recon_tools_python` → Shared Python tools

## Development Deployment

### Quick Start

```bash
# 1. Clone repository
git clone <repository-url>
cd recon

# 2. Start services
./scripts/dev-start.sh

# 3. Access platform
# Frontend: http://localhost:5173
# API Docs: http://localhost:8000/docs
```

### Manual Start

```bash
# Copy environment template (if not exists)
cp .env.example .env

# Review and update .env if needed
nano .env

# Build and start all services
docker-compose up --build

# Or run in background
docker-compose up -d --build
```

### Development Features

✅ **Hot Reload:**
- Backend: Python code changes auto-reload
- Frontend: Vite dev server with HMR

✅ **SQLite Database:**
- No separate database container needed
- Database file at `./data/recon.db`

✅ **Bind Mounts:**
- Easy access to logs and data
- Direct file editing

✅ **Fast Iteration:**
- Code changes reflected immediately
- No rebuild needed for application code

### Useful Development Commands

```bash
# View logs (all services)
docker-compose logs -f

# View specific service logs
docker-compose logs -f backend

# Execute commands in backend
docker-compose exec backend python main.py --check-tools
docker-compose exec backend python main.py --install-tools

# Access backend shell
docker-compose exec backend bash

# Restart specific service
docker-compose restart backend

# Stop all services
docker-compose down

# Stop and remove everything (including volumes)
docker-compose down -v
```

## Production Deployment

### Initial Setup

```bash
# 1. Clone repository
git clone <repository-url>
cd recon

# 2. Create production environment file
cp .env.production.example .env.production

# 3. Generate strong credentials
DB_PASSWORD=$(openssl rand -base64 32)
JWT_SECRET=$(openssl rand -base64 64)

# 4. Edit .env.production
nano .env.production
# Set DB_PASSWORD and JWT_SECRET_KEY

# 5. Secure environment file
chmod 600 .env.production

# 6. Start production services
./scripts/prod-start.sh
```

### Manual Production Start

```bash
# Build and start with production overrides
docker-compose -f docker-compose.yaml -f docker-compose.prod.yaml up -d --build

# Wait for services to be healthy
sleep 10

# Check service status
docker-compose ps

# Install security tools
docker-compose exec backend python main.py --install-tools

# Check tool status
docker-compose exec backend python main.py --check-tools
```

### Production Configuration

**Environment Variables (.env.production):**

```bash
# Database
DB_PASSWORD=<strong-random-password>

# Security
JWT_SECRET_KEY=<strong-random-string>

# Scanning
SCAN_PROFILE=normal  # or aggressive for faster scans

# Features (enable as needed)
ENABLE_WEB_DISCOVERY=true
ENABLE_RECURSION=true
RECURSION_DEPTH=3
```

**Resource Limits:**

Services have CPU/memory limits in production:
- Backend: 4 CPUs, 4GB RAM
- PostgreSQL: 2 CPUs, 2GB RAM
- Frontend: 1 CPU, 512MB RAM
- Mitmproxy: 2 CPUs, 1GB RAM
- Tools: 1 CPU, 512MB RAM

**Adjust in `docker-compose.prod.yaml` if needed.**

### Production Monitoring

```bash
# Check service health
docker-compose ps

# View resource usage
docker stats

# Comprehensive health check
curl http://localhost:8000/api/health/comprehensive | jq

# Monitor logs
docker-compose logs -f --tail=100

# Database connection test
docker-compose exec postgres psql -U recon -c "SELECT version();"
```

### Production Best Practices

✅ **Security:**
- Never commit `.env.production` to git
- Use `chmod 600 .env.production`
- Rotate secrets regularly
- Keep Docker images updated

✅ **Backups:**
- Run `./scripts/backup.sh` daily
- Store backups off-server
- Test restore procedure regularly

✅ **Updates:**
```bash
# Pull latest code
git pull

# Rebuild with new code
docker-compose -f docker-compose.yaml -f docker-compose.prod.yaml up -d --build

# Check for issues
docker-compose logs -f
```

✅ **Monitoring:**
- Check logs regularly: `docker-compose logs`
- Monitor disk usage: `df -h`
- Monitor container health: `docker-compose ps`

## Container Details

### Tools Container

**Purpose:** Pre-built container with all security tools installed.

**Tools Included:**
- **Go Tools (15):** subfinder, assetfinder, httpx, naabu, dnsx, mapcidr, gotator, gospider, unfurl, gobuster, anew, gau, waybackurls, github-subdomains, gitlab-subdomains
- **Python Tools (4):** ctfr, favup, secretfinder, hosthunter
- **C Tools (1):** massdns
- **System Tools:** nmap, git, make

**Volume Sharing:**
- Go/C binaries → `/tools/bin` (shared with backend)
- Python tools → `/tools/python-tools` (shared with backend)

**Build Time:** ~15-20 minutes (first build), cached afterwards

**Rebuild Tools:**
```bash
docker-compose build --no-cache tools
```

### Backend Container

**Purpose:** FastAPI application server.

**Features:**
- Python 3.11 slim base
- Multi-stage build (dependencies cached)
- Tools available via shared volumes
- Health check on `/health` endpoint

**Environment:**
- `PATH` includes `/tools/bin` and `/tools/python-tools`
- `PYTHONPATH` includes `/tools/python-tools`

**Logs Location:**
- Container: `/app/logs`
- Host (dev): `./logs`
- Host (prod): Docker volume `recon_backend_logs`

### Frontend Container

**Purpose:** React UI with Vite (dev) or Nginx (prod).

**Development:**
- Base: `node:20-alpine`
- Server: Vite dev server
- Hot reload: Enabled
- Port: 5173

**Production:**
- Base: `nginx:alpine`
- Optimized build with caching
- Gzip compression enabled
- Security headers added

### Mitmproxy Container

**Purpose:** HTTP/HTTPS traffic interception and analysis.

**Features:**
- mitmproxy 10.1.5
- Custom interceptor addon
- WAL (Write-Ahead Log) for resilience
- Pattern-based vulnerability detection

**Certificates:**
- Generated on first run
- Stored in `./data/certs` (dev) or volume (prod)
- Install CA cert for HTTPS interception

**Traffic Storage:**
- WAL: `/app/wal`
- Database: Configured via `DATABASE_URL`

### PostgreSQL Container

**Purpose:** Production database (not used in development).

**Configuration:**
- Version: PostgreSQL 16 Alpine
- User: `recon`
- Database: `recon`
- Password: From `DB_PASSWORD` env var

**Health Check:**
- Command: `pg_isready -U recon`
- Interval: 10 seconds

**Backup:**
```bash
docker-compose exec postgres pg_dump -U recon recon > backup.sql
```

## Data Persistence

### Development

**Bind Mounts** (host directories mounted into containers):

```yaml
./data   → /app/data    # SQLite DB, API keys, certs
./logs   → /app/logs    # Application logs
./config → /app/config  # Configuration files
```

**Advantages:**
- Easy to inspect files
- Direct editing possible
- Simple backup (copy files)

**Disadvantages:**
- File permissions can be tricky
- Slower on macOS/Windows (Docker Desktop)

### Production

**Docker Volumes** (Docker-managed storage):

```yaml
recon_postgres_data     # PostgreSQL data
recon_backend_data      # Application data
recon_backend_logs      # Logs (optional, can use bind mount)
recon_mitmproxy_certs   # SSL certificates
recon_mitmproxy_wal     # Traffic WAL
```

**Advantages:**
- Better performance
- Docker-managed lifecycle
- Portable across hosts

**Disadvantages:**
- Requires Docker commands to access
- Backup needs special handling

### Volume Management

```bash
# List volumes
docker volume ls

# Inspect volume
docker volume inspect recon_postgres_data

# Backup volume
docker run --rm \
  -v recon_postgres_data:/data \
  -v $(pwd)/backups:/backup \
  alpine tar czf /backup/postgres_data.tar.gz /data

# Restore volume
docker run --rm \
  -v recon_postgres_data:/data \
  -v $(pwd)/backups:/backup \
  alpine tar xzf /backup/postgres_data.tar.gz -C /

# Remove volume (WARNING: deletes data!)
docker volume rm recon_postgres_data
```

## Backup and Restore

### Automated Backup

```bash
# Run backup script
./scripts/backup.sh

# Creates:
# - backups/postgres_YYYYMMDD_HHMMSS.sql (if using PostgreSQL)
# - backups/recon_YYYYMMDD_HHMMSS.db (if using SQLite)
# - backups/logs_config_YYYYMMDD_HHMMSS.tar.gz
```

### Manual Backup

**PostgreSQL (Production):**
```bash
# SQL dump
docker-compose exec postgres pg_dump -U recon recon > backup.sql

# Volume backup
docker run --rm \
  -v recon_postgres_data:/data \
  -v $(pwd):/backup \
  alpine tar czf /backup/postgres_volume.tar.gz /data
```

**SQLite (Development):**
```bash
# Simple copy
cp ./data/recon.db ./backups/recon_$(date +%Y%m%d).db
```

### Restore

```bash
# Using restore script
./scripts/restore.sh 20251014_120000

# Manual PostgreSQL restore
cat backup.sql | docker-compose exec -T postgres psql -U recon recon

# Manual SQLite restore
cp backups/recon_20251014.db ./data/recon.db
docker-compose restart backend
```

### Backup Best Practices

✅ **Schedule:** Daily automated backups (add to cron)
✅ **Retention:** Keep 7 daily, 4 weekly, 12 monthly
✅ **Off-site:** Store backups remotely (S3, rsync, etc.)
✅ **Testing:** Test restore monthly
✅ **Monitoring:** Alert on backup failures

**Example Cron:**
```bash
# Daily backup at 2 AM
0 2 * * * cd /path/to/recon && ./scripts/backup.sh >> /var/log/recon-backup.log 2>&1
```

## Troubleshooting

### Container Won't Start

**Check logs:**
```bash
docker-compose logs <service-name>
```

**Common issues:**
- Port already in use: Change port in docker-compose.yaml
- Volume permission denied: Check file ownership
- Out of memory: Reduce resource limits or add RAM

### Tools Not Found in Backend

**Verify tools container:**
```bash
# Check tools are built
docker-compose exec tools ls -la /tools/bin

# Check backend can see tools
docker-compose exec backend ls -la /tools/bin

# Check PATH
docker-compose exec backend echo $PATH
```

**Rebuild tools container:**
```bash
docker-compose build --no-cache tools
docker-compose restart backend
```

### Database Connection Failed

**Development (SQLite):**
```bash
# Check database file exists
ls -la ./data/recon.db

# Check permissions
chmod 644 ./data/recon.db

# Check DATABASE_URL in .env
grep DATABASE_URL .env
```

**Production (PostgreSQL):**
```bash
# Check postgres is healthy
docker-compose ps postgres

# Check connection from backend
docker-compose exec backend python -c "
from sqlalchemy import create_engine, text
import os
engine = create_engine(os.getenv('DATABASE_URL'))
with engine.connect() as conn:
    result = conn.execute(text('SELECT version()'))
    print(result.fetchone())
"

# Check DATABASE_URL
docker-compose exec backend env | grep DATABASE_URL
```

### Frontend Can't Reach Backend

**Check environment variables:**
```bash
# In development
docker-compose exec frontend env | grep VITE

# Should be:
# VITE_API_URL=http://localhost:8000
# VITE_WS_URL=ws://localhost:8000
```

**Check network:**
```bash
# Containers should be on same network
docker network inspect recon-network

# Test backend from frontend container
docker-compose exec frontend wget -O- http://backend:8000/health
```

### Build Fails

**Clear Docker cache:**
```bash
# Remove old images
docker-compose down --rmi all

# Clear build cache
docker builder prune -a

# Rebuild from scratch
docker-compose build --no-cache
```

**Check disk space:**
```bash
df -h
docker system df
```

### Performance Issues

**Check resource usage:**
```bash
docker stats
```

**Increase resources:**
- Edit `docker-compose.prod.yaml` deploy limits
- Increase Docker Desktop resources (macOS/Windows)

**Optimize:**
- Reduce `GLOBAL_RATE_LIMIT` in .env
- Disable unnecessary phases
- Use `SCAN_PROFILE=passive` for slower scans

### Logs Too Large

**Configure log rotation:**

Already configured in docker-compose files:
```yaml
logging:
  driver: "json-file"
  options:
    max-size: "10m"  # Max 10MB per file
    max-file: "3"    # Keep 3 files
```

**Manual cleanup:**
```bash
# Clear all logs
docker-compose down
docker system prune -a --volumes

# Or truncate specific container logs
: > $(docker inspect --format='{{.LogPath}}' recon-backend)
```

### Mitmproxy Certificate Issues

**Regenerate certificates:**
```bash
# Remove old certs
rm -rf ./data/certs/*

# Restart mitmproxy
docker-compose restart mitmproxy

# New certs generated at:
# ./data/certs/mitmproxy-ca-cert.pem
```

**Install CA certificate:**
```bash
# Copy cert
docker-compose exec mitmproxy cat /root/.mitmproxy/mitmproxy-ca-cert.pem > mitmproxy-ca.pem

# Install system-wide (Ubuntu)
sudo cp mitmproxy-ca.pem /usr/local/share/ca-certificates/mitmproxy-ca.crt
sudo update-ca-certificates
```

---

## Additional Resources

- **Docker Documentation:** https://docs.docker.com
- **Docker Compose:** https://docs.docker.com/compose
- **Project README:** `../README.md`
- **CLAUDE.md:** `../CLAUDE.md`
- **API Documentation:** http://localhost:8000/docs (when running)

## Support

For issues or questions:
1. Check this troubleshooting guide
2. Review container logs: `docker-compose logs`
3. Check GitHub Issues
4. Consult `CLAUDE.md` for architecture details
```

**Step 2: Verify documentation is complete**

```bash
wc -l docs/DOCKER_DEPLOYMENT.md
```

Expected: 500+ lines of comprehensive documentation

**Step 3: Commit Docker deployment documentation**

```bash
git add docs/DOCKER_DEPLOYMENT.md
git commit -m "docs: add comprehensive Docker deployment guide"
```

---

## Task 12: Final Verification and Testing

**Step 1: Verify all files created**

```bash
ls -la docker/
ls -la scripts/
ls -la docs/plans/
```

Expected: All Docker files, scripts, and documentation present

**Step 2: Test docker-compose configuration**

```bash
docker-compose config > /dev/null && echo "✅ Base config valid" || echo "❌ Base config invalid"
docker-compose -f docker-compose.yaml -f docker-compose.prod.yaml config > /dev/null && echo "✅ Production config valid" || echo "❌ Production config invalid"
```

Expected: Both configurations validate successfully

**Step 3: Create final summary commit**

```bash
git add -A
git commit -m "feat: complete Docker containerization implementation

- Multi-container architecture (backend, frontend, tools, mitmproxy, postgres)
- Development and production configurations
- Automated helper scripts for deployment and backup
- Comprehensive documentation
- SQLite for dev, PostgreSQL for production
- Shared tools container with 20+ security tools"
```

**Step 4: View implementation summary**

```bash
git log --oneline -12
```

Expected: Shows all commits from the implementation

---

## Summary

This plan implements complete Docker containerization for the Security Reconnaissance Platform with:

✅ **5 Dockerfiles:** Tools, Backend, Frontend, Mitmproxy, (PostgreSQL uses official image)
✅ **2 Compose Files:** Base (dev) and production override
✅ **4 Helper Scripts:** Dev start, prod start, backup, restore
✅ **Documentation:** CLAUDE.md updated, comprehensive deployment guide
✅ **Environment Management:** Development and production configurations
✅ **Data Persistence:** Hybrid approach with volumes and bind mounts

**Next Steps After Implementation:**
1. Test development deployment: `./scripts/dev-start.sh`
2. Verify all containers start successfully
3. Test tool availability in backend container
4. Test production deployment in staging environment
5. Create pull request for review
