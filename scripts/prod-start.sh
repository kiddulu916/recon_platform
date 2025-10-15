#!/bin/bash
set -e

echo "🚀 Starting Security Reconnaissance Platform (Production Mode)"
echo "================================================================"
echo ""

# Check if Docker is running
if ! docker info > /dev/null 2>&1; then
    echo "❌ Error: Docker is not running!"
    echo "   Please start Docker and try again."
    exit 1
fi

echo "✅ Docker is running"

# Check if .env.production exists
if [ ! -f .env.production ]; then
    echo "❌ Error: .env.production file not found!"
    echo ""
    echo "Please create .env.production with production settings."
    echo "You can use .env.production.example as a template:"
    echo ""
    echo "  cp .env.production.example .env.production"
    echo "  nano .env.production"
    echo ""
    echo "Make sure to set:"
    echo "  - DB_PASSWORD (generate with: openssl rand -base64 32)"
    echo "  - JWT_SECRET_KEY (generate with: openssl rand -base64 64)"
    exit 1
fi

echo "✅ Environment file found"

# Validate required environment variables
source .env.production

if [ -z "$DB_PASSWORD" ]; then
    echo "❌ Error: DB_PASSWORD not set in .env.production"
    echo "   Generate one with: openssl rand -base64 32"
    exit 1
fi

if [ -z "$JWT_SECRET_KEY" ]; then
    echo "❌ Error: JWT_SECRET_KEY not set in .env.production"
    echo "   Generate one with: openssl rand -base64 64"
    exit 1
fi

# Check for CHANGE_ME placeholders
if grep -q "CHANGE_ME" .env.production; then
    echo "⚠️  Warning: .env.production contains CHANGE_ME placeholders!"
    echo "   Please replace all CHANGE_ME values with actual credentials."
    read -p "Continue anyway? (y/N) " -n 1 -r
    echo
    if [[ ! $REPLY =~ ^[Yy]$ ]]; then
        exit 1
    fi
fi

echo "✅ Environment validation passed"

# Set permissions on .env.production
chmod 600 .env.production
echo "✅ Secured .env.production (permissions: 600)"
echo ""

# Start services
echo "📦 Building and starting Docker containers..."
echo "   This may take several minutes..."
echo ""

docker-compose -f docker-compose.yaml -f docker-compose.prod.yaml up -d --build

echo ""
echo "⏳ Waiting for services to be healthy..."
sleep 10

# Check service health
echo ""
echo "Service Status:"
docker-compose -f docker-compose.yaml -f docker-compose.prod.yaml ps

echo ""
echo "✅ Production environment started!"
echo ""
echo "Access the platform:"
echo "   Frontend:    http://localhost:5173"
echo "   Backend API: http://localhost:8000"
echo "   API Docs:    http://localhost:8000/docs"
echo "   Mitmproxy:   http://localhost:8080"
echo ""
echo "📝 Next steps:"
echo "   1. Check logs:    docker-compose -f docker-compose.yaml -f docker-compose.prod.yaml logs -f"
echo "   2. Monitor health: docker-compose -f docker-compose.yaml -f docker-compose.prod.yaml ps"
echo "   3. Stop services: docker-compose -f docker-compose.yaml -f docker-compose.prod.yaml down"
echo ""
echo "To install security tools (if not already installed):"
echo "   docker-compose -f docker-compose.yaml -f docker-compose.prod.yaml exec backend python main.py --install-tools"
