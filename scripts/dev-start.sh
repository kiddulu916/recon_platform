#!/bin/bash
set -e

echo "🚀 Starting Security Reconnaissance Platform (Development Mode)"
echo "================================================================="
echo ""

# Check if Docker is running
if ! docker info > /dev/null 2>&1; then
    echo "❌ Error: Docker is not running!"
    echo "   Please start Docker and try again."
    exit 1
fi

echo "✅ Docker is running"

# Check if .env exists
if [ ! -f .env ]; then
    echo "⚠️  .env file not found. Copying from .env.example..."
    if [ -f .env.example ]; then
        cp .env.example .env
        echo "✅ Created .env file. Please review and update if needed."
    else
        echo "❌ Error: .env.example not found!"
        exit 1
    fi
fi

echo "✅ Environment file found"
echo ""

# Pull latest images (optional, commented out for faster startup)
# echo "📦 Pulling latest base images..."
# docker-compose pull

# Start services
echo "📦 Building and starting Docker containers..."
echo "   This may take a few minutes on first run..."
echo ""

docker-compose up --build

echo ""
echo "✅ Development environment started!"
echo ""
echo "Access the platform:"
echo "   Frontend:    http://localhost:5173"
echo "   Backend API: http://localhost:8000"
echo "   API Docs:    http://localhost:8000/docs"
echo "   Mitmproxy:   http://localhost:8080"
echo ""
echo "To stop: Press Ctrl+C"
echo "To run in background: docker-compose up -d --build"
