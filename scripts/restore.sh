#!/bin/bash
set -e

echo "♻️  Restore Script for Security Reconnaissance Platform"
echo "========================================================"
echo ""

# Default backup directory
BACKUP_DIR="${2:-./backups}"

# Check if timestamp provided
if [ -z "$1" ]; then
    echo "Usage: $0 <backup_timestamp> [backup_directory]"
    echo ""
    echo "Examples:"
    echo "   $0 20251014_120000"
    echo "   $0 20251014_120000 ./backups"
    echo ""
    echo "Available backups in $BACKUP_DIR:"
    if [ -d "$BACKUP_DIR" ]; then
        ls -1 "$BACKUP_DIR" | grep -E "\.sql$|\.db$|\.tar\.gz$" | sort -r | head -20
    else
        echo "   (Backup directory does not exist)"
    fi
    exit 1
fi

TIMESTAMP=$1

echo "Restore timestamp: $TIMESTAMP"
echo "Backup location: $BACKUP_DIR"
echo ""

# Check if running production or development
if docker ps | grep -q recon-postgres; then
    echo "📦 Detected PostgreSQL (Production Mode)"
    echo ""

    # Check if backup file exists
    if [ ! -f "$BACKUP_DIR/postgres_$TIMESTAMP.sql" ]; then
        echo "❌ Error: Backup file not found: $BACKUP_DIR/postgres_$TIMESTAMP.sql"
        echo ""
        echo "Available PostgreSQL backups:"
        ls -1 "$BACKUP_DIR" | grep "postgres_.*\.sql$" | sort -r | head -10
        exit 1
    fi

    # Confirm restore
    echo "⚠️  WARNING: This will replace the current database!"
    echo "   Backup file: $BACKUP_DIR/postgres_$TIMESTAMP.sql"
    read -p "Continue with restore? (yes/N) " -n 3 -r
    echo
    if [[ ! $REPLY =~ ^[Yy][Ee][Ss]$ ]]; then
        echo "Restore cancelled."
        exit 0
    fi

    echo ""
    echo "Stopping backend and mitmproxy to avoid connection issues..."
    docker-compose -f docker-compose.yaml -f docker-compose.prod.yaml stop backend mitmproxy

    echo "Restoring PostgreSQL database..."
    cat "$BACKUP_DIR/postgres_$TIMESTAMP.sql" | docker-compose -f docker-compose.yaml -f docker-compose.prod.yaml exec -T postgres psql -U recon recon

    echo "Restarting services..."
    docker-compose -f docker-compose.yaml -f docker-compose.prod.yaml start backend mitmproxy

    echo ""
    echo "✅ PostgreSQL database restored from: $BACKUP_DIR/postgres_$TIMESTAMP.sql"

else
    echo "📦 Detected SQLite (Development Mode)"
    echo ""

    # Check if backup file exists
    if [ ! -f "$BACKUP_DIR/recon_$TIMESTAMP.db" ]; then
        echo "❌ Error: Backup file not found: $BACKUP_DIR/recon_$TIMESTAMP.db"
        echo ""
        echo "Available SQLite backups:"
        ls -1 "$BACKUP_DIR" | grep "recon_.*\.db$" | sort -r | head -10
        exit 1
    fi

    # Confirm restore
    echo "⚠️  WARNING: This will replace the current database!"
    echo "   Backup file: $BACKUP_DIR/recon_$TIMESTAMP.db"
    read -p "Continue with restore? (yes/N) " -n 3 -r
    echo
    if [[ ! $REPLY =~ ^[Yy][Ee][Ss]$ ]]; then
        echo "Restore cancelled."
        exit 0
    fi

    echo ""
    echo "Stopping services..."
    docker-compose stop

    # Create backup of current database before restore
    if [ -f ./data/recon.db ]; then
        echo "Creating safety backup of current database..."
        cp ./data/recon.db ./data/recon.db.pre-restore-$(date +%Y%m%d_%H%M%S)
    fi

    # Ensure data directory exists
    mkdir -p ./data

    echo "Restoring SQLite database..."
    cp "$BACKUP_DIR/recon_$TIMESTAMP.db" ./data/recon.db

    echo "Restarting services..."
    docker-compose start

    echo ""
    echo "✅ SQLite database restored from: $BACKUP_DIR/recon_$TIMESTAMP.db"
fi

# Optionally restore logs/config if available
if [ -f "$BACKUP_DIR/logs_config_$TIMESTAMP.tar.gz" ]; then
    read -p "Restore logs and config as well? (y/N) " -n 1 -r
    echo
    if [[ $REPLY =~ ^[Yy]$ ]]; then
        echo "Restoring logs and config..."
        tar xzf "$BACKUP_DIR/logs_config_$TIMESTAMP.tar.gz"
        echo "✅ Logs and config restored"
    fi
fi

echo ""
echo "✅ Restore completed successfully!"
echo ""
echo "Check service status:"
if docker ps | grep -q recon-postgres; then
    echo "   docker-compose -f docker-compose.yaml -f docker-compose.prod.yaml ps"
    echo "   docker-compose -f docker-compose.yaml -f docker-compose.prod.yaml logs -f"
else
    echo "   docker-compose ps"
    echo "   docker-compose logs -f"
fi
