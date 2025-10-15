#!/bin/bash
set -e

echo "💾 Backup Script for Security Reconnaissance Platform"
echo "======================================================"
echo ""

# Default backup directory
BACKUP_DIR="${1:-./backups}"
TIMESTAMP=$(date +%Y%m%d_%H%M%S)

# Create backup directory if it doesn't exist
mkdir -p "$BACKUP_DIR"

echo "Backup location: $BACKUP_DIR"
echo "Timestamp: $TIMESTAMP"
echo ""

# Check if running production or development
if docker ps | grep -q recon-postgres; then
    echo "📦 Detected PostgreSQL (Production Mode)"
    echo "   Backing up PostgreSQL database..."

    # Check if postgres container is running
    if ! docker-compose -f docker-compose.yaml -f docker-compose.prod.yaml ps postgres | grep -q "Up"; then
        echo "❌ Error: PostgreSQL container is not running!"
        exit 1
    fi

    # Backup PostgreSQL database
    docker-compose -f docker-compose.yaml -f docker-compose.prod.yaml exec -T postgres pg_dump -U recon recon > "$BACKUP_DIR/postgres_$TIMESTAMP.sql"
    echo "   ✅ PostgreSQL backup saved to: $BACKUP_DIR/postgres_$TIMESTAMP.sql"

    # Backup PostgreSQL data volume
    echo "   Backing up PostgreSQL data volume..."
    docker run --rm \
        -v recon_postgres_data:/data \
        -v "$(pwd)/$BACKUP_DIR":/backup \
        alpine tar czf /backup/postgres_data_$TIMESTAMP.tar.gz -C / data
    echo "   ✅ Volume backup saved to: $BACKUP_DIR/postgres_data_$TIMESTAMP.tar.gz"

    # Backup backend data volume
    if docker volume ls | grep -q recon_backend_data; then
        echo "   Backing up backend data volume..."
        docker run --rm \
            -v recon_backend_data:/data \
            -v "$(pwd)/$BACKUP_DIR":/backup \
            alpine tar czf /backup/backend_data_$TIMESTAMP.tar.gz -C / data
        echo "   ✅ Backend data backup saved to: $BACKUP_DIR/backend_data_$TIMESTAMP.tar.gz"
    fi

else
    echo "📦 Detected SQLite (Development Mode)"

    # Backup SQLite database
    if [ -f ./data/recon.db ]; then
        echo "   Backing up SQLite database..."
        cp ./data/recon.db "$BACKUP_DIR/recon_$TIMESTAMP.db"
        echo "   ✅ SQLite backup saved to: $BACKUP_DIR/recon_$TIMESTAMP.db"
    else
        echo "   ⚠️  No SQLite database found at ./data/recon.db"
    fi

    # Backup entire data directory if it exists
    if [ -d ./data ]; then
        echo "   Backing up data directory..."
        tar czf "$BACKUP_DIR/data_$TIMESTAMP.tar.gz" ./data 2>/dev/null || true
        echo "   ✅ Data directory backed up to: $BACKUP_DIR/data_$TIMESTAMP.tar.gz"
    fi
fi

# Backup logs and config (both dev and prod)
if [ -d ./logs ] || [ -d ./config ]; then
    echo "📦 Backing up logs and config..."
    tar czf "$BACKUP_DIR/logs_config_$TIMESTAMP.tar.gz" logs/ config/ 2>/dev/null || true
    echo "   ✅ Logs and config backed up to: $BACKUP_DIR/logs_config_$TIMESTAMP.tar.gz"
fi

# Calculate backup size
echo ""
echo "📊 Backup Summary:"
echo "   Location: $BACKUP_DIR/"
ls -lh "$BACKUP_DIR"/*"$TIMESTAMP"* 2>/dev/null | awk '{print "   - " $9 " (" $5 ")"}'

echo ""
echo "✅ Backup completed successfully!"
echo ""
echo "To restore this backup:"
echo "   ./scripts/restore.sh $TIMESTAMP"
