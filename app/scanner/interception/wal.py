"""
Write-Ahead Log (WAL) System for HTTP Traffic

Provides immediate, resilient persistence of HTTP traffic data
before structured database processing.

Features:
- Async file I/O for performance
- msgpack serialization for efficiency
- Automatic file rotation
- Buffer management
- Error recovery
"""

import asyncio
import uuid
from pathlib import Path
from typing import Dict, Any, List, Optional
from datetime import datetime, timedelta
import aiofiles
import msgpack
import structlog

logger = structlog.get_logger()


class WALWriter:
    """
    Write-Ahead Log writer for immediate traffic capture
    
    Writes traffic data to msgpack files with automatic rotation.
    Designed for high-throughput, low-latency writes.
    """
    
    def __init__(self, config):
        """
        Initialize WAL writer
        
        Args:
            config: Application configuration
        """
        self.config = config
        self.logger = logger.bind(component="wal_writer")
        
        # WAL directory
        self.wal_dir = Path(config.proxy.wal_directory)
        self.wal_dir.mkdir(parents=True, exist_ok=True)
        
        # Current WAL file
        self._current_file: Optional[Path] = None
        self._current_file_size = 0
        self._current_file_start_time: Optional[datetime] = None
        
        # Buffer for batching writes
        self._buffer: List[Dict[str, Any]] = []
        self._buffer_lock = asyncio.Lock()
        
        # Rotation thresholds
        self._max_size_bytes = config.proxy.wal_max_size_mb * 1024 * 1024
        self._max_age = timedelta(hours=config.proxy.wal_max_age_hours)
        self._buffer_size = config.proxy.wal_buffer_size
        
        # Statistics
        self.stats = {
            "entries_written": 0,
            "files_created": 0,
            "rotations": 0,
            "errors": 0,
            "bytes_written": 0
        }
    
    def write(self, traffic_data: Dict[str, Any]):
        """
        Write traffic data to WAL (non-async wrapper)
        
        Args:
            traffic_data: Traffic data dictionary
        """
        # Create async task
        asyncio.create_task(self.write_async(traffic_data))
    
    async def write_async(self, traffic_data: Dict[str, Any]):
        """
        Write traffic data to WAL asynchronously
        
        Args:
            traffic_data: Traffic data dictionary
        """
        try:
            async with self._buffer_lock:
                # Add to buffer
                entry = {
                    "wal_id": str(uuid.uuid4()),
                    "timestamp": datetime.utcnow().isoformat(),
                    "data": traffic_data
                }
                self._buffer.append(entry)
                
                # Flush if buffer is full
                if len(self._buffer) >= self._buffer_size:
                    await self._flush_buffer()
        
        except Exception as e:
            self.logger.error("Error writing to WAL", error=str(e))
            self.stats["errors"] += 1
    
    async def _flush_buffer(self):
        """
        Flush buffer to disk
        
        Called when buffer is full or on demand.
        """
        if not self._buffer:
            return
        
        try:
            # Check if rotation needed
            await self._check_rotation()
            
            # Ensure we have a current file
            if not self._current_file:
                await self._create_new_file()
            
            # Serialize entries
            entries_data = msgpack.packb(self._buffer)
            
            # Write to file
            async with aiofiles.open(self._current_file, 'ab') as f:
                await f.write(entries_data)
            
            # Update statistics
            entries_written = len(self._buffer)
            bytes_written = len(entries_data)
            
            self.stats["entries_written"] += entries_written
            self.stats["bytes_written"] += bytes_written
            self._current_file_size += bytes_written
            
            self.logger.debug(
                "Buffer flushed",
                entries=entries_written,
                bytes=bytes_written,
                file=self._current_file.name
            )
            
            # Clear buffer
            self._buffer.clear()
        
        except Exception as e:
            self.logger.error("Error flushing buffer", error=str(e))
            self.stats["errors"] += 1
            raise
    
    async def _check_rotation(self):
        """Check if rotation is needed and perform if necessary"""
        if not self._current_file or not self._current_file_start_time:
            return
        
        needs_rotation = False
        
        # Check size threshold
        if self._current_file_size >= self._max_size_bytes:
            self.logger.info(
                "WAL rotation: size threshold",
                current_size=self._current_file_size,
                max_size=self._max_size_bytes
            )
            needs_rotation = True
        
        # Check age threshold
        age = datetime.utcnow() - self._current_file_start_time
        if age >= self._max_age:
            self.logger.info(
                "WAL rotation: age threshold",
                age_hours=age.total_seconds() / 3600,
                max_hours=self._max_age.total_seconds() / 3600
            )
            needs_rotation = True
        
        if needs_rotation:
            await self._rotate_file()
    
    async def _rotate_file(self):
        """Rotate to a new WAL file"""
        # Flush any pending writes
        if self._buffer:
            # Temporarily clear buffer to avoid recursion
            buffer_backup = self._buffer.copy()
            self._buffer.clear()
            
            # Write current buffer
            entries_data = msgpack.packb(buffer_backup)
            if self._current_file:
                async with aiofiles.open(self._current_file, 'ab') as f:
                    await f.write(entries_data)
        
        # Create new file
        await self._create_new_file()
        
        self.stats["rotations"] += 1
    
    async def _create_new_file(self):
        """Create a new WAL file"""
        timestamp = datetime.utcnow().strftime("%Y%m%d_%H%M%S")
        file_id = str(uuid.uuid4())[:8]
        filename = f"wal_{timestamp}_{file_id}.msgpack"
        
        self._current_file = self.wal_dir / filename
        self._current_file_size = 0
        self._current_file_start_time = datetime.utcnow()
        
        # Create empty file
        async with aiofiles.open(self._current_file, 'wb') as f:
            pass
        
        self.stats["files_created"] += 1
        
        self.logger.info("Created new WAL file", filename=filename)
    
    async def flush(self):
        """Force flush buffer to disk"""
        async with self._buffer_lock:
            if self._buffer:
                await self._flush_buffer()
    
    async def close(self):
        """Close WAL writer and flush any pending writes"""
        await self.flush()
        self.logger.info("WAL writer closed", stats=self.stats)
    
    def get_stats(self) -> Dict[str, Any]:
        """Get WAL writer statistics"""
        return {
            **self.stats,
            "current_file": str(self._current_file) if self._current_file else None,
            "current_file_size": self._current_file_size,
            "buffer_size": len(self._buffer),
            "current_file_age_seconds": (
                (datetime.utcnow() - self._current_file_start_time).total_seconds()
                if self._current_file_start_time else 0
            )
        }


class WALReader:
    """
    WAL reader for processing traffic entries
    
    Reads and deserializes traffic data from WAL files.
    """
    
    def __init__(self, config):
        """
        Initialize WAL reader
        
        Args:
            config: Application configuration
        """
        self.config = config
        self.logger = logger.bind(component="wal_reader")
        self.wal_dir = Path(config.proxy.wal_directory)
    
    def list_wal_files(self) -> List[Path]:
        """
        List all WAL files in order
        
        Returns:
            List of WAL file paths, sorted by creation time
        """
        if not self.wal_dir.exists():
            return []
        
        wal_files = list(self.wal_dir.glob("wal_*.msgpack"))
        return sorted(wal_files, key=lambda p: p.stat().st_mtime)
    
    async def read_file(self, file_path: Path) -> List[Dict[str, Any]]:
        """
        Read all entries from a WAL file
        
        Args:
            file_path: Path to WAL file
        
        Returns:
            List of traffic entry dictionaries
        """
        try:
            async with aiofiles.open(file_path, 'rb') as f:
                content = await f.read()
            
            if not content:
                return []
            
            # Deserialize
            entries = msgpack.unpackb(content, raw=False)
            
            self.logger.debug("Read WAL file", file=file_path.name, entries=len(entries))
            
            return entries
        
        except Exception as e:
            self.logger.error("Error reading WAL file", file=str(file_path), error=str(e))
            return []
    
    async def read_unprocessed(self, limit: Optional[int] = None) -> List[tuple[Path, List[Dict[str, Any]]]]:
        """
        Read unprocessed WAL files
        
        Args:
            limit: Maximum number of files to read
        
        Returns:
            List of (file_path, entries) tuples
        """
        wal_files = self.list_wal_files()
        
        if limit:
            wal_files = wal_files[:limit]
        
        results = []
        for file_path in wal_files:
            entries = await self.read_file(file_path)
            if entries:
                results.append((file_path, entries))
        
        return results
    
    async def delete_file(self, file_path: Path):
        """
        Delete a processed WAL file
        
        Args:
            file_path: Path to WAL file
        """
        try:
            file_path.unlink()
            self.logger.info("Deleted WAL file", file=file_path.name)
        except Exception as e:
            self.logger.error("Error deleting WAL file", file=str(file_path), error=str(e))
    
    async def cleanup_old_files(self, max_age_hours: int = 24):
        """
        Clean up old processed WAL files
        
        Args:
            max_age_hours: Maximum age in hours before deletion
        """
        cutoff_time = datetime.utcnow() - timedelta(hours=max_age_hours)
        deleted_count = 0
        
        for file_path in self.list_wal_files():
            file_time = datetime.fromtimestamp(file_path.stat().st_mtime)
            if file_time < cutoff_time:
                await self.delete_file(file_path)
                deleted_count += 1
        
        if deleted_count > 0:
            self.logger.info("Cleaned up old WAL files", count=deleted_count)
