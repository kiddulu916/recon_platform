"""
Traffic Processor for Background Processing Pipeline

Coordinates reading traffic data from WAL and moving it to structured storage.
Runs as a background task with configurable intervals.
"""

import asyncio
from typing import Optional
from datetime import datetime
import structlog

from app.core.database import async_session_maker
from .wal import WALReader
from .storage_manager import StorageManager

logger = structlog.get_logger()


class TrafficProcessor:
    """
    Background processor for HTTP traffic data
    
    Reads traffic from WAL files and moves to structured database storage.
    Runs continuously in the background with configurable intervals.
    """
    
    def __init__(self, config):
        """
        Initialize traffic processor
        
        Args:
            config: Application configuration
        """
        self.config = config
        self.logger = logger.bind(component="traffic_processor")
        
        # Components
        self.wal_reader = WALReader(config)
        self.storage_manager = StorageManager(config)
        
        # Processing settings
        self.interval = config.proxy.processing_interval_seconds
        self.batch_size = config.proxy.processing_batch_size
        self.enabled = config.proxy.processing_enabled
        
        # State
        self._running = False
        self._task: Optional[asyncio.Task] = None
        
        # Statistics
        self.stats = {
            "cycles_completed": 0,
            "files_processed": 0,
            "entries_processed": 0,
            "errors": 0,
            "last_run": None
        }
    
    async def start(self):
        """
        Start the background processor
        
        Launches a background task that runs continuously.
        """
        if self._running:
            self.logger.warning("Processor already running")
            return
        
        if not self.enabled:
            self.logger.info("Processor disabled in configuration")
            return
        
        self._running = True
        self._task = asyncio.create_task(self._run_loop())
        
        self.logger.info(
            "Processor started",
            interval=self.interval,
            batch_size=self.batch_size
        )
    
    async def stop(self):
        """
        Stop the background processor
        
        Gracefully stops the processor and waits for completion.
        """
        if not self._running:
            return
        
        self.logger.info("Stopping processor...")
        
        self._running = False
        
        if self._task:
            self._task.cancel()
            try:
                await self._task
            except asyncio.CancelledError:
                pass
        
        self.logger.info("Processor stopped")
    
    async def _run_loop(self):
        """
        Main processing loop
        
        Runs continuously, processing WAL files at regular intervals.
        """
        self.logger.info("Processing loop started")
        
        while self._running:
            try:
                await self._process_cycle()
                self.stats["cycles_completed"] += 1
                self.stats["last_run"] = datetime.utcnow().isoformat()
                
                # Wait for next cycle
                await asyncio.sleep(self.interval)
            
            except asyncio.CancelledError:
                break
            
            except Exception as e:
                self.logger.error("Error in processing loop", error=str(e))
                self.stats["errors"] += 1
                await asyncio.sleep(self.interval)
        
        self.logger.info("Processing loop stopped")
    
    async def _process_cycle(self):
        """
        Process one cycle of WAL files
        
        Reads unprocessed WAL files and moves data to database.
        """
        # Read unprocessed WAL files
        wal_files = await self.wal_reader.read_unprocessed(limit=10)
        
        if not wal_files:
            self.logger.debug("No WAL files to process")
            return
        
        self.logger.info("Processing WAL files", count=len(wal_files))
        
        # Process each file
        for file_path, entries in wal_files:
            try:
                await self._process_file(file_path, entries)
                self.stats["files_processed"] += 1
            
            except Exception as e:
                self.logger.error(
                    "Error processing file",
                    file=str(file_path),
                    error=str(e)
                )
                self.stats["errors"] += 1
    
    async def _process_file(self, file_path, entries):
        """
        Process a single WAL file
        
        Args:
            file_path: Path to WAL file
            entries: List of traffic entries from file
        """
        if not entries:
            # Empty file, can delete
            await self.wal_reader.delete_file(file_path)
            return
        
        self.logger.debug(
            "Processing file",
            file=file_path.name,
            entries=len(entries)
        )
        
        # Process in batches
        for i in range(0, len(entries), self.batch_size):
            batch = entries[i:i + self.batch_size]
            await self._process_batch(batch)
        
        # Delete processed file
        await self.wal_reader.delete_file(file_path)
        
        self.logger.info(
            "File processed and deleted",
            file=file_path.name,
            entries=len(entries)
        )
    
    async def _process_batch(self, entries):
        """
        Process a batch of entries
        
        Args:
            entries: List of traffic entries
        """
        try:
            # Extract traffic data from entries
            traffic_data = []
            for entry in entries:
                data = entry.get("data")
                if data:
                    traffic_data.append(data)
            
            if not traffic_data:
                return
            
            # Store in database
            async with async_session_maker() as session:
                created_ids = await self.storage_manager.store_traffic_batch(
                    session,
                    traffic_data
                )
                
                self.stats["entries_processed"] += len(created_ids)
                
                self.logger.debug(
                    "Batch processed",
                    entries=len(traffic_data),
                    created=len(created_ids)
                )
        
        except Exception as e:
            self.logger.error("Error processing batch", error=str(e))
            self.stats["errors"] += 1
            raise
    
    async def process_now(self):
        """
        Trigger immediate processing cycle
        
        Useful for manual processing or testing.
        """
        self.logger.info("Manual processing triggered")
        await self._process_cycle()
    
    def get_stats(self) -> dict:
        """
        Get processor statistics
        
        Returns:
            Dictionary with statistics
        """
        return {
            **self.stats,
            "running": self._running,
            "interval_seconds": self.interval,
            "batch_size": self.batch_size,
            "storage_stats": self.storage_manager.get_stats()
        }
    
    async def cleanup_old_wal_files(self, max_age_hours: int = 24):
        """
        Clean up old WAL files
        
        Args:
            max_age_hours: Maximum age before deletion
        """
        await self.wal_reader.cleanup_old_files(max_age_hours)


async def create_processor(config) -> TrafficProcessor:
    """
    Factory function to create and start a traffic processor
    
    Args:
        config: Application configuration
    
    Returns:
        Started TrafficProcessor instance
    """
    processor = TrafficProcessor(config)
    await processor.start()
    return processor
