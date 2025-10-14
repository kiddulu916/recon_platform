"""
Storage Manager for HTTP Traffic Data

Handles efficient batch insertion of traffic data into the database
with proper transaction management and error handling.
"""

import gzip
import json
from typing import List, Dict, Any, Optional
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select
import structlog

from app.models.http_traffic import HTTPTraffic, HTTPTrafficWAL
from app.models.domain import Subdomain

logger = structlog.get_logger()


class StorageManager:
    """
    Manages efficient storage of HTTP traffic data
    
    Features:
    - Batch insertions for performance
    - Response body compression
    - Transaction management
    - Error handling and retry
    - Subdomain lookup and linking
    """
    
    def __init__(self, config):
        """
        Initialize storage manager
        
        Args:
            config: Application configuration
        """
        self.config = config
        self.logger = logger.bind(component="storage_manager")
        
        # Compression settings
        self.compress_bodies = config.proxy.compress_response_bodies
        self.compression_min_size = config.proxy.compression_min_size_bytes
        self.max_body_size = config.proxy.max_body_size_mb * 1024 * 1024
        
        # Statistics
        self.stats = {
            "traffic_inserted": 0,
            "batches_processed": 0,
            "errors": 0,
            "bytes_compressed": 0,
            "compression_ratio": 0.0
        }
    
    async def store_traffic_batch(
        self,
        session: AsyncSession,
        traffic_entries: List[Dict[str, Any]]
    ) -> List[int]:
        """
        Store a batch of traffic entries
        
        Args:
            session: Database session
            traffic_entries: List of traffic data dictionaries
        
        Returns:
            List of created HTTPTraffic IDs
        """
        if not traffic_entries:
            return []
        
        try:
            created_ids = []
            
            for entry in traffic_entries:
                try:
                    # Create HTTPTraffic record
                    traffic_id = await self._create_traffic_record(session, entry)
                    if traffic_id:
                        created_ids.append(traffic_id)
                
                except Exception as e:
                    self.logger.error(
                        "Error storing traffic entry",
                        error=str(e),
                        url=entry.get("request", {}).get("url")
                    )
                    self.stats["errors"] += 1
            
            # Commit batch
            await session.commit()
            
            self.stats["traffic_inserted"] += len(created_ids)
            self.stats["batches_processed"] += 1
            
            self.logger.info(
                "Batch stored",
                entries=len(traffic_entries),
                created=len(created_ids)
            )
            
            return created_ids
        
        except Exception as e:
            await session.rollback()
            self.logger.error("Error storing batch", error=str(e))
            self.stats["errors"] += 1
            raise
    
    async def _create_traffic_record(
        self,
        session: AsyncSession,
        entry: Dict[str, Any]
    ) -> Optional[int]:
        """
        Create a single HTTPTraffic record
        
        Args:
            session: Database session
            entry: Traffic data dictionary
        
        Returns:
            Created record ID or None
        """
        request = entry.get("request", {})
        response = entry.get("response")
        context = entry.get("context", {})
        certificate = entry.get("certificate")
        
        # Extract subdomain and link to database
        subdomain_id = await self._get_subdomain_id(
            session,
            request.get("host"),
            context.get("domain_id"),
            context.get("subdomain_id")
        )
        
        if not subdomain_id:
            self.logger.warning(
                "No subdomain found for traffic",
                host=request.get("host")
            )
            # Still store but without subdomain link
        
        # Compress request body if needed
        request_body = self._compress_body(request.get("content"))
        
        # Compress response body if needed
        response_body = None
        response_size = 0
        if response:
            response_body = self._compress_body(response.get("content"))
            response_size = response.get("size", 0)
        
        # Build traffic record
        traffic = HTTPTraffic(
            subdomain_id=subdomain_id,
            
            # Request
            method=request.get("method"),
            url=request.get("url"),
            path=request.get("path"),
            query_params=json.dumps(request.get("query_params", {})),
            request_headers=json.dumps(request.get("headers", {})),
            request_body=request_body,
            request_content_type=request.get("content_type"),
            
            # Response
            status_code=response.get("status_code") if response else None,
            response_headers=json.dumps(response.get("headers", {})) if response else None,
            response_body=response_body,
            response_content_type=response.get("content_type") if response else None,
            response_size=response_size,
            
            # Timing
            response_time_ms=entry.get("response_time_ms"),
            
            # Context
            scanner_module=context.get("scanner_module"),
            scan_purpose=context.get("scan_purpose"),
            correlation_id=context.get("correlation_id"),
            parent_traffic_id=None,  # Will be linked later if needed
            
            # Certificate info
            certificate_fingerprint=certificate[0].get("fingerprint") if certificate else None,
            certificate_issuer=certificate[0].get("issuer") if certificate else None,
            certificate_subject=certificate[0].get("subject") if certificate else None,
            certificate_validation_errors=None,  # To be filled by validator
            
            # Error
            has_error=bool(entry.get("error")),
            error_type="connection_error" if entry.get("error") else None,
            
            # Analysis flags
            is_analyzed=False
        )
        
        session.add(traffic)
        await session.flush()
        
        return traffic.id
    
    async def _get_subdomain_id(
        self,
        session: AsyncSession,
        host: Optional[str],
        domain_id: Optional[int],
        subdomain_id: Optional[int]
    ) -> Optional[int]:
        """
        Get or create subdomain ID
        
        Args:
            session: Database session
            host: Hostname from request
            domain_id: Domain ID from context
            subdomain_id: Subdomain ID from context (if already known)
        
        Returns:
            Subdomain ID or None
        """
        # Use provided subdomain ID if available
        if subdomain_id:
            return subdomain_id
        
        # Look up by host and domain
        if host and domain_id:
            result = await session.execute(
                select(Subdomain).where(
                    Subdomain.subdomain == host,
                    Subdomain.domain_id == domain_id
                )
            )
            subdomain = result.scalar_one_or_none()
            if subdomain:
                return subdomain.id
        
        # Not found
        return None
    
    def _compress_body(self, content: Optional[bytes]) -> Optional[bytes]:
        """
        Compress body content if appropriate
        
        Args:
            content: Raw body content
        
        Returns:
            Compressed content or None
        """
        if not content or not self.compress_bodies:
            return content
        
        # Don't compress if too small
        if len(content) < self.compression_min_size:
            return content
        
        # Don't compress if too large
        if len(content) > self.max_body_size:
            self.logger.warning(
                "Body too large, truncating",
                size=len(content),
                max_size=self.max_body_size
            )
            content = content[:self.max_body_size]
        
        try:
            compressed = gzip.compress(content, compresslevel=6)
            
            # Track compression ratio
            original_size = len(content)
            compressed_size = len(compressed)
            ratio = compressed_size / original_size if original_size > 0 else 1.0
            
            self.stats["bytes_compressed"] += original_size - compressed_size
            self.stats["compression_ratio"] = ratio
            
            return compressed
        
        except Exception as e:
            self.logger.error("Compression failed", error=str(e))
            return content
    
    async def store_wal_record(
        self,
        session: AsyncSession,
        wal_id: str,
        raw_data: bytes
    ):
        """
        Store a WAL record in the database
        
        Used for WAL persistence to database before processing.
        
        Args:
            session: Database session
            wal_id: WAL entry UUID
            raw_data: Serialized traffic data
        """
        try:
            wal_record = HTTPTrafficWAL(
                wal_id=wal_id,
                raw_data=raw_data,
                processed=False
            )
            
            session.add(wal_record)
            await session.commit()
        
        except Exception as e:
            await session.rollback()
            self.logger.error("Error storing WAL record", error=str(e), wal_id=wal_id)
            raise
    
    async def mark_wal_processed(
        self,
        session: AsyncSession,
        wal_id: str,
        http_traffic_id: Optional[int] = None,
        error: Optional[str] = None
    ):
        """
        Mark a WAL record as processed
        
        Args:
            session: Database session
            wal_id: WAL entry UUID
            http_traffic_id: Created HTTPTraffic ID (if successful)
            error: Error message (if failed)
        """
        try:
            result = await session.execute(
                select(HTTPTrafficWAL).where(HTTPTrafficWAL.wal_id == wal_id)
            )
            wal_record = result.scalar_one_or_none()
            
            if wal_record:
                wal_record.processed = True
                wal_record.http_traffic_id = http_traffic_id
                wal_record.error_message = error
                wal_record.processing_attempts += 1
                
                await session.commit()
        
        except Exception as e:
            await session.rollback()
            self.logger.error("Error marking WAL processed", error=str(e), wal_id=wal_id)
    
    def get_stats(self) -> Dict[str, Any]:
        """Get storage manager statistics"""
        return self.stats.copy()
