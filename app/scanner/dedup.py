"""
Deduplication manager for cross-phase result tracking
Uses bloom filter for fast lookups and database queries for verification
"""

from typing import Set, List, Dict, Optional
from pybloom_live import BloomFilter
import structlog
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

logger = structlog.get_logger()


class DeduplicationManager:
    """
    Manages deduplication across scanning phases
    Combines in-memory bloom filter with database verification
    """
    
    def __init__(self, capacity: int = 100000, error_rate: float = 0.001):
        """
        Args:
            capacity: Expected number of unique items
            error_rate: False positive rate for bloom filter
        """
        self.subdomains_bloom = BloomFilter(capacity=capacity, error_rate=error_rate)
        self.ips_bloom = BloomFilter(capacity=capacity, error_rate=error_rate)
        self.urls_bloom = BloomFilter(capacity=capacity, error_rate=error_rate)
        
        # Track discovery sources for each item
        self.subdomain_sources: Dict[str, Set[str]] = {}
        self.ip_sources: Dict[str, Set[str]] = {}
        
        # Track initialization status
        self.initialized_for_domain: Optional[int] = None
        self.initialization_count: int = 0
        
        self.logger = logger.bind(component="deduplication")
    
    def add_subdomain(self, subdomain: str, source: str) -> bool:
        """
        Add subdomain to deduplication set
        
        Args:
            subdomain: Subdomain to add
            source: Discovery source (tool/method name)
        
        Returns:
            True if new, False if duplicate
        """
        subdomain = subdomain.lower().strip()
        
        # Check bloom filter first
        if subdomain in self.subdomains_bloom:
            # Possible duplicate, add source anyway
            if subdomain not in self.subdomain_sources:
                self.subdomain_sources[subdomain] = set()
            self.subdomain_sources[subdomain].add(source)
            return False
        
        # New subdomain
        self.subdomains_bloom.add(subdomain)
        self.subdomain_sources[subdomain] = {source}
        return True
    
    def add_ip(self, ip: str, source: str) -> bool:
        """
        Add IP address to deduplication set
        
        Args:
            ip: IP address to add
            source: Discovery source
        
        Returns:
            True if new, False if duplicate
        """
        ip = ip.strip()
        
        if ip in self.ips_bloom:
            if ip not in self.ip_sources:
                self.ip_sources[ip] = set()
            self.ip_sources[ip].add(source)
            return False
        
        self.ips_bloom.add(ip)
        self.ip_sources[ip] = {source}
        return True
    
    def add_url(self, url: str) -> bool:
        """
        Add URL to deduplication set
        
        Args:
            url: URL to add
        
        Returns:
            True if new, False if duplicate
        """
        url = url.strip()
        
        if url in self.urls_bloom:
            return False
        
        self.urls_bloom.add(url)
        return True
    
    def add_subdomains_batch(self, subdomains: List[str], source: str) -> List[str]:
        """
        Add multiple subdomains and return only new ones
        
        Args:
            subdomains: List of subdomains
            source: Discovery source
        
        Returns:
            List of new subdomains
        """
        new_subdomains = []
        
        for subdomain in subdomains:
            if self.add_subdomain(subdomain, source):
                new_subdomains.append(subdomain)
        
        self.logger.info(
            "Batch deduplication",
            source=source,
            total=len(subdomains),
            new=len(new_subdomains),
            duplicates=len(subdomains) - len(new_subdomains)
        )
        
        return new_subdomains
    
    def add_ips_batch(self, ips: List[str], source: str) -> List[str]:
        """
        Add multiple IPs and return only new ones
        
        Args:
            ips: List of IP addresses
            source: Discovery source
        
        Returns:
            List of new IPs
        """
        new_ips = []
        
        for ip in ips:
            if self.add_ip(ip, source):
                new_ips.append(ip)
        
        self.logger.info(
            "Batch IP deduplication",
            source=source,
            total=len(ips),
            new=len(new_ips)
        )
        
        return new_ips
    
    def get_sources(self, subdomain: str) -> Set[str]:
        """Get all sources that discovered this subdomain"""
        return self.subdomain_sources.get(subdomain.lower().strip(), set())
    
    def get_ip_sources(self, ip: str) -> Set[str]:
        """Get all sources that discovered this IP"""
        return self.ip_sources.get(ip.strip(), set())
    
    async def check_subdomain_in_db(
        self,
        session: AsyncSession,
        subdomain: str,
        domain_id: int
    ) -> bool:
        """
        Check if subdomain exists in database
        
        Args:
            session: Database session
            subdomain: Subdomain to check
            domain_id: Parent domain ID
        
        Returns:
            True if exists, False otherwise
        """
        from app.models.domain import Subdomain
        
        result = await session.execute(
            select(Subdomain).where(
                Subdomain.subdomain == subdomain.lower().strip(),
                Subdomain.domain_id == domain_id
            )
        )
        return result.scalar_one_or_none() is not None
    
    async def check_ip_in_db(
        self,
        session: AsyncSession,
        ip: str
    ) -> bool:
        """
        Check if IP exists in database
        
        Args:
            session: Database session
            ip: IP address to check
        
        Returns:
            True if exists, False otherwise
        """
        from app.models.network import IPAddress
        
        result = await session.execute(
            select(IPAddress).where(IPAddress.ip == ip.strip())
        )
        return result.scalar_one_or_none() is not None
    
    async def initialize_from_database(
        self,
        session: AsyncSession,
        domain_id: int
    ) -> int:
        """
        Initialize bloom filters with existing database records for a domain
        
        Args:
            session: Database session
            domain_id: Domain ID to load records for
        
        Returns:
            Count of records loaded
        """
        # Skip if already initialized for this domain
        if self.initialized_for_domain == domain_id:
            self.logger.debug(
                "Dedup manager already initialized for domain",
                domain_id=domain_id
            )
            return self.initialization_count
        
        self.logger.info(
            "Initializing dedup manager from database",
            domain_id=domain_id
        )
        
        from app.models.domain import Subdomain
        from app.models.network import IPAddress, SubdomainIP
        
        loaded_count = 0
        
        try:
            # Load all subdomains for this domain
            result = await session.execute(
                select(Subdomain.subdomain, Subdomain.discovery_sources).where(
                    Subdomain.domain_id == domain_id
                )
            )
            
            subdomain_rows = result.fetchall()
            for subdomain, sources_json in subdomain_rows:
                subdomain = subdomain.lower().strip()
                self.subdomains_bloom.add(subdomain)
                
                # Parse and add sources
                try:
                    import json
                    sources = json.loads(sources_json) if sources_json else []
                    if subdomain not in self.subdomain_sources:
                        self.subdomain_sources[subdomain] = set()
                    self.subdomain_sources[subdomain].update(sources)
                except (json.JSONDecodeError, TypeError):
                    pass
                
                loaded_count += 1
            
            # Load all IPs associated with this domain's subdomains
            result = await session.execute(
                select(IPAddress.ip).join(
                    SubdomainIP
                ).join(
                    Subdomain
                ).where(
                    Subdomain.domain_id == domain_id
                )
            )
            
            ip_rows = result.fetchall()
            for (ip,) in ip_rows:
                self.ips_bloom.add(ip.strip())
                loaded_count += 1
            
            self.initialized_for_domain = domain_id
            self.initialization_count = loaded_count
            
            self.logger.info(
                "Dedup manager initialized from database",
                domain_id=domain_id,
                subdomains=len(subdomain_rows),
                ips=len(ip_rows),
                total_loaded=loaded_count
            )
            
            return loaded_count
        
        except Exception as e:
            self.logger.warning(
                "Failed to initialize dedup manager from database",
                domain_id=domain_id,
                error=str(e)
            )
            # Don't fail the scan if initialization fails
            return 0
    
    def get_stats(self) -> Dict:
        """Get deduplication statistics"""
        return {
            "subdomains": {
                "bloom_size": len(self.subdomains_bloom),
                "sources_tracked": len(self.subdomain_sources)
            },
            "ips": {
                "bloom_size": len(self.ips_bloom),
                "sources_tracked": len(self.ip_sources)
            },
            "urls": {
                "bloom_size": len(self.urls_bloom)
            },
            "initialized_for_domain": self.initialized_for_domain,
            "initialization_count": self.initialization_count
        }
    
    def clear(self):
        """Clear all deduplication data"""
        self.subdomains_bloom = BloomFilter(
            capacity=100000,
            error_rate=0.001
        )
        self.ips_bloom = BloomFilter(
            capacity=100000,
            error_rate=0.001
        )
        self.urls_bloom = BloomFilter(
            capacity=100000,
            error_rate=0.001
        )
        self.subdomain_sources.clear()
        self.ip_sources.clear()
        self.initialized_for_domain = None
        self.initialization_count = 0
        self.logger.info("Deduplication manager cleared")

