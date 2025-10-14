"""
Horizontal enumeration techniques
Discovers company acquisitions, ASN ranges, reverse DNS, and favicon hashing
"""

from typing import List, Dict, Set
import structlog
from sqlalchemy.ext.asyncio import AsyncSession

from .acquisitions import AcquisitionDiscovery
from .asn_lookup import ASNLookup
from .reverse_dns import ReverseDNS
from .favicon_hash import FaviconHasher

logger = structlog.get_logger()


class HorizontalEnumerator:
    """
    Orchestrates horizontal enumeration techniques
    Discovers infrastructure through company relationships and IP ranges
    """
    
    def __init__(self, config, rate_limiter, dedup_manager):
        self.config = config
        self.rate_limiter = rate_limiter
        self.dedup_manager = dedup_manager
        self.logger = logger.bind(component="horizontal_enum")
        
        # Initialize sub-modules
        self.acquisition_discovery = AcquisitionDiscovery(config, rate_limiter)
        self.asn_lookup = ASNLookup(config, rate_limiter)
        self.reverse_dns = ReverseDNS(config, rate_limiter)
        self.favicon_hasher = FaviconHasher(config, rate_limiter)
    
    async def enumerate(
        self,
        session: AsyncSession,
        domain: str,
        domain_id: int
    ) -> Dict[str, any]:
        """
        Run complete horizontal enumeration workflow
        
        Args:
            session: Database session
            domain: Target domain
            domain_id: Domain ID in database
        
        Returns:
            Dictionary with results from each phase
        """
        self.logger.info("Starting horizontal enumeration", domain=domain)
        results = {
            "acquisitions": [],
            "asns": [],
            "reverse_dns": [],
            "favicon_hashes": []
        }
        
        try:
            # Phase 1: Acquisition Discovery
            self.logger.info("Phase 1: Acquisition Discovery")
            acquisitions = await self.acquisition_discovery.discover(
                session,
                domain,
                domain_id
            )
            results["acquisitions"] = acquisitions
            self.logger.info(
                "Acquisition discovery complete",
                companies_found=len(acquisitions)
            )
            
            # Phase 2: ASN Lookup
            self.logger.info("Phase 2: ASN Lookup")
            asns = await self.asn_lookup.lookup(
                session,
                domain,
                domain_id
            )
            results["asns"] = asns
            self.logger.info(
                "ASN lookup complete",
                asns_found=len(asns)
            )
            
            # Phase 3: Reverse DNS from ASN IP ranges
            self.logger.info("Phase 3: Reverse DNS")
            if asns:
                # Extract IP ranges from discovered ASNs
                ip_ranges = []
                for asn_data in asns:
                    ip_ranges.extend(asn_data.get("ip_ranges", []))
                
                reverse_dns_results = await self.reverse_dns.enumerate(
                    session,
                    ip_ranges,
                    domain_id
                )
                results["reverse_dns"] = reverse_dns_results
                self.logger.info(
                    "Reverse DNS complete",
                    subdomains_found=len(reverse_dns_results)
                )
            
            # Phase 4: Favicon Hashing (on discovered subdomains)
            self.logger.info("Phase 4: Favicon Hashing")
            # This will be run after we have subdomains from vertical enumeration
            # For now, we'll skip this in horizontal phase
            
            self.logger.info(
                "Horizontal enumeration complete",
                total_acquisitions=len(results["acquisitions"]),
                total_asns=len(results["asns"]),
                total_reverse_dns=len(results["reverse_dns"])
            )
            
            return results
            
        except Exception as e:
            self.logger.error("Horizontal enumeration failed", error=str(e))
            raise

