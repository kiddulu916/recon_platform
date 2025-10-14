"""
Main scanner engine
Orchestrates all scanning operations and integrates all modules
"""

from typing import List, Dict, Optional
import structlog
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select

from app.scanner.rate_limiter import ScanProfileRateLimiter
from app.scanner.dedup import DeduplicationManager
from app.scanner.horizontal import HorizontalEnumerator
from app.scanner.vertical.passive import PassiveEnumerator
from app.scanner.vertical.active import ActiveEnumerator
from app.scanner.probing.port_scanner import PortScanner
from app.scanner.probing.http_prober import HTTPProber
from app.scanner.probing.service_detector import ServiceDetector
from app.scanner.probing.web_discovery_orchestrator import WebDiscoveryOrchestrator
from app.scanner.recursive.orchestrator import RecursiveEnumerator
from app.intelligence.orchestrator import VulnerabilityIntelligenceOrchestrator
from app.models.domain import Subdomain

logger = structlog.get_logger()


class ScannerEngine:
    """
    Main scanner engine that orchestrates all scanning operations
    Integrates horizontal, passive, active, probing, and recursive modules
    """
    
    def __init__(self, config, db_manager):
        self.config = config
        self.db_manager = db_manager
        self.logger = logger.bind(component="scanner_engine")
        
        # Initialize rate limiter based on scan profile
        scan_profile = config.scanner.scan_profile
        self.rate_limiter = ScanProfileRateLimiter(scan_profile)
        
        # Initialize deduplication manager
        self.dedup_manager = DeduplicationManager()
        
        # Initialize enumerators
        self.horizontal_enum = HorizontalEnumerator(
            config,
            self.rate_limiter,
            self.dedup_manager
        )
        self.passive_enum = PassiveEnumerator(
            config,
            self.rate_limiter,
            self.dedup_manager
        )
        self.active_enum = ActiveEnumerator(
            config,
            self.rate_limiter,
            self.dedup_manager
        )
        
        # Initialize probing modules
        self.port_scanner = PortScanner(config, self.rate_limiter)
        self.http_prober = HTTPProber(config, self.rate_limiter)
        self.service_detector = ServiceDetector(config, self.rate_limiter)

        # Initialize web discovery orchestrator
        self.web_discovery = WebDiscoveryOrchestrator(config, self.rate_limiter)

        # Initialize vulnerability intelligence orchestrator
        self.vuln_intelligence = VulnerabilityIntelligenceOrchestrator(config)

        # Initialize recursive enumerator
        self.recursive_enum = RecursiveEnumerator(self)
        
        self.logger.info("Scanner engine initialized", scan_profile=scan_profile)
    
    async def run_horizontal_enumeration(
        self,
        session: AsyncSession,
        domain: str,
        domain_id: int
    ) -> Dict:
        """
        Run horizontal enumeration phase
        
        Args:
            session: Database session
            domain: Target domain
            domain_id: Domain ID
        
        Returns:
            Horizontal enumeration results
        """
        self.logger.info("Starting horizontal enumeration phase", domain=domain)
        
        try:
            results = await self.horizontal_enum.enumerate(
                session,
                domain,
                domain_id
            )
            
            self.logger.info(
                "Horizontal enumeration phase complete",
                acquisitions=len(results.get("acquisitions", [])),
                asns=len(results.get("asns", [])),
                reverse_dns=len(results.get("reverse_dns", []))
            )
            
            return results
        
        except Exception as e:
            self.logger.error("Horizontal enumeration failed", error=str(e))
            return {}
    
    async def run_passive_enumeration(
        self,
        session: AsyncSession,
        domain: str,
        domain_id: int,
        recursion_level: int = 0
    ) -> List[str]:
        """
        Run passive enumeration phase
        
        Args:
            session: Database session
            domain: Target domain
            domain_id: Domain ID
            recursion_level: Current recursion depth
        
        Returns:
            List of discovered subdomains
        """
        self.logger.info("Starting passive enumeration phase", domain=domain)
        
        try:
            results = await self.passive_enum.enumerate(
                session,
                domain,
                domain_id,
                recursion_level
            )
            
            self.logger.info(
                "Passive enumeration phase complete",
                subdomains=len(results)
            )
            
            return results
        
        except Exception as e:
            self.logger.error("Passive enumeration failed", error=str(e))
            return []
    
    async def run_active_enumeration(
        self,
        session: AsyncSession,
        domain: str,
        domain_id: int,
        known_subdomains: List[str] = None,
        recursion_level: int = 0
    ) -> List[str]:
        """
        Run active enumeration phase
        
        Args:
            session: Database session
            domain: Target domain
            domain_id: Domain ID
            known_subdomains: Previously discovered subdomains
            recursion_level: Current recursion depth
        
        Returns:
            List of discovered subdomains
        """
        self.logger.info("Starting active enumeration phase", domain=domain)
        
        try:
            results = await self.active_enum.enumerate(
                session,
                domain,
                domain_id,
                known_subdomains,
                recursion_level
            )
            
            self.logger.info(
                "Active enumeration phase complete",
                subdomains=len(results)
            )
            
            return results
        
        except Exception as e:
            self.logger.error("Active enumeration failed", error=str(e))
            return []
    
    async def run_web_probing(
        self,
        session: AsyncSession,
        domain_id: int
    ):
        """
        Run web probing phase
        
        Args:
            session: Database session
            domain_id: Domain ID
        """
        self.logger.info("Starting web probing phase")
        
        try:
            # Get all subdomains for this domain
            result = await session.execute(
                select(Subdomain).where(Subdomain.domain_id == domain_id)
            )
            subdomains = result.scalars().all()
            
            if not subdomains:
                self.logger.info("No subdomains to probe")
                return
            
            subdomain_list = [sub.subdomain for sub in subdomains]
            
            # Phase 1: Port scanning
            self.logger.info("Running port scan", targets=len(subdomain_list))
            port_results = await self.port_scanner.scan(
                session,
                subdomain_list,
                profile="default"
            )
            
            # Phase 2: HTTP probing
            self.logger.info("Running HTTP probing", targets=len(subdomain_list))
            http_results = await self.http_prober.probe(
                session,
                subdomain_list,
                domain_id
            )
            
            # Phase 3: Intelligent web discovery (optional)
            if hasattr(self.config.scanner, 'enable_web_discovery') and self.config.scanner.enable_web_discovery:
                self.logger.info("Running intelligent web discovery")

                # Run on top subdomains with HTTP/HTTPS
                web_targets = [
                    sub for sub in subdomains
                    if sub.has_http or sub.has_https
                ][:10]  # Limit to top 10

                for target in web_targets:
                    try:
                        base_url = f"https://{target.subdomain}" if target.has_https else f"http://{target.subdomain}"

                        web_results = await self.web_discovery.discover(
                            session,
                            target.id,
                            base_url,
                            enable_crawling=True,
                            enable_directory_enum=True,
                            enable_api_discovery=True,
                            max_crawl_depth=3,
                            max_crawl_pages=500
                        )

                        self.logger.info(
                            "Web discovery complete for subdomain",
                            subdomain=target.subdomain,
                            apis_found=len(web_results.get("api_discovery", {}).get("apis", [])),
                            paths_found=len(web_results.get("directory_enum", {}).get("discovered_paths", []))
                        )

                    except Exception as e:
                        self.logger.warning("Web discovery failed for subdomain", subdomain=target.subdomain, error=str(e))

            self.logger.info(
                "Web probing phase complete",
                port_results=len(port_results),
                http_results=len(http_results)
            )

        except Exception as e:
            self.logger.error("Web probing failed", error=str(e))
    
    async def run_recursive_enumeration(
        self,
        session: AsyncSession,
        domain_id: int,
        max_depth: int = 2
    ):
        """
        Run recursive enumeration on newly discovered subdomains
        
        Args:
            session: Database session
            domain_id: Domain ID
            max_depth: Maximum recursion depth
        """
        self.logger.info(
            "Starting recursive enumeration",
            max_depth=max_depth
        )
        
        try:
            await self.recursive_enum.enumerate(session, domain_id, max_depth)
            self.logger.info("Recursive enumeration complete")
        
        except Exception as e:
            self.logger.error("Recursive enumeration failed", error=str(e))
    
    def get_stats(self) -> Dict:
        """Get scanner engine statistics"""
        return {
            "rate_limiter": self.rate_limiter.get_stats(),
            "deduplication": self.dedup_manager.get_stats(),
            "recursive": self.recursive_enum.get_stats()
        }

