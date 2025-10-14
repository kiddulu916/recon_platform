"""
Active subdomain enumeration
DNS brute-forcing, permutations, JS scraping, and active probing
"""

from typing import List, Dict
import structlog
from sqlalchemy.ext.asyncio import AsyncSession
import json

from .dns_bruteforce import DNSBruteForcer
from .permutations import SubdomainPermuter
from .js_scraping import JSSourceScraper
from .vhost_discovery import VHOSTDiscovery
from .google_analytics import AnalyticsTracker
from .tls_csp_cname_probing import ActiveProbing
from .regex_permutations import RegexPermuter
from app.models.domain import Subdomain

logger = structlog.get_logger()


class ActiveEnumerator:
    """
    Orchestrates active subdomain enumeration
    More aggressive techniques that directly interact with targets
    """
    
    def __init__(self, config, rate_limiter, dedup_manager):
        self.config = config
        self.rate_limiter = rate_limiter
        self.dedup_manager = dedup_manager
        self.logger = logger.bind(component="active_enum")
        
        # Initialize modules
        self.dns_bruteforcer = DNSBruteForcer(config, rate_limiter)
        self.permuter = SubdomainPermuter(config, rate_limiter)
        self.js_scraper = JSSourceScraper(config, rate_limiter)
        self.vhost_discovery = VHOSTDiscovery(config, rate_limiter)
        self.analytics_tracker = AnalyticsTracker(config, rate_limiter)
        self.active_probing = ActiveProbing(config, rate_limiter)
        self.regex_permuter = RegexPermuter(config, rate_limiter)
    
    async def enumerate(
        self,
        session: AsyncSession,
        domain: str,
        domain_id: int,
        known_subdomains: List[str] = None,
        recursion_level: int = 0
    ) -> List[str]:
        """
        Run active enumeration workflow
        
        Args:
            session: Database session
            domain: Target domain
            domain_id: Domain ID in database
            known_subdomains: Previously discovered subdomains for permutation
            recursion_level: Current recursion depth
        
        Returns:
            List of newly discovered subdomains
        """
        self.logger.info("Starting active enumeration", domain=domain)
        
        all_subdomains = set()
        
        # Phase 1: DNS Brute-forcing
        self.logger.info("Phase 1: DNS Brute-forcing")
        bruteforce_results = await self.dns_bruteforcer.bruteforce(domain)
        all_subdomains.update(bruteforce_results)
        self.logger.info("DNS brute-force complete", found=len(bruteforce_results))
        
        # Phase 2: Permutations (if we have known subdomains)
        if known_subdomains:
            self.logger.info("Phase 2: Subdomain Permutations")
            permutation_results = await self.permuter.generate_and_resolve(
                domain,
                known_subdomains
            )
            all_subdomains.update(permutation_results)
            self.logger.info("Permutations complete", found=len(permutation_results))
        
        # Phase 3: JS/Source Code Scraping (if we have known subdomains)
        if known_subdomains:
            self.logger.info("Phase 3: JS/Source Code Scraping")
            js_results = await self.js_scraper.scrape(
                session,
                known_subdomains[:100],  # Limit to first 100
                domain_id
            )
            all_subdomains.update(js_results)
            self.logger.info("JS scraping complete", found=len(js_results))
        
        # Phase 4: Google Analytics Tracking
        if known_subdomains:
            self.logger.info("Phase 4: Google Analytics Tracking")
            ga_results = await self.analytics_tracker.track(known_subdomains[:50])
            all_subdomains.update(ga_results)
            self.logger.info("Analytics tracking complete", found=len(ga_results))
        
        # Phase 5: TLS/CSP/CNAME Probing
        self.logger.info("Phase 5: TLS/CSP/CNAME Probing")
        probing_results = await self.active_probing.probe(domain, known_subdomains)
        all_subdomains.update(probing_results)
        self.logger.info("Active probing complete", found=len(probing_results))
        
        # Phase 6: Regex Permutations (if we have discovered subdomains)
        if known_subdomains or all_subdomains:
            self.logger.info("Phase 6: Regex Permutations")
            combined_subdomains = list(set(known_subdomains or []) | all_subdomains)
            regex_perms = self.regex_permuter.generate_permutations(
                combined_subdomains[:200],  # Limit input
                domain
            )
            # Only take a subset and resolve them
            if regex_perms:
                resolved_perms = await self.permuter.generate_and_resolve(
                    domain,
                    regex_perms[:500]  # Limit to 500 permutations
                )
                all_subdomains.update(resolved_perms)
                self.logger.info("Regex permutations complete", found=len(resolved_perms))
        
        # Deduplicate
        new_subdomains = self.dedup_manager.add_subdomains_batch(
            list(all_subdomains),
            "active_enum"
        )
        
        # Save to database
        saved_count = 0
        for subdomain in new_subdomains:
            try:
                subdomain_record = Subdomain(
                    subdomain=subdomain,
                    domain_id=domain_id,
                    discovery_method="active",
                    discovery_sources=json.dumps([
                        "dns_bruteforce", "permutations", "js_scraping",
                        "google_analytics", "tls_csp_cname", "regex_permutations"
                    ]),
                    recursion_level=recursion_level,
                    resolves=True  # Active enumeration confirms resolution
                )
                session.add(subdomain_record)
                saved_count += 1
            except Exception as e:
                self.logger.warning("Failed to save subdomain", subdomain=subdomain, error=str(e))
        
        await session.commit()
        
        self.logger.info(
            "Active enumeration complete",
            new=len(new_subdomains),
            saved=saved_count
        )
        
        return new_subdomains

