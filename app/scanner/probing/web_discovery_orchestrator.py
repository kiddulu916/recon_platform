"""
Web Discovery Orchestrator

Coordinates all web discovery modules:
- Intelligent crawling with application modeling
- Context-aware directory/file enumeration
- Advanced API discovery

Manages the overall web discovery workflow and integrates findings.
"""

import asyncio
from typing import Dict, Any, List, Optional
import structlog
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select
import aiohttp

from app.scanner.probing.intelligent_crawler import IntelligentCrawler
from app.scanner.probing.directory_enumeration import ContextAwareDirectoryEnumerator
from app.scanner.probing.api_discovery import APIDiscoveryEngine
from app.models.http_traffic import HTTPTraffic
from app.models.domain import Subdomain

logger = structlog.get_logger()


class WebDiscoveryOrchestrator:
    """
    Orchestrates comprehensive web discovery

    Workflow:
    1. Intelligent crawling to map application structure
    2. Directory/file enumeration with technology-aware wordlists
    3. API discovery using multiple techniques
    4. Cross-correlation of findings
    """

    def __init__(self, config, rate_limiter):
        self.config = config
        self.rate_limiter = rate_limiter
        self.logger = logger.bind(component="web_discovery")

        # Statistics
        self.stats = {
            "subdomains_processed": 0,
            "total_urls_discovered": 0,
            "total_paths_discovered": 0,
            "total_apis_discovered": 0,
            "crawl_time_seconds": 0,
            "enum_time_seconds": 0,
            "api_time_seconds": 0,
        }

    async def discover(
        self,
        db_session: AsyncSession,
        subdomain_id: int,
        base_url: str,
        enable_crawling: bool = True,
        enable_directory_enum: bool = True,
        enable_api_discovery: bool = True,
        max_crawl_depth: int = 5,
        max_crawl_pages: int = 1000
    ) -> Dict[str, Any]:
        """
        Run comprehensive web discovery

        Args:
            db_session: Database session
            subdomain_id: Subdomain ID to scan
            base_url: Base URL to start from
            enable_crawling: Enable intelligent crawling
            enable_directory_enum: Enable directory enumeration
            enable_api_discovery: Enable API discovery
            max_crawl_depth: Maximum crawl depth
            max_crawl_pages: Maximum pages to crawl

        Returns:
            Discovery results
        """
        self.logger.info("Starting web discovery", base_url=base_url)

        results = {
            "crawl": {},
            "directory_enum": {},
            "api_discovery": {},
            "stats": self.stats
        }

        # Create shared HTTP session
        timeout = aiohttp.ClientTimeout(total=30)
        async with aiohttp.ClientSession(timeout=timeout) as http_session:

            # Phase 1: Intelligent Crawling
            crawl_results = {}
            if enable_crawling:
                import time
                start_time = time.time()

                self.logger.info("Phase 1: Intelligent crawling")
                crawler = IntelligentCrawler(self.config, self.rate_limiter, http_session)

                crawl_results = await crawler.crawl(
                    db_session,
                    base_url,
                    subdomain_id,
                    max_depth=max_crawl_depth,
                    max_pages=max_crawl_pages
                )

                results["crawl"] = crawl_results
                self.stats["crawl_time_seconds"] = int(time.time() - start_time)
                self.stats["total_urls_discovered"] = crawl_results.get("stats", {}).get("urls_crawled", 0)

            # Phase 2: Directory/File Enumeration
            enum_results = {}
            if enable_directory_enum:
                import time
                start_time = time.time()

                self.logger.info("Phase 2: Directory enumeration")
                enumerator = ContextAwareDirectoryEnumerator(
                    self.config,
                    self.rate_limiter,
                    http_session
                )

                # Pass discovered paths from crawling as initial wordlist
                initial_paths = []
                if crawl_results:
                    app_state = crawl_results.get("routing_scheme", {})
                    discovered_resources = crawl_results.get("discovered_resources", [])

                    # Generate paths from discovered resources
                    for resource in discovered_resources:
                        initial_paths.append(f"/{resource}")
                        initial_paths.append(f"/api/{resource}")
                        initial_paths.append(f"/api/v1/{resource}")

                enum_results = await enumerator.enumerate(
                    db_session,
                    base_url,
                    subdomain_id,
                    initial_paths=initial_paths
                )

                results["directory_enum"] = enum_results
                self.stats["enum_time_seconds"] = int(time.time() - start_time)
                self.stats["total_paths_discovered"] = len(enum_results.get("discovered_paths", []))

            # Phase 3: API Discovery
            api_results = {}
            if enable_api_discovery:
                import time
                start_time = time.time()

                self.logger.info("Phase 3: API discovery")
                api_engine = APIDiscoveryEngine(self.config, self.rate_limiter, http_session)

                # Get observed traffic for dynamic analysis
                observed_traffic = await self._get_observed_traffic(db_session, subdomain_id)

                api_results = await api_engine.discover(
                    db_session,
                    base_url,
                    subdomain_id,
                    observed_traffic=observed_traffic
                )

                results["api_discovery"] = api_results
                self.stats["api_time_seconds"] = int(time.time() - start_time)
                self.stats["total_apis_discovered"] = len(api_results.get("apis", []))

        self.stats["subdomains_processed"] += 1

        # Generate summary
        summary = self._generate_summary(results)
        results["summary"] = summary

        self.logger.info("Web discovery complete", **self.stats)

        return results

    async def discover_multiple(
        self,
        db_session: AsyncSession,
        subdomains: List[str],
        domain_id: int,
        **kwargs
    ) -> Dict[str, Any]:
        """
        Run web discovery on multiple subdomains

        Args:
            db_session: Database session
            subdomains: List of subdomains to scan
            domain_id: Domain ID
            **kwargs: Additional arguments for discover()

        Returns:
            Aggregated results
        """
        self.logger.info("Starting multi-subdomain web discovery", count=len(subdomains))

        all_results = []

        for subdomain in subdomains[:20]:  # Limit to prevent overwhelming
            try:
                # Get subdomain record
                result = await db_session.execute(
                    select(Subdomain).where(
                        Subdomain.subdomain == subdomain,
                        Subdomain.domain_id == domain_id
                    )
                )
                subdomain_record = result.scalar_one_or_none()

                if not subdomain_record:
                    self.logger.warning("Subdomain not found", subdomain=subdomain)
                    continue

                # Determine base URL
                base_url = f"https://{subdomain}" if subdomain_record.has_https else f"http://{subdomain}"

                # Run discovery
                discovery_results = await self.discover(
                    db_session,
                    subdomain_record.id,
                    base_url,
                    **kwargs
                )

                all_results.append({
                    "subdomain": subdomain,
                    "results": discovery_results
                })

            except Exception as e:
                self.logger.error("Discovery failed for subdomain", subdomain=subdomain, error=str(e))

        return {
            "results": all_results,
            "stats": self.stats
        }

    async def _get_observed_traffic(
        self,
        db_session: AsyncSession,
        subdomain_id: int,
        limit: int = 500
    ) -> List[HTTPTraffic]:
        """Get recently observed HTTP traffic for this subdomain"""
        result = await db_session.execute(
            select(HTTPTraffic)
            .where(HTTPTraffic.subdomain_id == subdomain_id)
            .order_by(HTTPTraffic.timestamp.desc())
            .limit(limit)
        )
        return list(result.scalars().all())

    def _generate_summary(self, results: Dict[str, Any]) -> Dict[str, Any]:
        """Generate summary of discoveries"""
        summary = {
            "key_findings": [],
            "technologies": [],
            "url_patterns": [],
            "api_endpoints": [],
            "interesting_paths": [],
            "auth_required_paths": [],
        }

        # Extract from crawl results
        if "crawl" in results:
            crawl = results["crawl"]

            if "routing_scheme" in crawl:
                for prefix, routing_type in crawl["routing_scheme"].items():
                    summary["key_findings"].append(
                        f"Detected {routing_type} routing at {prefix}"
                    )

            if "url_patterns" in crawl:
                summary["url_patterns"] = list(crawl["url_patterns"].keys())

            if "api_versions" in crawl:
                summary["key_findings"].append(
                    f"API versions found: {', '.join(crawl['api_versions'])}"
                )

            if "auth_required_paths" in crawl:
                summary["auth_required_paths"] = crawl["auth_required_paths"]

        # Extract from directory enumeration
        if "directory_enum" in results:
            enum = results["directory_enum"]

            if "detected_technologies" in enum:
                summary["technologies"] = enum["detected_technologies"]

            if "discovered_paths" in enum:
                summary["interesting_paths"] = enum["discovered_paths"][:20]  # Top 20

        # Extract from API discovery
        if "api_discovery" in results:
            api = results["api_discovery"]

            if "apis" in api:
                for api_endpoint in api["apis"][:20]:  # Top 20
                    summary["api_endpoints"].append({
                        "url": api_endpoint["url"],
                        "method": api_endpoint["method"],
                        "type": api_endpoint["api_type"],
                        "requires_auth": api_endpoint["requires_auth"]
                    })

        return summary
