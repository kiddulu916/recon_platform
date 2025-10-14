"""
Passive subdomain enumeration
Uses multiple external sources without directly touching the target
"""

from typing import List, Optional
import structlog
from sqlalchemy.ext.asyncio import AsyncSession
import asyncio
import json

from .subfinder import SubfinderWrapper
from .assetfinder import AssetfinderWrapper
from .amass import AmassWrapper
from .ct_logs import CTLogScanner
from .findomain import FindomainWrapper
from .gau import GAUWrapper
from .waybackurls import WaybackurlsWrapper
from .github_subdomains import GithubSubdomainsWrapper
from .gitlab_subdomains import GitlabSubdomainsWrapper
from app.models.domain import Subdomain

logger = structlog.get_logger()


class PassiveEnumerator:
    """
    Orchestrates passive subdomain enumeration
    Runs multiple tools in parallel and aggregates results
    """
    
    def __init__(self, config, rate_limiter, dedup_manager):
        self.config = config
        self.rate_limiter = rate_limiter
        self.dedup_manager = dedup_manager
        self.logger = logger.bind(component="passive_enum")
        
        # Initialize tool wrappers
        self.subfinder = SubfinderWrapper()
        self.assetfinder = AssetfinderWrapper()
        self.amass = AmassWrapper()
        self.ct_scanner = CTLogScanner(config, rate_limiter)
        self.findomain = FindomainWrapper()
        self.gau = GAUWrapper()
        self.waybackurls = WaybackurlsWrapper()
        
        # GitHub/GitLab tools (with tokens if available)
        github_token = config.api_keys.get_key("github")
        gitlab_token = config.api_keys.get_key("gitlab")
        self.github_subdomains = GithubSubdomainsWrapper(github_token)
        self.gitlab_subdomains = GitlabSubdomainsWrapper(gitlab_token)
    
    async def enumerate(
        self,
        session: AsyncSession,
        domain: str,
        domain_id: int,
        recursion_level: int = 0
    ) -> List[str]:
        """
        Run passive enumeration workflow
        
        Args:
            session: Database session
            domain: Target domain
            domain_id: Domain ID in database
            recursion_level: Current recursion depth
        
        Returns:
            List of discovered subdomains
        """
        self.logger.info("Starting passive enumeration", domain=domain)
        
        # Run all passive sources in parallel
        tasks = [
            self._run_subfinder(domain),
            self._run_assetfinder(domain),
            self._run_amass(domain),
            self._run_ct_logs(domain),
            self._run_findomain(domain),
            self._run_gau(domain),
            self._run_waybackurls(domain),
            self._run_github_subdomains(domain),
            self._run_gitlab_subdomains(domain),
        ]
        
        results = await asyncio.gather(*tasks, return_exceptions=True)
        
        # Aggregate all results
        all_subdomains = set()
        source_map = {}  # subdomain -> list of sources
        
        tool_names = [
            "subfinder", "assetfinder", "amass", "ct_logs", "findomain",
            "gau", "waybackurls", "github_subdomains", "gitlab_subdomains"
        ]
        for tool_name, result in zip(tool_names, results):
            if isinstance(result, Exception):
                self.logger.error(f"{tool_name} failed", error=str(result))
                continue
            
            for subdomain in result:
                all_subdomains.add(subdomain)
                if subdomain not in source_map:
                    source_map[subdomain] = []
                source_map[subdomain].append(tool_name)
        
        self.logger.info(
            "Passive enumeration complete",
            total_subdomains=len(all_subdomains)
        )
        
        # Deduplicate and save to database with upsert logic
        new_subdomains = self.dedup_manager.add_subdomains_batch(
            list(all_subdomains),
            "passive_enum"
        )
        
        # Use upsert logic to handle duplicates gracefully
        new_count = 0
        updated_count = 0
        failed_count = 0
        
        for subdomain in new_subdomains:
            was_new = await self._upsert_subdomain(
                session,
                subdomain,
                domain_id,
                "passive",
                source_map.get(subdomain, ["passive"]),
                recursion_level
            )
            
            if was_new is True:
                new_count += 1
            elif was_new is False:
                updated_count += 1
            else:
                failed_count += 1
        
        # Commit all changes
        try:
            await session.commit()
        except Exception as e:
            self.logger.error("Failed to commit passive enumeration results", error=str(e))
            await session.rollback()
        
        self.logger.info(
            "Passive enumeration saved",
            total=len(new_subdomains),
            new=new_count,
            updated=updated_count,
            failed=failed_count
        )
        
        return new_subdomains
    
    async def _upsert_subdomain(
        self,
        session: AsyncSession,
        subdomain: str,
        domain_id: int,
        discovery_method: str,
        discovery_sources: List[str],
        recursion_level: int
    ) -> Optional[bool]:
        """
        Insert or update a subdomain
        
        Args:
            session: Database session
            subdomain: Subdomain to upsert
            domain_id: Parent domain ID
            discovery_method: How it was discovered
            discovery_sources: List of discovery sources
            recursion_level: Recursion depth
        
        Returns:
            True if new, False if updated, None if failed
        """
        from sqlalchemy.exc import IntegrityError
        from datetime import datetime
        
        try:
            # Try to insert as new
            subdomain_record = Subdomain(
                subdomain=subdomain,
                domain_id=domain_id,
                discovery_method=discovery_method,
                discovery_sources=json.dumps(discovery_sources),
                recursion_level=recursion_level,
                discovered_at=datetime.utcnow()
            )
            session.add(subdomain_record)
            await session.flush()  # Flush to catch IntegrityError immediately
            return True
        
        except IntegrityError:
            # Subdomain already exists, update it instead
            await session.rollback()
            
            try:
                # Query existing subdomain
                from sqlalchemy import select
                result = await session.execute(
                    select(Subdomain).where(
                        Subdomain.subdomain == subdomain,
                        Subdomain.domain_id == domain_id
                    )
                )
                existing = result.scalar_one_or_none()
                
                if existing:
                    # Merge discovery sources
                    try:
                        existing_sources = json.loads(existing.discovery_sources) if existing.discovery_sources else []
                    except (json.JSONDecodeError, TypeError):
                        existing_sources = []
                    
                    # Union of sources
                    merged_sources = list(set(existing_sources + discovery_sources))
                    existing.discovery_sources = json.dumps(merged_sources)
                    
                    # Update recursion level if deeper
                    if recursion_level < existing.recursion_level:
                        existing.recursion_level = recursion_level
                    
                    await session.flush()
                    
                    self.logger.debug(
                        "Updated existing subdomain",
                        subdomain=subdomain,
                        sources=merged_sources
                    )
                    return False
                else:
                    self.logger.warning(
                        "IntegrityError but subdomain not found",
                        subdomain=subdomain
                    )
                    return None
            
            except Exception as e:
                self.logger.error(
                    "Failed to update existing subdomain",
                    subdomain=subdomain,
                    error=str(e)
                )
                await session.rollback()
                return None
        
        except Exception as e:
            self.logger.error(
                "Failed to upsert subdomain",
                subdomain=subdomain,
                error=str(e)
            )
            await session.rollback()
            return None
    
    async def _run_subfinder(self, domain: str) -> List[str]:
        """Run subfinder"""
        await self.rate_limiter.acquire(tool="subfinder")
        result = await self.subfinder.run(domain)
        return result.results if result.success else []
    
    async def _run_assetfinder(self, domain: str) -> List[str]:
        """Run assetfinder"""
        await self.rate_limiter.acquire(tool="assetfinder")
        result = await self.assetfinder.run(domain)
        return result.results if result.success else []
    
    async def _run_amass(self, domain: str) -> List[str]:
        """Run amass in passive mode"""
        await self.rate_limiter.acquire(tool="amass")
        result = await self.amass.run(domain)
        return result.results if result.success else []
    
    async def _run_ct_logs(self, domain: str) -> List[str]:
        """Run CT log enumeration"""
        return await self.ct_scanner.scan(domain)
    
    async def _run_findomain(self, domain: str) -> List[str]:
        """Run findomain"""
        await self.rate_limiter.acquire(tool="findomain")
        result = await self.findomain.run(domain)
        return result.results if result.success else []
    
    async def _run_gau(self, domain: str) -> List[str]:
        """Run gau (GetAllUrls)"""
        await self.rate_limiter.acquire(tool="gau")
        result = await self.gau.run(domain)
        return result.results if result.success else []
    
    async def _run_waybackurls(self, domain: str) -> List[str]:
        """Run waybackurls"""
        await self.rate_limiter.acquire(tool="waybackurls")
        result = await self.waybackurls.run(domain)
        return result.results if result.success else []
    
    async def _run_github_subdomains(self, domain: str) -> List[str]:
        """Run github-subdomains"""
        await self.rate_limiter.acquire(tool="github_subdomains")
        result = await self.github_subdomains.run(domain)
        return result.results if result.success else []
    
    async def _run_gitlab_subdomains(self, domain: str) -> List[str]:
        """Run gitlab-subdomains"""
        await self.rate_limiter.acquire(tool="gitlab_subdomains")
        result = await self.gitlab_subdomains.run(domain)
        return result.results if result.success else []

